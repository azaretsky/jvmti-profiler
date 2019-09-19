#include "profiler.h"

static
int thread_stack_cmp(struct thread_stack *l, struct thread_stack *r)
{
    return l->tid < r->tid ? -1 : (l->tid == r->tid ? 0 : 1);
}

RB_GENERATE_STATIC(threads_rb, thread_stack, rb, thread_stack_cmp)

void profiler_start(struct profiler *profiler)
{
    RB_INIT(&profiler->threads);
}

void profiler_init_method(struct profiler *profiler, struct agent_method *method)
{
}

static
struct thread_stack *find_thread(struct profiler *profiler, jlong tid)
{
    struct thread_stack find, *stack;
    find.tid = tid;
    stack = RB_FIND(threads_rb, &profiler->threads, &find);
    if (stack == NULL) {
        stack = profiler_allocate(profiler, sizeof(*stack));
        if (stack != NULL) {
            stack->tid = tid;
            SLIST_INIT(&stack->head);
            RB_INSERT(threads_rb, &profiler->threads, stack);
        }
    }
    return stack;
}

static
void push_method(struct profiler *profiler, struct thread_stack *stack, struct agent_event *event)
{
    struct thread_stack_entry *entry;
    entry = profiler_allocate(profiler, sizeof(*entry));
    if (entry == NULL)
        return;
    ++event->method->call_count;
    entry->method = event->method;
    entry->entry_nanos = event->nanos;
    SLIST_INSERT_HEAD(&stack->head, entry, slist);
}

static
void pop_method(struct profiler *profiler, struct thread_stack *stack, struct agent_event *event)
{
    struct thread_stack_entry *current = SLIST_FIRST(&stack->head);
    jlong total;
    if (current == NULL) {
        fprintf(stderr, "thread %ld %ld skipping exit %s %s %s\n", event->tid, event->nanos, event->method->class_sig, event->method->name, event->method->sig);
        return;
    }
    if (current->method != event->method) {
        fprintf(stderr, "last entry: %s %s %s\ncurrent exit: %s %s %s\neverything is broken\n",
            current->method->class_sig, current->method->name, current->method->sig,
            event->method->class_sig, event->method->name, event->method->sig);
        return;
    }
    total = event->nanos - current->entry_nanos;
    current->method->total_time += total;
    SLIST_REMOVE_HEAD(&stack->head, slist);
    profiler_deallocate(profiler, current);
    if (!SLIST_EMPTY(&stack->head))
        SLIST_FIRST(&stack->head)->method->sub_time += total;
}

void profiler_process_event(struct profiler *profiler, struct agent_event *event)
{
    struct thread_stack *stack;

    stack = find_thread(profiler, event->tid);
    if (stack == NULL)
        return;

    if (event->event_type == EVENT_ENTRY)
        push_method(profiler, stack, event);
    else
        pop_method(profiler, stack, event);
}

static
void dump_non_empty_stacks(struct profiler *profiler)
{
    struct thread_stack *stack;
    stack = RB_MIN(threads_rb, &profiler->threads);
    while (stack != NULL) {
        struct thread_stack *next_stack = RB_NEXT(threads_rb, &profiler->threads, stack);
        RB_REMOVE(threads_rb, &profiler->threads, stack);
        if (!SLIST_EMPTY(&stack->head)) {
            struct thread_stack_entry *entry;
            fprintf(stderr, "thread %ld:\n", stack->tid);
            entry = SLIST_FIRST(&stack->head);
            while (entry != NULL) {
                struct thread_stack_entry *next_entry = SLIST_NEXT(entry, slist);
                fprintf(stderr, "%ld %s %s %s\n", entry->entry_nanos, entry->method->class_sig, entry->method->name, entry->method->sig);
                profiler_deallocate(profiler, entry);
                entry = next_entry;
            }
        }
        profiler_deallocate(profiler, stack);
        stack = next_stack;
    }
}

void profiler_stop(struct profiler *profiler, struct agent_method_iterator *iterator)
{
    const struct agent_method *method;

    dump_non_empty_stacks(profiler);

    printf("calls own total class method signature\n");
    while ((method = agent_method_iterator_next(iterator)) != NULL)
        printf("%ld %ld %ld %s %s %s\n",
            method->call_count, method->total_time - method->sub_time, method->total_time,
            method->class_sig, method->name, method->sig);
}
