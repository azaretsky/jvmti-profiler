#ifndef _PROFILER_H_
#define _PROFILER_H_

#include <sys/queue.h>
#include <sys/tree.h>

#ifndef __unused
#define __unused __attribute__((unused))
#endif

/*
just for the jlong definition
*/
#include <jni.h>

struct agent_method {
    const char *class_sig;
    const char *name;
    const char *sig;
    jlong call_count;
    jlong total_time;
    jlong sub_time;
};

enum agent_event_type {
    EVENT_ENTRY,
    EVENT_NORMAL_EXIT,
    EVENT_EXCEPTION_EXIT,
};

struct agent_event {
    jlong tid;
    jlong nanos;
    struct agent_method *method;
    enum agent_event_type event_type;
};

struct thread_stack_entry {
    SLIST_ENTRY(thread_stack_entry) slist;
    struct agent_method *method;
    jlong entry_nanos;
};

struct thread_stack {
    RB_ENTRY(thread_stack) rb;
    jlong tid;
    SLIST_HEAD(thread_stack_head, thread_stack_entry) head;
};

struct profiler {
    RB_HEAD(threads_rb, thread_stack) threads;
};

struct agent_method_iterator;

const struct agent_method *agent_method_iterator_next(struct agent_method_iterator *iterator);

void *profiler_allocate(struct profiler *profiler, jlong size);
void profiler_deallocate(struct profiler *profiler, void *mem);

void profiler_start(struct profiler *profiler);
void profiler_init_method(struct profiler *profiler, struct agent_method *method);
void profiler_process_event(struct profiler *profiler, struct agent_event *event);
void profiler_stop(struct profiler *profiler, struct agent_method_iterator *iterator);

#endif
