#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <jvmti.h>

#include "profiler.h"

struct agent_local {
    jfieldID tid_field;
    RB_HEAD(agent_methods, agent_method_box) methods;
    jrawMonitorID monitor;
    STAILQ_HEAD(agent_event_queue, agent_internal_event) events;
    enum agent_thread_state {
        AGENT_THREAD_NONE,
        AGENT_THREAD_STARTING,
        AGENT_THREAD_STARTED,
        AGENT_THREAD_STOPPING,
        AGENT_THREAD_STOPPED,
    } stats_thread_state : 3;
    int use_system_timer : 1;
    int spin_agent_thread : 1;
};

struct agent_method_box {
    RB_ENTRY(agent_method_box) rb;
    jmethodID id;
    struct agent_method method;
};

static
int agent_method_box_cmp(struct agent_method_box *l, struct agent_method_box *r)
{
    return l->id < r->id ? -1 : (l->id == r->id ? 0 : 1);
}

RB_GENERATE_STATIC(agent_methods, agent_method_box, rb, agent_method_box_cmp)

struct agent_internal_event {
    STAILQ_ENTRY(agent_internal_event) queue;
    jlong tid;
    jlong nanos;
    jmethodID method;
    enum agent_event_type event_type;
};

static
void *jvmti_alloc(jvmtiEnv *env, jlong size)
{
    unsigned char *mem;
    jvmtiError status;

    status = (*env)->Allocate(env, size, &mem);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "Allocate: %d\n", status);
        return NULL;
    }
    return mem;
}

static
void jvmti_free(jvmtiEnv *env, void *mem)
{
    jvmtiError status;

    status = (*env)->Deallocate(env, mem);
    if (status != JVMTI_ERROR_NONE)
        fprintf(stderr, "Deallocate: %d\n", status);
}

struct profiler_box {
    jvmtiEnv *env;
    struct profiler profiler;
};

void *profiler_allocate(struct profiler *profiler, jlong size) {
    jvmtiEnv *env = ((struct profiler_box *)((char *)profiler - offsetof(struct profiler_box, profiler)))->env;
    return jvmti_alloc(env, size);
}

void profiler_deallocate(struct profiler *profiler, void *mem)
{
    jvmtiEnv *env = ((struct profiler_box *)((char *)profiler - offsetof(struct profiler_box, profiler)))->env;
    jvmti_free(env, mem);
}

static
struct agent_method *lookup_method(struct agent_local *local, jvmtiEnv *env, JNIEnv *jni, jmethodID method, struct profiler *profiler)
{
    struct agent_method_box find, *box;
    struct agent_method *res = NULL;
    char *name, *sig, *class_sig;
    char *box_name, *box_sig, *box_class_sig;
    jclass method_class;
    size_t class_sig_byte_size, name_byte_size, sig_byte_size;
    jvmtiError status;

    find.id = method;
    box = RB_FIND(agent_methods, &local->methods, &find);
    if (box != NULL)
        return &box->method;

    status = (*env)->GetMethodName(env, method, &name, &sig, NULL);
    if (status != JVMTI_ERROR_NONE) {
        name = NULL;
        sig = NULL;
        fprintf(stderr, "GetMethodName (%p): %d\n", method, status);
        goto exit;
    }

    status = (*env)->GetMethodDeclaringClass(env, method, &method_class);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetMethodDeclaringClass (%p %s): %d\n", method, name, status);
        goto exit;
    }
    status = (*env)->GetClassSignature(env, method_class, &class_sig, NULL);
    (*jni)->DeleteLocalRef(jni, method_class);
    if (status != JVMTI_ERROR_NONE) {
        class_sig = NULL;
        fprintf(stderr, "GetClassSignature (method %p %s): %d\n", method, name, status);
        goto exit;
    }

    class_sig_byte_size = strlen(class_sig) + 1;
    name_byte_size = strlen(name) + 1;
    sig_byte_size = strlen(sig) + 1;
    box = jvmti_alloc(env, sizeof(struct agent_method_box) + class_sig_byte_size + name_byte_size + sig_byte_size);
    if (box == NULL)
        goto exit;
    box->id = method;
    box_class_sig = ((char *)box) + sizeof(struct agent_method_box);
    box_name = box_class_sig + class_sig_byte_size;
    box_sig = box_name + name_byte_size;
    memcpy(box_class_sig, class_sig, class_sig_byte_size);
    memcpy(box_name, name, name_byte_size);
    memcpy(box_sig, sig, sig_byte_size);
    res = &box->method;
    memset(res, 0, sizeof(*res));
    res->class_sig = box_class_sig;
    res->name = box_name;
    res->sig = box_sig;
    profiler_init_method(profiler, res);
    RB_INSERT(agent_methods, &local->methods, box);

exit:
    if (class_sig != NULL)
        jvmti_free(env, class_sig);
    if (sig != NULL)
        jvmti_free(env, sig);
    if (name != NULL)
        jvmti_free(env, name);
    return res;
}

static
void stop_for_a_moment(const struct agent_local *local)
{
    if (!local->spin_agent_thread) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
        nanosleep(&ts, NULL);
    }
}

struct agent_method_iterator {
    jvmtiEnv *env;
    struct agent_methods *methods;
    struct agent_method_box *current, *next;
};

static
void init_method_iterator(jvmtiEnv *env, struct agent_methods *methods, struct agent_method_iterator *iter)
{
    iter->env = env;
    iter->methods = methods;
    iter->current = NULL;
    iter->next = RB_MIN(agent_methods, methods);
}

const struct agent_method *agent_method_iterator_next(struct agent_method_iterator *iter)
{
    if (iter->current != NULL)
        jvmti_free(iter->env, iter->current);
    iter->current = iter->next;
    if (iter->current == NULL)
        return NULL;
    iter->next = RB_NEXT(agent_methods, iter->methods, iter->current);
    RB_REMOVE(agent_methods, iter->methods, iter->current);
    return &iter->current->method;
}

static
void JNICALL agent_thread_func(jvmtiEnv *env, JNIEnv *jni, void *arg)
{
    struct agent_local *local = arg;
    jvmtiError status;
    struct agent_internal_event *event;
    struct agent_method_iterator iter;
    struct profiler_box profiler_box;
    struct profiler *profiler;
    STAILQ_HEAD(agent_event_queue, agent_internal_event) events = STAILQ_HEAD_INITIALIZER(events);

    profiler_box.env = env;
    memset(&profiler_box.profiler, 0, sizeof(profiler_box.profiler));
    profiler = &profiler_box.profiler;
    profiler_start(profiler);

    (*env)->RawMonitorEnter(env, local->monitor);
    if (local->stats_thread_state != AGENT_THREAD_STARTING) {
        fprintf(stderr, "stats thread was interrupted right at the beginning\n");
        goto stop;
    }
    local->stats_thread_state = AGENT_THREAD_STARTED;
    (*env)->RawMonitorNotify(env, local->monitor);
    for (;;) {
        if (STAILQ_EMPTY(&local->events)) {
            if (local->stats_thread_state == AGENT_THREAD_STOPPING)
                break;
            status = (*env)->RawMonitorWait(env, local->monitor, 0);
            if (status != JVMTI_ERROR_NONE) {
                fprintf(stderr, "RawMonitorWait: %d\n", status);
                break;
            }
            continue;
        }
        STAILQ_CONCAT(&events, &local->events);
        (*env)->RawMonitorExit(env, local->monitor);
        event = STAILQ_FIRST(&events);
        while (event != NULL) {
            struct agent_event profiler_event;
            struct agent_internal_event *next = STAILQ_NEXT(event, queue);
            profiler_event.method = lookup_method(local, env, jni, event->method, profiler);
            profiler_event.tid = event->tid;
            profiler_event.nanos = event->nanos;
            profiler_event.event_type = event->event_type;
            jvmti_free(env, event);
            if (profiler_event.method != NULL)
                profiler_process_event(profiler, &profiler_event);
            event = next;
        }
        STAILQ_INIT(&events);
        stop_for_a_moment(local);
        (*env)->RawMonitorEnter(env, local->monitor);
    }
stop:
    init_method_iterator(env, &local->methods, &iter);
    profiler_stop(profiler, &iter);
    local->stats_thread_state = AGENT_THREAD_STOPPED;
    (*env)->RawMonitorNotify(env, local->monitor);
    (*env)->RawMonitorExit(env, local->monitor);
}

static
void print_timer_info(const char *name, jvmtiTimerInfo *ti)
{
    fprintf(stderr, "%s:\n"
        "    max_value: 0x%lx\n"
        "    may_skip_forward: %s\n"
        "    may_skip_backward: %s\n",
        name,
        ti->max_value,
        ti->may_skip_forward ? "yes" : "no",
        ti->may_skip_backward ? "yes" : "no"
    );
    fputs("    kind: ", stderr);
    switch (ti->kind) {
    case JVMTI_TIMER_USER_CPU:
        fprintf(stderr, "user");
        break;
    case JVMTI_TIMER_TOTAL_CPU:
        fprintf(stderr, "total");
        break;
    case JVMTI_TIMER_ELAPSED:
        fprintf(stderr, "elapsed");
        break;
    default:
        fprintf(stderr, "%d", ti->kind);
    }
    fputs("\n", stderr);
}

static
void JNICALL on_vm_init(jvmtiEnv *env, JNIEnv *jni, jthread thread)
{
    struct agent_local *local;
    jvmtiError status;
    jvmtiTimerInfo ti;
    jclass thread_class;
    jmethodID thread_cons;
    jstring thread_name;
    jthread agent_thread;

    status = (*env)->GetEnvironmentLocalStorage(env, (void **)&local);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetEnvironmentLocalStorage: %d\n", status);
        return;
    }

    status = (*env)->GetTimerInfo(env, &ti);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetTimerInfo: %d\n", status);
        return;
    }
    print_timer_info("system timer", &ti);

    if (!local->use_system_timer) {
        status = (*env)->GetCurrentThreadCpuTimerInfo(env, &ti);
        if (status != JVMTI_ERROR_NONE) {
            fprintf(stderr, "GetCurrentThreadCpuTimerInfo: %d\n", status);
            return;
        }
        print_timer_info("current thread timer", &ti);
    }

    thread_class = (*jni)->FindClass(jni, "java/lang/Thread");
    if (thread_class == NULL) {
        fprintf(stderr, "FindClass(Thread) failed\n");
        return;
    }
    local->tid_field = (*jni)->GetFieldID(jni, thread_class, "tid", "J");
    if (local->tid_field == NULL) {
        fprintf(stderr, "GetFieldID(Thread.tid) failed\n");
        return;
    }

    thread_cons = (*jni)->GetMethodID(jni, thread_class, "<init>", "(Ljava/lang/String;)V");
    if (thread_cons == NULL) {
        fprintf(stderr, "GetMethodID(Thread.<init>(String)) failed\n");
        return;
    }
    thread_name = (*jni)->NewStringUTF(jni, "profiler stats collector");
    if (thread_name == NULL) {
        fprintf(stderr, "NewStringUTF failed\n");
        return;
    }
    agent_thread = (*jni)->NewObject(jni, thread_class, thread_cons, thread_name);
    if (agent_thread == NULL) {
        fprintf(stderr, "NewObject failed\n");
        return;
    }
    local->stats_thread_state = AGENT_THREAD_STARTING;
    status = (*env)->RunAgentThread(env, agent_thread, agent_thread_func, local, JVMTI_THREAD_MIN_PRIORITY);
    if (status != JVMTI_ERROR_NONE) {
        local->stats_thread_state = AGENT_THREAD_NONE;
        fprintf(stderr, "RunAgentThread: %d\n", status);
        return;
    }
    (*env)->RawMonitorEnter(env, local->monitor);
    while (local->stats_thread_state == AGENT_THREAD_STARTING)
        (*env)->RawMonitorWait(env, local->monitor, 0);
    (*env)->RawMonitorExit(env, local->monitor);

    status = (*env)->SetEventNotificationMode(env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY): %d\n", status);
        return;
    }
    status = (*env)->SetEventNotificationMode(env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT): %d\n", status);
        return;
    }
}

static
void JNICALL on_vm_death(jvmtiEnv *env, JNIEnv *jni)
{
    struct agent_local *local;
    jlong start_time = 0, stop_time = 0;
    jvmtiError status;

    status = (*env)->GetEnvironmentLocalStorage(env, (void **)&local);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetEnvironmentLocalStorage: %d\n", status);
        return;
    }

    (*env)->GetTime(env, &start_time);
    (*env)->RawMonitorEnter(env, local->monitor);
    if (local->stats_thread_state != AGENT_THREAD_NONE) {
        while (local->stats_thread_state != AGENT_THREAD_STOPPED) {
            local->stats_thread_state = AGENT_THREAD_STOPPING;
            (*env)->RawMonitorNotify(env, local->monitor);
            (*env)->RawMonitorWait(env, local->monitor, 0);
        }
    }
    (*env)->RawMonitorExit(env, local->monitor);
    (*env)->GetTime(env, &stop_time);

    fprintf(stderr, "stats thread is stopped (it took %lu ns)\n", stop_time - start_time);
}

static
void post_event(jvmtiEnv *env, JNIEnv *jni, enum agent_event_type event_type, jthread thread, jmethodID method)
{
    struct agent_local *local;
    jlong nanos;
    struct agent_internal_event *event;
    jvmtiError status;

    status = (*env)->GetEnvironmentLocalStorage(env, (void **)&local);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetEnvironmentLocalStorage: %d\n", status);
        return;
    }

    if (local->use_system_timer)
        status = (*env)->GetTime(env, &nanos);
    else
        status = (*env)->GetCurrentThreadCpuTime(env, &nanos);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "timer error: %d\n", status);
        return;
    }

    event = jvmti_alloc(env, sizeof(*event));
    if (event == NULL)
        return;
    event->tid = (*jni)->GetLongField(jni, thread, local->tid_field);
    event->nanos = nanos;
    event->method = method;
    event->event_type = event_type;
    (*env)->RawMonitorEnter(env, local->monitor);
    STAILQ_INSERT_TAIL(&local->events, event, queue);
    (*env)->RawMonitorNotify(env, local->monitor);
    (*env)->RawMonitorExit(env, local->monitor);
}

static
void JNICALL on_method_entry(jvmtiEnv *env, JNIEnv *jni, jthread thread, jmethodID method)
{
    post_event(env, jni, EVENT_ENTRY, thread, method);
}

static
void JNICALL on_method_exit(jvmtiEnv *env, JNIEnv *jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value)
{
    post_event(env, jni, was_popped_by_exception ? EVENT_EXCEPTION_EXIT : EVENT_NORMAL_EXIT, thread, method);
}

struct agent_option_iterator {
    const char *options;
    size_t options_length;
    const char *name;
    size_t name_length;
    const char *value;
    size_t value_length;
};

static
void init_option_iterator(const char *options, struct agent_option_iterator *iterator)
{
    iterator->options = options;
    iterator->options_length = options != NULL ? strlen(options) : 0;
    iterator->name = iterator->value = NULL;
    iterator->name_length = iterator->value_length = 0;
}

static
int next_option(struct agent_option_iterator *iterator)
{
    const char *current, *option_delim, *value_delim;
    size_t current_length;

    if (iterator->options_length == 0)
        return 0;

    current = iterator->options;
    option_delim = memchr(current, ',', iterator->options_length);
    if (option_delim == NULL) {
        current_length = iterator->options_length;
        iterator->options = NULL;
        iterator->options_length = 0;
    } else {
        current_length = option_delim - current;
        iterator->options = option_delim + 1;
        iterator->options_length -= current_length + 1;
    }

    iterator->name = current;
    value_delim = memchr(current, '=', current_length);
    if (value_delim == NULL) {
        iterator->name_length = current_length;
        iterator->value = NULL;
        iterator->value_length = 0;
    } else {
        iterator->name_length = value_delim - current;
        iterator->value = value_delim + 1;
        iterator->value_length = current_length - (iterator->value - current);
    }
    return 1;
}

static
int option_has_name(const struct agent_option_iterator *iterator, const char *name)
{
    size_t name_length = strlen(name);
    if (iterator->name_length != name_length)
        return 0;
    return memcmp(iterator->name, name, name_length) == 0;
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    jvmtiEnv *env;
    jint status;
    jvmtiCapabilities caps;
    jvmtiEventCallbacks cbs;
    struct agent_local *local;
    struct agent_option_iterator option_iterator;
    int use_system_timer, spin_agent_thread;

    status = (*vm)->GetEnv(vm, (void **)&env, JVMTI_VERSION);
    if (status != JNI_OK) {
        fprintf(stderr, "failed to get JVMTI env: %d\n", status);
        return -1;
    }

    use_system_timer = 0;
    spin_agent_thread = 0;
    init_option_iterator(options, &option_iterator);
    while (next_option(&option_iterator)) {
        if (option_has_name(&option_iterator, "system-timer"))
            use_system_timer = 1;
        else if (option_has_name(&option_iterator, "spin"))
            spin_agent_thread = 1;
        else {
            fprintf(stderr, "unknown option \"%.*s\" = \"%.*s\"\n",
                (int)option_iterator.name_length, option_iterator.name,
                (int)option_iterator.value_length, option_iterator.value);
        }
    }

    status = (*env)->GetPotentialCapabilities(env, &caps);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "GetPotentialCapabilities: %d\n", status);
        return -1;
    }
    if (!(caps.can_generate_method_entry_events && caps.can_generate_method_exit_events)) {
        fprintf(stderr, "these capabilities are required:\n"
            "can_generate_method_entry_events=%d\n"
            "can_generate_method_exit_events=%d\n",
            caps.can_generate_method_entry_events,
            caps.can_generate_method_exit_events);
        return -1;
    }
    if (!(use_system_timer || caps.can_get_current_thread_cpu_time)) {
        fprintf(stderr, "this additional capability is required:\n"
            "can_get_current_thread_cpu_time=%d\n",
            caps.can_get_current_thread_cpu_time);
        return -1;
    }
    memset(&caps, 0, sizeof(caps));
    if (!use_system_timer)
        caps.can_get_current_thread_cpu_time = 1;
    caps.can_generate_method_entry_events = 1;
    caps.can_generate_method_exit_events = 1;
    status = (*env)->AddCapabilities(env, &caps);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "AddCapabilities: %d\n", status);
        return -1;
    }

    local = jvmti_alloc(env, sizeof(*local));
    if (local == NULL)
        return -1;
    memset(local, 0, sizeof(*local));
    status = (*env)->CreateRawMonitor(env, "profiler monitor", &local->monitor);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "CreateRawMonitor: %d\n", status);
        return -1;
    }
    RB_INIT(&local->methods);
    STAILQ_INIT(&local->events);
    local->stats_thread_state = AGENT_THREAD_NONE;
    local->use_system_timer = use_system_timer;
    local->spin_agent_thread = spin_agent_thread;
    status = (*env)->SetEnvironmentLocalStorage(env, local);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEnvironmentLocalStorage: %d\n", status);
        return -1;
    }

    memset(&cbs, 0, sizeof(cbs));
    cbs.VMInit = on_vm_init;
    cbs.VMDeath = on_vm_death;
    cbs.MethodEntry = on_method_entry;
    cbs.MethodExit = on_method_exit;
    status = (*env)->SetEventCallbacks(env, &cbs, sizeof(cbs));
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEventCallbacks: %d\n", status);
        return -1;
    }
    status = (*env)->SetEventNotificationMode(env, JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT): %d\n", status);
        return -1;
    }
    status = (*env)->SetEventNotificationMode(env, JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, NULL);
    if (status != JVMTI_ERROR_NONE) {
        fprintf(stderr, "SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH): %d\n", status);
        return -1;
    }
    return 0;
}
