// eBPF Performance Profiler - CPU Sampling Program
// This runs in the Linux kernel and samples what processes are doing

#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

// Maximum depth for stack traces
#define MAX_STACK_DEPTH 20

// Data structure sent to userspace for each CPU sample
struct sample_data
{
    u32 pid;             // Process ID
    u32 tgid;            // Thread Group ID (main process)
    u64 timestamp;       // When this sample was taken (nanoseconds)
    char comm[16];       // Process name (e.g., "python3")
    u32 cpu_id;          // Which CPU this was running on
    u64 kernel_stack_id; // ID for kernel stack trace
    u64 user_stack_id;   // ID for user stack trace
};

// Data structure for per-process CPU statistics
struct cpu_key
{
    u32 pid;
    char comm[16];
};

struct cpu_value
{
    u64 sample_count; // How many times we sampled this process
    u64 last_seen;    // Last time we saw this process
};

// ============================================================================
// BPF MAPS - These are how eBPF and userspace share data
// ============================================================================

// Perf buffer: Fast way to send events to userspace
BPF_PERF_OUTPUT(events);

// Hash map: Store per-process CPU usage statistics
BPF_HASH(cpu_stats, struct cpu_key, struct cpu_value, 10240);

// Stack traces: Store stack traces for profiling
BPF_STACK_TRACE(stack_traces, 10240);

// ============================================================================
// MAIN SAMPLING FUNCTION - Called on every CPU sample
// ============================================================================

int on_cpu_sample(struct bpf_perf_event_data *ctx)
{
    // Get current process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;         // Process ID
    u32 tgid = pid_tgid & 0xFFFFFFFF; // Thread Group ID

    // Skip kernel threads (PID 0) and idle processes
    if (pid == 0)
    {
        return 0;
    }

    // Prepare sample data to send to userspace
    struct sample_data data = {};
    data.pid = pid;
    data.tgid = tgid;
    data.timestamp = bpf_ktime_get_ns();
    data.cpu_id = bpf_get_smp_processor_id();

    // Get process name (e.g., "python3", "nginx")
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Collect stack traces for profiling
    // User stack: Shows what functions in the application are running
    data.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

    // Kernel stack: Shows what kernel functions are running
    data.kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);

    // Send this sample to userspace
    events.perf_submit(ctx, &data, sizeof(data));

    // Update per-process statistics in our hash map
    struct cpu_key key = {};
    key.pid = pid;
    __builtin_memcpy(&key.comm, data.comm, sizeof(key.comm));

    struct cpu_value *value = cpu_stats.lookup(&key);
    if (value)
    {
        // Process already exists in map, increment count
        __sync_fetch_and_add(&value->sample_count, 1);
        value->last_seen = data.timestamp;
    }
    else
    {
        // New process, create entry
        struct cpu_value new_value = {};
        new_value.sample_count = 1;
        new_value.last_seen = data.timestamp;
        cpu_stats.update(&key, &new_value);
    }

    return 0;
}

// ============================================================================
// SYSCALL TRACING - Track system calls (optional, for more insights)
// ============================================================================

// Data structure for syscall events
struct syscall_data
{
    u32 pid;
    u64 timestamp;
    char comm[16];
    int syscall_id;  // Which syscall (e.g., read, write, open)
    u64 duration_ns; // How long it took (nanoseconds)
};

// Map to track syscall entry times
BPF_HASH(syscall_enter_time, u64, u64, 10240);

// Perf buffer for syscall events
BPF_PERF_OUTPUT(syscall_events);

// Called when a syscall starts
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0)
    {
        return 0;
    }

    // Record when this syscall started
    u64 timestamp = bpf_ktime_get_ns();
    syscall_enter_time.update(&pid_tgid, &timestamp);

    return 0;
}

// Called when a syscall finishes
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0)
    {
        return 0;
    }

    // Look up when this syscall started
    u64 *start_time = syscall_enter_time.lookup(&pid_tgid);
    if (!start_time)
    {
        return 0;
    }

    // Calculate duration
    u64 end_time = bpf_ktime_get_ns();
    u64 duration = end_time - *start_time;

    // Prepare syscall event data
    struct syscall_data data = {};
    data.pid = pid;
    data.timestamp = end_time;
    data.syscall_id = args->id;
    data.duration_ns = duration;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Send to userspace
    syscall_events.perf_submit(args, &data, sizeof(data));

    // Clean up entry time
    syscall_enter_time.delete(&pid_tgid);

    return 0;
}

// ============================================================================
// I/O OPERATIONS TRACKING - Monitor read/write operations
// ============================================================================

struct io_data
{
    u32 pid;
    u64 timestamp;
    char comm[16];
    u64 bytes;       // Bytes read or written
    u64 duration_ns; // How long the I/O took
    u8 operation;    // 0 = read, 1 = write
};

BPF_PERF_OUTPUT(io_events);
BPF_HASH(io_start, u64, u64, 10240);

// Track read() system call
int trace_read_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    io_start.update(&pid_tgid, &timestamp);
    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 *start_time = io_start.lookup(&pid_tgid);
    if (!start_time)
    {
        return 0;
    }

    u64 end_time = bpf_ktime_get_ns();
    s64 bytes = PT_REGS_RC(ctx); // Return value = bytes read

    // Only track successful reads
    if (bytes > 0)
    {
        struct io_data data = {};
        data.pid = pid;
        data.timestamp = end_time;
        data.bytes = bytes;
        data.duration_ns = end_time - *start_time;
        data.operation = 0; // read
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        io_events.perf_submit(ctx, &data, sizeof(data));
    }

    io_start.delete(&pid_tgid);
    return 0;
}

// Track write() system call
int trace_write_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    io_start.update(&pid_tgid, &timestamp);
    return 0;
}

int trace_write_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 *start_time = io_start.lookup(&pid_tgid);
    if (!start_time)
    {
        return 0;
    }

    u64 end_time = bpf_ktime_get_ns();
    s64 bytes = PT_REGS_RC(ctx); // Return value = bytes written

    // Only track successful writes
    if (bytes > 0)
    {
        struct io_data data = {};
        data.pid = pid;
        data.timestamp = end_time;
        data.bytes = bytes;
        data.duration_ns = end_time - *start_time;
        data.operation = 1; // write
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        io_events.perf_submit(ctx, &data, sizeof(data));
    }

    io_start.delete(&pid_tgid);
    return 0;
}