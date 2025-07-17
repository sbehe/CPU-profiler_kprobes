# perftop — Linux Kernel Module CPU Profiler

## Overview

**perftop** is a Linux kernel module that profiles CPU scheduling activity at the task level. It leverages **Kprobes** to hook into the Linux scheduler and tracks:

- How often each unique task (defined by its stack trace) is scheduled
- The total time each task spends executing on the CPU (in `rdtsc` ticks)
- The top 20 most scheduled tasks ranked by cumulative execution time

Profiling data is exposed through the `/proc` filesystem via a virtual file at `/proc/perftop`.

---

## Features

- **Kprobe-based instrumentation**: Hooks into `pick_next_task_fair()` to monitor task switches.
- **Stack trace-based tracking**: Tasks are uniquely identified by their kernel/user stack traces (instead of just PID).
- **CPU time accounting**: Uses the `rdtsc` instruction to record how long a task runs while in the `TASK_RUNNING` state.
- **Jenkins hash**: Used to hash stack traces for efficient lookup and aggregation.
- **RB-tree integration** : Maintains a ranked list of the top 20 most scheduled tasks.

---

## Output Format — `/proc/perftop`

Each time you run `cat /proc/perftop`, the profiler prints:

1. **Top 20 most scheduled tasks**, sorted by total CPU time
2. **For each task:**
   - Rank
   - Stack trace hash
   - Total time spent on CPU (in `rdtsc` ticks)
   - Stack trace dump (max depth 4)

> Units: Time is measured in raw `rdtsc` ticks, providing high-resolution CPU timing data.

---

## How It Works

- On each context switch, the profiler:
  1. Retrieves the stack trace of the incoming task (user/kernel)
  2. Computes a Jenkins hash from the trace
  3. Updates a hash table entry:
     - Increment scheduling count
     - Update cumulative runtime
  4. Tracks the outgoing task’s execution time via `rdtsc` delta
  5. Updates the RB-tree (if enabled) to maintain sorted ordering

---

## Build & Run

### Build the module:
```bash
make
```

### Load the module
```
sudo insmod perftop.ko
```

### View profiler output
```
cat /proc/perftop
```

### Unload the module
```
sudo rmmod perftop
```
