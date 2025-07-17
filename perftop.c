#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/hash.h>
#include <linux/timekeeping.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sabyasachi");
MODULE_DESCRIPTION("CPU Profiler to track task scheduling time");

#define MAX_BUCKETS 10
static DEFINE_HASHTABLE(task_table, MAX_BUCKETS);
#define MAX_STACK_DEPTH 4

struct task_entry {
    unsigned long stack[MAX_STACK_DEPTH];
    u64 total_time;
    unsigned int last_scheduled_in;
    unsigned long task_hash;
    struct hlist_node task_node;
};

static struct task_entry *find_task_entry(unsigned long hash) {
    struct task_entry *entry;
    hash_for_each_possible(task_table, entry, task_node, hash) {
        if (entry->task_hash == hash) {
            return entry;
        }
    }
    return NULL;
}

static void update_task_time(unsigned long hash, u64 current_time) {
    struct task_entry *entry = find_task_entry(hash);
    if (entry && entry->last_scheduled_in) {
        entry->total_time += current_time - entry->last_scheduled_in;
    }
}

static void insert_task_entry(unsigned long hash, unsigned long *stack, u64 current_time) {
    struct task_entry *entry = find_task_entry(hash);
    
    if (!entry) {
        entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
        if (!entry) return;

        memcpy(entry->stack, stack, sizeof(unsigned long) * MAX_STACK_DEPTH);
        entry->total_time = 0;
        entry->task_hash = hash;
        hash_add(task_table, &entry->task_node, hash);
    }

    entry->last_scheduled_in = current_time;
}

static int perftop_proc_show(struct seq_file *m, void *v) {
    struct task_entry *entry;
    int i;

    seq_puts(m, "Stack trace, Hash, Time Spent (rdtsc ticks)\n");

    hash_for_each(task_table, i, entry, task_node) {
        for (int j = 0; j < MAX_STACK_DEPTH; ++j) {
            seq_printf(m, "\n0x%lx", entry->stack[j]);
        }
        seq_printf(m, ", %llu\n", entry->total_time);
    }
    return 0;
}

typedef unsigned long (*typ1)(unsigned long *, unsigned int);
typedef unsigned long (*typ2)(unsigned long *, unsigned int, unsigned int);
static typ1 stack_trace_save_user_;
static typ2 stack_trace_save_;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    static unsigned long prev_task_hash = 0;
    unsigned long stack[MAX_STACK_DEPTH];
    int depth = 0;
    u64 current_time = rdtsc();
    unsigned long hash;

    struct task_struct *task = current;
    if (prev_task_hash) {
        update_task_time(prev_task_hash, current_time);
    }

    if (task->mm) {
        depth = stack_trace_save_user_(stack, MAX_STACK_DEPTH);
    } else {
        depth = stack_trace_save_(stack, MAX_STACK_DEPTH, 0);
    }

    if (depth > 0) {
        depth = min (depth, MAX_STACK_DEPTH);
        hash = full_name_hash(NULL, (unsigned char *)stack, depth * sizeof(unsigned long));
        if (hash > 0)
            insert_task_entry(hash, stack, current_time);
    }

    prev_task_hash = hash;
    return 0;
}

static struct kprobe kp, kp1, kp2;

static int perftop_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, perftop_proc_show, NULL);
}

static const struct proc_ops perftop_fops = {
    .proc_open = perftop_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init perftop_init(void) {
    proc_create("perftop", 0, NULL, &perftop_fops);

    kp1.symbol_name = "stack_trace_save_user";
    if (register_kprobe(&kp1) < 0) {
        pr_err("Failed to register kprobe for stack_trace_save_user\n");
        return -EINVAL;
    }
    stack_trace_save_user_ = (typ1)kp1.addr;

    kp2.symbol_name = "stack_trace_save";
    if (register_kprobe(&kp2) < 0) {
        pr_err("Failed to register kprobe for stack_trace_save\n");
        unregister_kprobe(&kp1);
        return -EINVAL;
    }
    stack_trace_save_ = (typ2)kp2.addr;

    kp.symbol_name = "pick_next_task_fair";
    kp.pre_handler = handler_pre;

    if (register_kprobe(&kp) < 0) {
        pr_err("Failed to register kprobe for pick_next_task_fair\n");
        unregister_kprobe(&kp1);
        unregister_kprobe(&kp2);
        return -EINVAL;
    }

    pr_info("perftop module loaded\n");
    return 0;
}

static void __exit perftop_exit(void) {
    struct task_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(task_table, bkt, tmp, entry, task_node) {
        hash_del(&entry->task_node);
        kfree(entry);
    }

    remove_proc_entry("perftop", NULL);
    unregister_kprobe(&kp);
    unregister_kprobe(&kp1);
    unregister_kprobe(&kp2);

    pr_info("perftop module unloaded\n");
}

module_init(perftop_init);
module_exit(perftop_exit);