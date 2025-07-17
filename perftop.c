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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sabyasachi");
MODULE_DESCRIPTION("CPU Profiler to track task scheduling");

#define MAX_BUCKETS 10
static DEFINE_HASHTABLE(task_table, MAX_BUCKETS);
#define MAX_STACK_DEPTH 4

struct task_count {
    unsigned long stack[MAX_STACK_DEPTH];
    pid_t task_hash;
    unsigned int count;
    struct hlist_node task_node;
};

struct task_count *find_task_count(u32 hash) {
    struct task_count *entry;
    hash_for_each_possible(task_table, entry, task_node, hash) {
        if (entry->task_hash == hash) {
            return entry;
        }
    }
    return NULL;
}

static void insert_task_count(unsigned long hash, unsigned long * stack) {
    struct task_count *entry = find_task_count(hash);
    
    if (!entry) {
        entry = kzalloc(sizeof(*entry), GFP_ATOMIC);  // GFP_ATOMIC for interrupt-safe allocation
        if (!entry) return;

        entry->task_hash = hash;
        memcpy (entry->stack, stack, sizeof (unsigned long) * MAX_STACK_DEPTH);
        entry->count = 0;
        hash_add(task_table, &entry->task_node, hash);
    }
    entry->count++;
}

static int perftop_proc_show(struct seq_file *m, void *v) {
    struct task_count *entry;
    int i;

    seq_puts(m, "Stack trace, Stack trace hash, Scheduled Count\n");

    hash_for_each(task_table, i, entry, task_node) {
        for (int i = 0; i < MAX_STACK_DEPTH; ++i) {
            seq_printf (m, "\n%ld", entry->stack[i]);
        }
        seq_printf(m, "    %d    %u\n", entry->task_hash, entry->count);
    }
    return 0;
}

typedef unsigned long (*typ1) (unsigned long *, unsigned int);
typedef unsigned long (*typ2) (unsigned long *, unsigned int, unsigned int);
static typ1 stack_trace_save_user_;
static typ2 stack_trace_save_;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    unsigned long stack[MAX_STACK_DEPTH];
    int depth = 0;
    unsigned long hash;

    struct task_struct *task = current;

    if (task->mm) {
        depth = stack_trace_save_user_(stack, MAX_STACK_DEPTH);
    } else {
        depth = stack_trace_save_(stack, MAX_STACK_DEPTH, 0);
    }

    if (depth > 0) {
        hash = full_name_hash(NULL, (unsigned char *)stack, depth * sizeof(unsigned long));
        insert_task_count(hash, stack);  // Store PID instead of hash
    }

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
    struct task_count *entry;
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