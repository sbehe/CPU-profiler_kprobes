#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sabyasachi");
MODULE_DESCRIPTION("CPU Profiler to track task scheduling");

#define MAX_BUCKETS 10
static DEFINE_HASHTABLE(pid_table, MAX_BUCKETS);

struct pid_count {
    pid_t pid;
    unsigned int count;
    struct hlist_node pid_node;
};

struct pid_count *find_pid_count(pid_t pid) {

    struct pid_count *entry;
    hash_for_each_possible(pid_table, entry, pid_node, pid) {
        if (entry->pid == pid) {
            return entry;
        }
    }
    return NULL;
}

static void insert_pid_count(pid_t pid) {
    struct pid_count *entry = find_pid_count(pid);
    
    if (!entry) {
        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) return;

        entry->pid = pid;
        hash_add(pid_table, &entry->pid_node, (unsigned long)pid);
    }
    entry->count++;
}

static int perftop_proc_show(struct seq_file *m, void *v) {
    //seq_puts(m, "Hello world\n");
    struct pid_count *entry;
    
    seq_puts(m, "PID, Scheduled Count\n");
    int i;

    hash_for_each(pid_table, i, entry, pid_node) {
        seq_printf(m, "%d, %u\n", entry->pid, entry->count);
    }
    return 0;
}
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {

    pid_t pid;

    struct task_struct * task = current;  // `current` gives the currently executing task (which is being scheduled)
    pid = task->pid;

    insert_pid_count(pid);
    return 0;
}

static struct kprobe kp;

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

    kp.symbol_name = "pick_next_task_fair";
    kp.pre_handler = handler_pre;

    if (register_kprobe(&kp) < 0) {
        pr_err("Failed to register kprobe\n");
        return -EINVAL;
    }
    pr_info("perftop module loaded\n");
    return 0;
}

static void __exit perftop_exit(void) {
    
    struct pid_count *entry;
    struct hlist_node *tmp;
    int bkt;

    // Clean up the hash table by freeing each entry
    hash_for_each_safe(pid_table, bkt, tmp, entry, pid_node) {
        hash_del(&entry->pid_node);  // Remove the entry from the hash table
        kfree(entry);  // Free the memory allocated for the entry
    }
    remove_proc_entry("perftop", NULL);
    unregister_kprobe(&kp);
    pr_info("perftop module unloaded\n");
}

module_init(perftop_init);
module_exit(perftop_exit);