#define LINUX

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timer.h> 
#include <linux/workqueue.h> 
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/jiffies.h>  

#include "mp3_given.h"

// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Asuthosh Anandaram <aa69@illinois.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CS-423 MP3");

#define REGISTER 'R'
#define DEREGISTER 'D'

static struct proc_dir_entry *proc_dir, *proc_entry; 

static LIST_HEAD(pcb_task_list);

struct kmem_cache *pcb_slab;
static DEFINE_MUTEX(pcb_list_mutex);

struct pcb {
	struct task_struct *linux_task;
	struct list_head list;
	pid_t pid;
};


void register_task(char *kbuf);
void deregister_task(char *kbuf);


#define DEBUG 1
//------------------------------------------------------------------
static ssize_t read_handler(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{
	printk( KERN_DEBUG "read handler\n");
	return 0;
}

static ssize_t write_handler(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{	
	
    char *kbuffer = kmalloc(count + 1, GFP_KERNEL);
	
    if (!kbuffer) {
        return -ENOMEM;
    }

    // Copy data from user space to the kernel buffer
    if (copy_from_user(kbuffer, ubuf, count)) {
        printk(KERN_ALERT "invalid copy data");
        kfree(kbuffer);
        return -EFAULT; 
    }

    kbuffer[count] = '\0';  // Null-terminate the string


	if(kbuffer[0] == 'R') {
		register_task(kbuffer);
	}

	else if(kbuffer[0] == 'U') {
		deregister_task(kbuffer);
	}

    kfree(kbuffer);  // Free the allocated memory
    return count;
}

void register_task(char *kbuf) {

    struct pcb *reg_pcb = kmem_cache_alloc(pcb_slab, GFP_KERNEL); 
    if(!reg_pcb) {
        printk(KERN_ERR "Failed to allocate memory for new task\n");
        return;
    }

    INIT_LIST_HEAD(&reg_pcb->list); 

    sscanf(kbuf, "R %u", &reg_pcb->pid); 

	printk(KERN_ALERT "reg_pcb_pid : %d\n", reg_pcb->pid); 

    mutex_lock(&pcb_list_mutex);
    list_add(&reg_pcb->list, &pcb_task_list);
    mutex_unlock(&pcb_list_mutex);
}

void deregister_task(char *kbuf) {
	struct pcb *pos, *next; 
	unsigned int pid; 

	sscanf(kbuf, "U %u", &pid); 

	printk(KERN_ALERT "dereg_pcb_pid : %d\n", pid); 

	mutex_lock(&pcb_list_mutex); 
	list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
		if(pos->pid == pid) {
			list_del(&pos->list);
			kmem_cache_free(pcb_slab, pos);
			break; 
		}
	}
	mutex_unlock(&pcb_list_mutex); 
}


static const struct proc_ops mp3_ops = 
{
	.proc_open = simple_open,
	.proc_read = read_handler,
	.proc_write = write_handler,
};


// mp3_init - Called when module is loaded
int __init rts_init(void)
{
#ifdef DEBUG
	printk(KERN_ALERT "RTS MODULE LOADING\n");
#endif
	// Insert your code here ...

	proc_dir = proc_mkdir("mp3", NULL);
	printk(KERN_ALERT "mp3 created....\n"); 

	proc_entry = proc_create("status", 0666, proc_dir, &mp3_ops);

	if (!proc_entry) {
		printk(KERN_ALERT "status creation failed....\n");
		return -ENOMEM;
	}
	printk(KERN_ALERT "status created....\n");

	pcb_slab = kmem_cache_create("pcb_slab_allocator", sizeof(struct pcb), 0, SLAB_HWCACHE_ALIGN, NULL); 


	printk(KERN_ALERT "RTS MODULE LOADED\n");
	return 0;
}

// mp3_exit - Called when module is unloaded
void __exit rts_exit(void)
{
	struct pcb *pos, *next; 
#ifdef DEBUG
	printk(KERN_ALERT "RTS MODULE UNLOADING\n");
#endif
	// Insert your code here ...

	mutex_destroy(&pcb_list_mutex);

	list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
			list_del(&pos->list);
			kmem_cache_free(pcb_slab, pos);
	}

	kmem_cache_destroy(pcb_slab);

	remove_proc_entry("status", proc_dir);
	printk(KERN_WARNING "status removed....\n");

	// Remove the directory within the proc filesystem
	remove_proc_entry("mp3", NULL);
	printk(KERN_WARNING "mp3 removed...\n");

	printk(KERN_ALERT "RTS MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(rts_init);
module_exit(rts_exit);