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
#include <linux/kdev_t.h>
#include <linux/list.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include "mp3_given.h"

// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Asuthosh Anandaram <aa69@illinois.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CS-423 MP3");

#define REGISTER 'R'
#define DEREGISTER 'U'
#define NUM_PAGES 128
//#define PAGE_SIZE 4096
#define DELAY_PERIOD 50 // period  = (1 second )/20 = 0.05 seconds = 50 milliseconds
#define PRO_BUF_OFLO 48000 //(NUM_PAGES*PAGE_SIZE/sizeof(unsigned long))
#define BUFFER_SIZE NUM_PAGES * PAGE_SIZE

static struct proc_dir_entry *proc_dir, *proc_entry; 


static LIST_HEAD(pcb_task_list);

struct kmem_cache *pcb_slab;
static DEFINE_MUTEX(pcb_list_mutex);

//augment the Process Control Block (PCB). This created PCB shall include three variables to keep the process utilization (u_time and s_time), major fault count, and minor fault count of the corresponding process.
// The pcb also includes the pid of the task
struct pcb {
	struct task_struct *linux_task;
	struct list_head list;
	pid_t pid;
	unsigned long min_flt; 
	unsigned long maj_flt;
	unsigned long utime; 
	unsigned long stime; 
};

//A memory buffer is allocated in the kernel memory when your kernel module is initialized and is freed when the module is uninitialized. The buffer needs to be virtually contiguous, but does not have to be physically contiguous.
unsigned long *mem_buffer;
unsigned long idx = 0;

int i = 0;

// Initializations for workqueue
static struct workqueue_struct *wq;
static void wq_fn(struct work_struct *work); 
static DECLARE_DELAYED_WORK(mp3_work, wq_fn); 


unsigned long delay; 

//initializations for character device driver
static dev_t mp3_dev;
static struct cdev mp3_cdev;

//function prototype
//-----------------------------------------------------------------
void register_task(char *kbuf);
void deregister_task(char *kbuf);
//----------------------------------------------------------------
#define DEBUG 1
//------------------------------------------------------------------

//workqueue function 
static void wq_fn(struct work_struct *work) {

	//iterate over the list, call get_cpu_time() for all the active processes
	struct pcb *pos,*next; 
	unsigned long min_flt_count = 0; 
	unsigned long maj_flt_count = 0; 
	unsigned long cpu_utilization = 0; 
	unsigned long maj_flt, min_flt, utime, stime;

	 if (!mem_buffer) {
        printk(KERN_ERR "mem_buffer is NULL\n");
        return;
    }

    //The memory buffer is organized as a queue that saves up to 12000 (=20x600) samples. Each sample consists of four unsigned long type data: (a)jiffies value (which is the Linux kernel variable that shows the number of timer ticks executed since the kernel boot-up), (b) minor fault count, (c) major fault count, and (d) CPU utilization (s_time + u_time). The work handler only writes one sample each time. In each sample, (b), (c), and (d) are the sum of that of all the registered processes within a sampling period (1/20 seconds) 

	mutex_lock(&pcb_list_mutex);
	list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
		if(get_cpu_use(pos->pid, &min_flt, &maj_flt, &utime, &stime) == 0) {
			
			printk(KERN_DEBUG "PID=%u, min_flt=%lu, maj_flt=%lu, utime=%lu, stime=%lu\n",pos->pid, min_flt, maj_flt, utime, stime);
			
			pos->min_flt += min_flt;
			pos->maj_flt += maj_flt;
			pos->utime += utime;
			pos->stime += stime;
			maj_flt_count += pos->maj_flt;
			maj_flt_count += pos->maj_flt;
			min_flt_count += pos->min_flt; 
			maj_flt_count += pos->maj_flt;
			cpu_utilization += pos->utime + pos->stime;

		}
		else {
			list_del(&pos->list);
			kfree(pos); 
		}

	}
	mutex_unlock(&pcb_list_mutex);

	mem_buffer[idx++] = jiffies; 
	mem_buffer[idx++] = min_flt_count;
	mem_buffer[idx++] = maj_flt_count; 
	mem_buffer[idx++] = cpu_utilization;

	printk(KERN_DEBUG "mem_buffer[%lu]: jiffies=%lu, min_flt=%lu, maj_flt=%lu, cpu_util=%lu\n", idx / 4, mem_buffer[idx - 4], mem_buffer[idx - 3], mem_buffer[idx - 2], mem_buffer[idx - 1]);


	if (idx + 4 > PRO_BUF_OFLO) {
		printk(KERN_ERR "Index exceeds buffer capacity, resetting\n");
		idx = 0;
	}

	if (wq) {
        queue_delayed_work(wq, &mp3_work, delay);
		//printk(KERN_ALERT "wq scheduled");
		//printk(KERN_INFO "Executing workqueue function at jiffies=%lu\n", jiffies);

    } else {
        printk(KERN_ERR "Workqueue is NULL\n");
    }

}

//used to read registered tasks via cat
static ssize_t read_handler(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) 
{	
	//printk(KERN_ALERT "read_handler"); 

	struct pcb *p; 
	char *kbuf; 
	int len = 0; 
	//ssize_t ret = len; 
	//unsigned long flags; 

	kbuf = (char *)kmalloc(count, GFP_KERNEL); 

	if(!kbuf) {
		return -ENOMEM;
	}

	// traverse over the list and read the current cpu time of the pid.  
	
	mutex_lock(&pcb_list_mutex);
	list_for_each_entry(p, &pcb_task_list, list) {
		len += sprintf(kbuf + len, "%u\n", p->pid);
		//printk(KERN_INFO "PID:%d and READ_TIME:%lu\n", p->pid, p->cpu_time);
		if(len > count) {
	        len = count;
	        break;
	  }
	}
	mutex_unlock(&pcb_list_mutex); 
	
	//printk(KERN_ALERT "Kbuf value in Read handler: %s", kbuf);

	
	//checks bounds of len
	if(len > count) {
	  	len = count;
	}
  
    if (len < count) {
	  kbuf[len] = '\0';
	}

	if(*ppos >= len) {
		kfree(kbuf);
		return 0;
    }
    // send it to user buffer
    if (copy_to_user(ubuf, kbuf, len)) {
		kfree(kbuf);
    	return -EFAULT;
	}
    
	//update *ppos according to len
    *ppos += len;
	kfree(kbuf);

	// return bytes read
	return len;

}

//he write callback function has a switch to separate each type of message (REGISTRATION, UNREGISTRATION).

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

	if(kbuffer[0] == REGISTER) {
		register_task(kbuffer);
	}

	else if(kbuffer[0] == DEREGISTER) {
		deregister_task(kbuffer);
	}

	kfree(kbuffer);  // Free the allocated memory
    return count;

}

//Flip argument is a pointer to a struct file object that represents the open file associated with the mmap operation 
// vma contains the information about the virtual address range that is used to access the device
// https://elixir.bootlin.com/linux/v5.15.127/source/drivers/video/fbdev/smscufx.c#L796

int mmap (struct file *file, struct vm_area_struct *vma) {

   //map the the physical pages of the buffer to the virtual address spave of the requested process
   //vmalloc_to_pfn(addr) : get the physical page addr of a virtual page of the buffer. 
   // remap_pfn_range() is used to map a virtual page of a user process to a physical page (which is obtained by the previous function).
   
   unsigned long start = vma->vm_start; 
   unsigned long size = vma->vm_end - vma->vm_start; 
   unsigned long page; 

   char *mem_buf = (char*)mem_buffer; 

   while(size > 0) {

      page = vmalloc_to_pfn(mem_buf);

      if (remap_pfn_range(vma, start, page, PAGE_SIZE,vma->vm_page_prot)){
			return -EAGAIN;
      }
      start += PAGE_SIZE; 

      mem_buf += PAGE_SIZE; 

      if(size > PAGE_SIZE){
         size -= PAGE_SIZE;
      }

      else {
         size = 0; 
      }

   }
   return 0;

}

//The registration function first adds the requesting process to the PCB list and calls a function that creates a work queue job if the requesting process is the first one in the PCB list.
void register_task(char *kbuf) 
{
	struct pcb *reg_pcb = kmem_cache_alloc(pcb_slab, GFP_KERNEL); 

    if(!reg_pcb) {
        printk(KERN_ERR "Failed to allocate memory for new task\n");
        return;
    }

    INIT_LIST_HEAD(&reg_pcb->list); 

    sscanf(kbuf, "R %u", &reg_pcb->pid); 

	printk(KERN_ALERT "reg_pcb_pid : %d\n", reg_pcb->pid); 

	reg_pcb->linux_task = find_task_by_pid(reg_pcb->pid);

	reg_pcb->min_flt = 0; 
	reg_pcb->maj_flt = 0;
	reg_pcb->utime = 0; 
	reg_pcb->stime = 0;

    mutex_lock(&pcb_list_mutex);
	// if list empty then 
	if(list_empty(&pcb_task_list)) {

		if (!queue_delayed_work(wq, &mp3_work, delay)) {
    	printk(KERN_ERR "Failed to queue delayed work\n");
		}

	}

    list_add(&reg_pcb->list, &pcb_task_list);
    mutex_unlock(&pcb_list_mutex);
}

//the unregister function deletes the requesting process from the PCB list (if exists). Then, if the PCB list is empty after the delete operation, the work queue job is deleted as well.
void deregister_task(char *kbuf)
 {
	
	struct pcb *pos, *next; 
	unsigned int pid; 

	printk(KERN_ALERT "Deregister Kernel Space/n");

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

	if(list_empty(&pcb_task_list)) {
		flush_workqueue(wq); 
	}

	mutex_unlock(&pcb_list_mutex); 

}


static const struct proc_ops mp3_ops = 
{
	.proc_open = simple_open,
	.proc_read = read_handler,
	.proc_write = write_handler,

};

static const struct file_operations mmap_ops = 
{
	.open = simple_open,
	.mmap = mmap,

};



// mp3_init - Called when module is loaded
int __init rts_init(void)
{
#ifdef DEBUG
    printk(KERN_ALERT "RTS MODULE LOADING\n");
#endif

    // Create /proc/mp3 directory and status file
    proc_dir = proc_mkdir("mp3", NULL);
    if (!proc_dir) {
        printk(KERN_ALERT "Failed to create /proc/mp3 directory\n");
        return -ENOMEM;
    }
    printk(KERN_ALERT "mp3 directory created....\n");

    proc_entry = proc_create("status", 0666, proc_dir, &mp3_ops);
    if (!proc_entry) {
        printk(KERN_ALERT "status creation failed....\n");
        remove_proc_entry("mp3", NULL);
        return -ENOMEM;
    }
    printk(KERN_ALERT "status created....\n");

    // Create slab cache for pcb struct
    pcb_slab = kmem_cache_create("pcb_slab_allocator", sizeof(struct pcb), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!pcb_slab) {
        printk(KERN_ERR "Failed to create pcb slab allocator\n");
        remove_proc_entry("status", proc_dir);
        remove_proc_entry("mp3", NULL);
        return -ENOMEM;
    }

    // Allocate memory for shared buffer
    mem_buffer = (unsigned long *)vmalloc(NUM_PAGES * PAGE_SIZE);
    if (!mem_buffer) {
        printk(KERN_ERR "Failed to allocate mem_buffer\n");
        kmem_cache_destroy(pcb_slab);
        remove_proc_entry("status", proc_dir);
        remove_proc_entry("mp3", NULL);
        return -ENOMEM;
    }
	memset(mem_buffer, -1, NUM_PAGES * PAGE_SIZE);

    // Initialize workqueue
    delay = msecs_to_jiffies(DELAY_PERIOD);
    wq = create_workqueue("wq");
    if (!wq) {
        printk(KERN_ERR "Failed to create workqueue\n");
        vfree(mem_buffer);
        kmem_cache_destroy(pcb_slab);
        remove_proc_entry("status", proc_dir);
        remove_proc_entry("mp3", NULL);
        return -ENOMEM;
    }

    // Register the character device
    int ret;
    ret = register_chrdev_region(MKDEV(423, 0), 1, "mp3_dev"); // Use major number 423
    if (ret < 0) {
        printk(KERN_ERR "Failed to register char device region\n");
        destroy_workqueue(wq);
        vfree(mem_buffer);
        kmem_cache_destroy(pcb_slab);
        remove_proc_entry("status", proc_dir);
        remove_proc_entry("mp3", NULL);
        return ret;
    }

    cdev_init(&mp3_cdev, &mmap_ops);
    ret = cdev_add(&mp3_cdev, MKDEV(423, 0), 1); // Minor number is 0
    if (ret < 0) {
        printk(KERN_ERR "Failed to add char device\n");
        unregister_chrdev_region(MKDEV(423, 0), 1);
        destroy_workqueue(wq);
        vfree(mem_buffer);
        kmem_cache_destroy(pcb_slab);
        remove_proc_entry("status", proc_dir);
        remove_proc_entry("mp3", NULL);
        return ret;
    }

	// source https://linux-kernel-labs.github.io/refs/heads/master/labs/memory_mapping.html
	for (i = 0; i < NUM_PAGES; i++) {
		SetPageReserved(vmalloc_to_page((char *)mem_buffer + i * PAGE_SIZE));
	}

    printk(KERN_ALERT "RTS MODULE LOADED\n");
    return 0;
}


// mp3_exit - Called when module is unloaded
void __exit rts_exit(void)
{
    struct pcb *pos, *next;

    printk(KERN_ALERT "RTS MODULE UNLOADING\n");

    // Cancel and destroy workqueue
    if (wq) {
        if (delayed_work_pending(&mp3_work)) {
            cancel_delayed_work_sync(&mp3_work);
        }
        flush_workqueue(wq);
        destroy_workqueue(wq);
        wq = NULL;
    }

    // Destroy mutex
    mutex_destroy(&pcb_list_mutex);

    // Free all tasks in the list
    list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
        list_del(&pos->list);
        kmem_cache_free(pcb_slab, pos);
    }

    // Destroy slab cache
    if (pcb_slab) {
        kmem_cache_destroy(pcb_slab);
        pcb_slab = NULL;
    }

    // Free and unmap memory buffer
    if (mem_buffer) {
        for (i = 0; i < NUM_PAGES; i++) {
            ClearPageReserved(vmalloc_to_page((char *)mem_buffer + i * PAGE_SIZE));
        }
        vfree(mem_buffer);
        mem_buffer = NULL;
    }

    // Remove proc entries
    if (proc_entry) {
        remove_proc_entry("status", proc_dir);
        proc_entry = NULL;
    }
    if (proc_dir) {
        remove_proc_entry("mp3", NULL);
        proc_dir = NULL;
    }

    // Cleanup character device
    cdev_del(&mp3_cdev);
    unregister_chrdev_region(mp3_dev, 1);

    printk(KERN_ALERT "RTS MODULE UNLOADED\n");
}


// Register init and exit funtions
module_init(rts_init);
module_exit(rts_exit);

