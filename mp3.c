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
#define PRO_BUF_OFLO (NUM_PAGES*PAGE_SIZE/sizeof(unsigned long))

static struct proc_dir_entry *proc_dir, *proc_entry; 

static LIST_HEAD(pcb_task_list);

struct kmem_cache *pcb_slab;
static DEFINE_MUTEX(pcb_list_mutex);

struct pcb {
	struct task_struct *linux_task;
	struct list_head list;
	pid_t pid;
	unsigned long min_flt; 
	unsigned long maj_flt;
	unsigned long utime; 
	unsigned long stime; 
};

unsigned long *mem_buffer;
unsigned long idx = 0;

static struct workqueue_struct *wq;
static void wq_fn(struct work_struct *work); 
static DECLARE_DELAYED_WORK(mp3_work, wq_fn); 


unsigned long delay; 

static dev_t mp3_dev;
static struct cdev mp3_cdev;
//-----------------------------------------------------------------
void register_task(char *kbuf);
void deregister_task(char *kbuf);
//----------------------------------------------------------------
#define DEBUG 1
//------------------------------------------------------------------
static void wq_fn(struct work_struct *work) {

	//iterate over the list, call get_cpu_time() for all the active processes
	struct pcb *pos,*next; 
	unsigned long min_flt_count = 0; 
	unsigned long maj_flt_count = 0; 
	unsigned long cpu_utilization = 0; 

	 if (!mem_buffer) {
        printk(KERN_ERR "mem_buffer is NULL\n");
        return;
    }

	mutex_lock(&pcb_list_mutex);
	list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
		if(get_cpu_use(pos->pid, &pos->min_flt, &pos->maj_flt, &pos->utime, &pos->stime) == 0) {
			
			//printk(KERN_INFO "PID=%u, min_flt=%lu, maj_flt=%lu, utime=%lu, stime=%lu\n",pos->pid, pos->min_flt, pos->maj_flt, pos->utime, pos->stime);
			
			min_flt_count += pos->min_flt; 
			maj_flt_count += pos->maj_flt;
			cpu_utilization += pos->utime + pos->stime;

		}
		else {
			continue; 
		}

	}


	mutex_unlock(&pcb_list_mutex);

	mem_buffer[idx++] = jiffies; 
	mem_buffer[idx++] = min_flt_count;
	mem_buffer[idx++] = maj_flt_count; 
	mem_buffer[idx++] = cpu_utilization;

	//printk(KERN_INFO "mem_buffer[%lu]: jiffies=%lu, min_flt=%lu, maj_flt=%lu, cpu_util=%lu\n", idx / 4, mem_buffer[idx - 4], mem_buffer[idx - 3], mem_buffer[idx - 2], mem_buffer[idx - 1]);


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

int mmap (struct file *filp, struct vm_area_struct *vma) {

   //map the the physical pages of the buffer to the virtual address spave of the requested process
   //vmalloc_to_pfn(addr) : get the physical page addr of a virtual page of the buffer. 
   // remap_pfn_range() is used to map a virtual page of a user process to a physical page (which is obtained by the previous function).
   
   unsigned long start = vma->vm_start; 
   unsigned long size = vma->vm_end - vma->vm_start; 
   unsigned long page; 

   char *mem_buf = (char*)mem_buffer; 

   while(size > 0) {

      page = vmalloc_to_pfn(mem_buf);

      if (remap_pfn_range(vma, start, page, PAGE_SIZE, PAGE_SHARED)){
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

	mem_buffer = (unsigned long *)vmalloc(NUM_PAGES*PAGE_SIZE); 

	if (!mem_buffer) {
    printk(KERN_ERR "Failed to allocate mem_buffer\n");
    return -ENOMEM; // Exit initialization if allocation fails
	}

	delay = msecs_to_jiffies(DELAY_PERIOD); 

	wq = create_workqueue("wq"); 
	if (!wq) {
    printk(KERN_ERR "Failed to create workqueue\n");
    return -ENOMEM;
	}

   //register the device using register_chrdev_region()
    /*Creating cdev structure*/

    alloc_chrdev_region(&mp3_dev, 0, 1, "mp3_dev"); 
    cdev_init(&mp3_cdev,&mmap_ops);

    // /*Adding character device to the system*/
    if((cdev_add(&mp3_cdev,mp3_dev,1)) < 0){
        pr_err("Cannot add the device to the system\n");
        //goto r_class;
    }
    

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


	if(delayed_work_pending(&mp3_work)) {
		cancel_delayed_work_sync(&mp3_work);
	}

	flush_workqueue(wq);
	destroy_workqueue(wq);

	mutex_destroy(&pcb_list_mutex);

	list_for_each_entry_safe(pos, next, &pcb_task_list, list) {
			list_del(&pos->list);
			kmem_cache_free(pcb_slab, pos);
	}

	kmem_cache_destroy(pcb_slab);

	vfree(mem_buffer);

	 unregister_chrdev_region(mp3_dev, 1);

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