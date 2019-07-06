#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/init.h> 
#include <linux/fs.h> 
#include <linux/mm.h> 
#include <linux/libmpk.h> 
#include <linux/uaccess.h>

#define MAX_SIZE (TABLE_SIZE * sizeof(HashEntry) + 0x1000 * 4)   /* max size mmaped to userspace */
#define DEVICE_NAME "libmpk"
#define  CLASS_NAME "sompk"

static struct class*  class;
static struct device*  device;
static int major;

static DEFINE_MUTEX(libmpk_mutex);

/*  executed once the device is closed or releaseed by userspace
 *  @param inodep: pointer to struct inode
 *  @param filep: pointer to struct file 
 */
static int libmpk_release(struct inode *inodep, struct file *filep)
{    
    kfree(table);
    mutex_unlock(&libmpk_mutex);
    pr_info("libmpk: Device successfully closed\n");
    return 0;
}

/* executed once the device is opened.
 *
 */
static int libmpk_open(struct inode *inodep, struct file *filep)
{
    int ret = 0; 

    if(!mutex_trylock(&libmpk_mutex)) {
        pr_alert("libmpk: Device busy!\n");
        ret = -EBUSY;
        goto out;
    }
 
    /* init this mmap area */
		alloc_hash();
    if (table == NULL) {
        ret = -ENOMEM; 
        goto out;
    }
    pr_info("libmpk: Device opened\n");

out:
    return ret;
}

/*  mmap handler to map kernel space to user space  
 *
 */
static int libmpk_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;
    struct page *page = NULL;
    unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

    if (size > MAX_SIZE) {
        ret = -EINVAL;
        goto out;  
    } 
    
    //memset(mmap_table, 0, TABLE_SIZE * sizeof(HashEntry));
    page = virt_to_page((unsigned long)table + (vma->vm_pgoff << PAGE_SHIFT)); 
    ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size, vma->vm_page_prot);
    if (ret != 0) {
        goto out;
    }   

out:
    return ret;
}

static ssize_t libmpk_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int ret;
    
    if (len > MAX_SIZE) {
        pr_info("read overflow!\n");
        ret = -EFAULT;
        goto out;
    }

    if (copy_to_user(buffer, table, len) == 0) {
        pr_info("libmpk: copy %u char to the user\n", len);
        ret = len;
    } else {
        ret =  -EFAULT;   
    } 

out:
    return ret;
}

static ssize_t libmpk_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    int ret;
 
    if (copy_from_user(table, buffer, len)) {
        pr_err("libmpk: write fault!\n");
        ret = -EFAULT;
        goto out;
    }
    pr_info("libmpk: copy %d char from the user\n", len);
    ret = len;

out:
    return ret;
}

static const struct file_operations libmpk_fops = {
    .open = libmpk_open,
    .read = libmpk_read,
    .write = libmpk_write,
    .release = libmpk_release,
    .mmap = libmpk_mmap,
    /* TODO munmap */
    /*.unlocked_ioctl = libmpk_ioctl,*/
    .owner = THIS_MODULE,
};

static char *libmpkdevnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666; // permission 
	return NULL; /* could override /dev name */
}

static int __init libmpk_init(void)
{
    int ret = 0;    
    major = register_chrdev(0, DEVICE_NAME, &libmpk_fops);

    if (major < 0) {
        pr_info("libmpk: fail to register major number!");
        ret = major;
        goto out;
    }

    class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(class)){ 
        unregister_chrdev(major, DEVICE_NAME);
        pr_info("libmpk: failed to register device class");
        ret = PTR_ERR(class);
        goto out;
    }
    class->devnode = libmpkdevnode;
    device = device_create(class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(class);
        unregister_chrdev(major, DEVICE_NAME);
        ret = PTR_ERR(device);
        goto out;
    }


    mutex_init(&libmpk_mutex);
out: 
    return ret;
}

static void __exit libmpk_exit(void)
{
    mutex_destroy(&libmpk_mutex); 
    device_destroy(class, MKDEV(major, 0));  
    class_unregister(class);
    class_destroy(class); 
    unregister_chrdev(major, DEVICE_NAME);
    
    pr_info("libmpk: unregistered!");
}

module_init(libmpk_init);
module_exit(libmpk_exit);
MODULE_LICENSE("GPL");
