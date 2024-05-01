
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/timekeeping.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/sched.h>
#include <linux/kprobes.h>
#include<linux/binfmts.h>
#include <asm/tlbflush.h>
#include <asm-generic/mman-common.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>

#define ERROR_SIZE 4
#define BUFFER_SIZE 4080

static char *k_buff;
static int k_buff_ptr = 0;
static unsigned long tracked_addr;
static int tracked_pid = -1;
static unsigned long no_of_page_faults;
static unsigned long page_fault_anon_read;
static unsigned long page_fault_anon_write;
static unsigned long page_fault_file_mapped_read;
static unsigned long page_fault_file_mapped_write;
static int populate_flag;
static struct file*log_file;

static int do_track(void){
    struct task_struct *p_tmp;
    for(p_tmp = current; p_tmp->pid; p_tmp = p_tmp->real_parent)
        if(p_tmp->pid == tracked_pid) return 1; // Found path to 'ansc'
    return 0;
}
static int __kprobes my_pf_hook2(struct kprobe *p, struct pt_regs *regs){
       struct vm_fault *vmf = (struct vm_fault*)regs->di;
       unsigned long address = vmf->real_address;

        if (current->pid == tracked_pid){
                printk(KERN_INFO "do_swap_page called for the address %lx\n", address);
        }
        return 0;
}
static int __kprobes my_pf_hook(struct kprobe *p, struct pt_regs *regs)
{  
  unsigned long address = regs->si;
  unsigned long fault_flags = regs->dx;  //created based on error code
  unsigned long current_time = ktime_get_ns();
  struct vm_area_struct *vma = (struct vm_area_struct*)regs->di;
  unsigned long packed_entry;
  address = (address >> 12);
  if(!k_buff)
        return 0;

  if(do_track()){
        no_of_page_faults++;
        if (!vma->vm_file && !vma->vm_ops){
                if(fault_flags & 0x1){
                        page_fault_anon_write++;
                        packed_entry = (address << ERROR_SIZE) | 0x0;
                }
                else{
                        page_fault_anon_read++;
                        packed_entry = (address << ERROR_SIZE) | 0x1;
                }
                k_buff_ptr += sprintf(k_buff+k_buff_ptr, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", (char)(packed_entry>>32), (char)(packed_entry >> 24), (char)(packed_entry >> 16), (char)(packed_entry >> 8), (char)(packed_entry), (char)(current_time >> 56), (char)(current_time >> 48), (char)(current_time >> 40), (char)(current_time >> 32), (char)(current_time >> 24), (char)(current_time >> 16), (char)(current_time >> 8), (char)(current_time),(char)(current->pid >> 24), (char)(current->pid >> 16), (char)(current->pid >> 8), (char)(current->pid));
        }
        else if(vma->vm_file){
                if(fault_flags & 0x1){
                        page_fault_file_mapped_write++;
                        packed_entry = (address << ERROR_SIZE) | 0x2;
                }
                else{
                        page_fault_file_mapped_read++;
                        packed_entry = (address << ERROR_SIZE) | 0x3;
                }
                k_buff_ptr += sprintf(k_buff+k_buff_ptr, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", (char)(packed_entry>>32), (char)(packed_entry >> 24), (char)(packed_entry >> 16), (char)(packed_entry >> 8), (char)(packed_entry), (char)(current_time >> 56), (char)(current_time >> 48), (char)(current_time >> 40), (char)(current_time >> 32), (char)(current_time >> 24), (char)(current_time >> 16), (char)(current_time >> 8), (char)(current_time),(char)(current->pid >> 24), (char)(current->pid >> 16), (char)(current->pid >> 8), (char)(current->pid));
        }
        if(k_buff_ptr >= BUFFER_SIZE){
                if(!log_file)
                        printk(KERN_INFO "no open file, flushing buffer\n");
                kernel_write(log_file, k_buff, BUFFER_SIZE, &log_file->f_pos);
                k_buff_ptr = 0;
        }
  }
  return 0;	
}
static int __kprobes my_mp_hook(struct kprobe *p, struct pt_regs *regs)
{
        if(populate_flag && current->pid == tracked_pid){
        printk(KERN_INFO "Setting MAP_POPULATE flag\n");
                regs->r8 = regs->r8 | MAP_POPULATE;
        }
        return 0;
}
static struct kprobe kp_process_fault = {
        .symbol_name   = "handle_mm_fault",
	.pre_handler = my_pf_hook,
	.post_handler = NULL,
};
static struct kprobe kp_process_fault2 = {
        .symbol_name   = "do_swap_page",
	.pre_handler = my_pf_hook2,
	.post_handler = NULL,
};
static struct kprobe kp_mmap_populate = {
        .symbol_name   = "do_mmap",
        .pre_handler = my_mp_hook,
        .post_handler = NULL,
};
static pte_t* get_pte(unsigned long address, char *buf, size_t *length)
{
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;
	size_t bufctr = 0;
        struct mm_struct *mm = current->mm;
        struct vm_area_struct *vma = find_vma(mm, address);
        if(!vma){
                 bufctr += sprintf(buf+bufctr, "No VMA for this address\n"); 
                 goto nul_ret;
        }
       

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto nul_ret;
        bufctr += sprintf(buf+bufctr, "pgd(va) [%lx] pgd (pa) [%lx] *pgd [%lx]\n", (unsigned long)pgd, __pa(pgd), pgd->pgd); 
        p4d = p4d_offset(pgd, address);
        if (p4d_none(*p4d))
                goto nul_ret;
        if (unlikely(p4d_bad(*p4d)))
                goto nul_ret;
        pud = pud_offset(p4d, address);
        if (pud_none(*pud))
                goto nul_ret;
        if (unlikely(pud_bad(*pud)))
                goto nul_ret;
        bufctr += sprintf(buf+bufctr, "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud);
        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto nul_ret;
        if (unlikely(pmd_trans_huge(*pmd))){
                printk(KERN_INFO "I am huge\n");
                goto nul_ret;
        }
        bufctr += sprintf(buf+bufctr, "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd);
        ptep = pte_offset_map(pmd, address);
        if(!ptep){
                printk(KERN_INFO "pte_p is null\n\n");
                goto nul_ret;
        }
        bufctr += sprintf(buf+bufctr, "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte);
        *length = bufctr;
        return ptep;

        nul_ret:
               bufctr += sprintf(buf+bufctr, "Address could not be translated\n"); 
               *length = bufctr;
               return NULL;

}

//sysfs entries

static ssize_t read_pid(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%d\n", tracked_pid);
}

static ssize_t set_pid(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        int newval;
        int err = kstrtoint(buf, 10, &newval);
        // if (err || newval < 0)
        //         return -EINVAL;
	printk(KERN_INFO "Tracked process pid = %d\n",newval); 
        if(log_file)
                filp_close(log_file, NULL);
        
        log_file = filp_open("/logfile", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (!log_file || IS_ERR(log_file)) {
                printk(KERN_INFO "Error opening log file\n");
        }
        tracked_pid = newval;
        no_of_page_faults = 0;
        page_fault_anon_read = 0;
        page_fault_anon_write = 0;
        page_fault_file_mapped_read = 0;
        page_fault_file_mapped_write = 0;
        k_buff_ptr = 0;
        return count;
}

static struct kobj_attribute memhook_pid_attribute = __ATTR(tracked_pid, 0644, read_pid, set_pid);

static ssize_t memhook_get_addr(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "No of page faults:%lu\nNo of file_mapped_write:%lu\nNo of file_mapped_read:%lu\nNo of anon_write:%lu\nNo of anon_read:%lu\n", no_of_page_faults, page_fault_file_mapped_write, page_fault_file_mapped_read, page_fault_anon_write, page_fault_anon_read);
}

static ssize_t memhook_set_addr(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        unsigned long newval;
        int err = kstrtoul(buf, 16, &newval);
        tracked_addr = newval;
        no_of_page_faults = 0;
        page_fault_anon_read = 0;
        page_fault_anon_write = 0;
        page_fault_file_mapped_read = 0;
        page_fault_file_mapped_write = 0;
	printk("Fault for addr [0x%lx] is tracked\n", tracked_addr);
        return count;
}
static struct kobj_attribute memhook_addr_attribute = __ATTR(tracked_faults, 0644, memhook_get_addr, memhook_set_addr);

static struct attribute *memhook_attrs[] = {
        &memhook_pid_attribute.attr,
        &memhook_addr_attribute.attr,
        NULL,
};
static ssize_t populate_get(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%d\n",populate_flag);
}
static ssize_t populate_set(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        int newval;
        int err = kstrtoint(buf, 10, &newval);
        if (err || newval < 0)
                return -EINVAL;
        populate_flag = newval;
        printk(KERN_INFO "populate_flag = %d\n",populate_flag);
        return count;
}
static struct kobj_attribute map_populate_hook_flag_attribute = __ATTR(populate,0644,populate_get, populate_set);
static struct attribute *map_populate_hook_attrs[] = {
        &map_populate_hook_flag_attribute.attr,
        NULL,
};
static struct attribute_group traphook_attr_group = {
        .attrs = memhook_attrs,
        .name = "cs614hook",
};
static struct attribute_group traphook_attr_group2 = {
        .attrs = map_populate_hook_attrs,
        .name = "map_populate_hook",
};
int init_module(void)
{
        int ret, probe2,probe3;
	
	printk(KERN_INFO "Setting the probe\n");
        k_buff = kmalloc(BUFFER_SIZE, GFP_KERNEL);
        if (!k_buff) {
                printk(KERN_INFO "kmalloc failed\n");
                return -ENOMEM;
        }
	ret = register_kprobe(&kp_process_fault);
        if (ret < 0) {
                printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
                return ret;
        }
        printk(KERN_INFO "Planted kprobe at %lx\n", (unsigned long)kp_process_fault.addr);
	
	ret = sysfs_create_group (kernel_kobj, &traphook_attr_group);
        if(unlikely(ret)){
                printk(KERN_INFO "demo: can't create sysfs\n");
                unregister_kprobe(&kp_process_fault);
		return ret;
	}
        probe2 = register_kprobe(&kp_mmap_populate);
        if (probe2 < 0) {
                printk(KERN_INFO "register_kprobe failed, returned %d\n", probe2);
                return probe2;
        }
        probe2 = sysfs_create_group (kernel_kobj, &traphook_attr_group2);
        if(unlikely(probe2)){
                printk(KERN_INFO "demo: can't create sysfs\n");
                unregister_kprobe(&kp_mmap_populate);
                return probe2;
        }
        probe3 = register_kprobe(&kp_process_fault2);
        if (probe3 < 0) {
                printk(KERN_INFO "register_kprobe failed, returned %d\n", probe3);
                return probe3;
        }
	return 0;
}

void cleanup_module(void)
{       
        if (k_buff_ptr > 0 && log_file)
                kernel_write(log_file, k_buff, k_buff_ptr, &log_file->f_pos); 
        kfree(k_buff);
        if(log_file)
                filp_close(log_file, NULL);
        unregister_kprobe(&kp_process_fault);
        unregister_kprobe(&kp_mmap_populate);
        unregister_kprobe(&kp_process_fault2);
        sysfs_remove_group (kernel_kobj, &traphook_attr_group);
        sysfs_remove_group (kernel_kobj, &traphook_attr_group2);
	printk(KERN_INFO "Removed the probes\n");
}

MODULE_AUTHOR("deba@cse.iitk.ac.in");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demo modules");
