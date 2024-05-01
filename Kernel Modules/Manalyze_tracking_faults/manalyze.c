#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/sched.h>
#include <linux/kprobes.h>
#include<linux/binfmts.h>
#include <asm/tlbflush.h>
#include <asm-generic/mman-common.h>

static unsigned long tracked_addr;
static int tracked_pid;
static unsigned long no_of_page_faults;
static unsigned long page_fault_anon_read;
static unsigned long page_fault_anon_write;
static unsigned long page_fault_file_mapped_read;
static unsigned long page_fault_file_mapped_write;
static int populate_flag;
static int __kprobes my_pf_hook(struct kprobe *p, struct pt_regs *regs)
{
//       struct vm_fault* vmf;
//         unsigned long address;  
  struct task_struct *tsk = current;
//   struct pt_regs *uregs = (struct pt_regs*)regs->cx;
  unsigned long address = regs->si;
  unsigned long fault_flags = regs->dx;  //created based on error code
  struct vm_area_struct *vma = (struct vm_area_struct*)regs->di;
  address = (address >> PAGE_SHIFT) << PAGE_SHIFT;

  if(tsk->pid == tracked_pid){
        //  dump_stack();
        no_of_page_faults++;
        if (!vma->vm_file && !vma->vm_ops){
                if(fault_flags & 0x1){
                        page_fault_anon_write++;
                        printk(KERN_INFO ",0x%lx,0",address);
                }
                else{
                        page_fault_anon_read++;
                        printk(KERN_INFO ",0x%lx,1",address);
                }
        }
        else if(vma->vm_file){
                if(fault_flags & 0x1){
                        page_fault_file_mapped_write++;
                        printk(KERN_INFO ",0x%lx,2",address);
                }
                else{
                        page_fault_file_mapped_read++;
                        printk(KERN_INFO ",0x%lx,3",address);
                }
        }
	else {
		// printk(KERN_INFO "Not getting the anon read fault for error code = 0x%lx ",fault_flags);
	}
        //   printk(KERN_INFO "Page fault pid = %d address [0x%lx] error code = 0x%lx ", 
	// 		  tsk->pid, address, fault_flags);
        // if(vma == NULL)
        // {
        //         printk(KERN_INFO "No VMA for this address\n");
        // }
        // else if(vma->vm_ops == NULL)
        // {
        //         printk(KERN_INFO "No vm_ops for this VMA\n");
        // }
        // else
        // {
        //         printk(KERN_INFO"map_pages = [%lu]\n",(unsigned long int)vma->vm_ops->map_pages);
        // }
  }
//  if (current->pid == tracked_pid) {
//         vmf = (struct vm_fault *)regs->di;
//         address = vmf->address;

//         printk(KERN_INFO "Do fault around called for address [0x%lx] and the flags [%d]\n", address, vmf->flags);
//  }
  return 0;	
}
static int __kprobes my_mp_hook(struct kprobe *p, struct pt_regs *regs)
{
        // unsigned long flags = regs->r8;
        if (populate_flag){
        printk(KERN_INFO "do_mmap called with populate flag: %d current_pid:%ul tracked_pid:%ul \n", populate_flag, current->pid, tracked_pid);

        if(populate_flag && current->pid == tracked_pid){
        printk(KERN_INFO "Setting MAP_POPULATE flag\n");
                regs->r8 = regs->r8 | MAP_POPULATE;
        }
        }
        return 0;
}
static struct kprobe kp_process_fault = {
        .symbol_name   = "handle_mm_fault",
	.pre_handler = my_pf_hook,
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
        //printk(KERN_INFO "pgd(va) [%lx] pgd (pa) [%lx] *pgd [%lx]\n", (unsigned long)pgd, __pa(pgd), pgd->pgd); 
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
        //printk(KERN_INFO "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud); 
        bufctr += sprintf(buf+bufctr, "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud);
        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto nul_ret;
        if (unlikely(pmd_trans_huge(*pmd))){
                printk(KERN_INFO "I am huge\n");
                goto nul_ret;
        }
        //printk(KERN_INFO "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd); 
        bufctr += sprintf(buf+bufctr, "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd);
        ptep = pte_offset_map(pmd, address);
        if(!ptep){
                printk(KERN_INFO "pte_p is null\n\n");
                goto nul_ret;
        }
        //printk(KERN_INFO "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte); 
        bufctr += sprintf(buf+bufctr, "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte);
        *length = bufctr;
        return ptep;

        nul_ret:
               //printk(KERN_INFO "Address could not be translated\n");
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
	printk(KERN_INFO "Tracked process pid = %d\n",newval); 
        tracked_pid = newval;
        no_of_page_faults = 0;
        page_fault_anon_read = 0;
        page_fault_anon_write = 0;
        page_fault_file_mapped_read = 0;
        page_fault_file_mapped_write = 0;
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
        if (err || newval < 0)
                return -EINVAL;
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
        int ret, probe2;
	
	printk(KERN_INFO "Setting the probe\n");

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
	return 0;
}

void cleanup_module(void)
{
        unregister_kprobe(&kp_process_fault);
        unregister_kprobe(&kp_mmap_populate);
        sysfs_remove_group (kernel_kobj, &traphook_attr_group);
        sysfs_remove_group (kernel_kobj, &traphook_attr_group2);
	printk(KERN_INFO "Removed the probes\n");
}

MODULE_AUTHOR("deba@cse.iitk.ac.in");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demo modules");
