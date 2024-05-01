static unsigned nr_prefault_page __read_mostly = 0;
static int tracked_pid __read_mostly = -1; 
#ifdef CONFIG_DEBUG_FS
static int nr_prefault_page_get(void *data, u64 *val)
{
	*val = nr_prefault_page * PAGE_SIZE;
	return 0;
}

static int nr_prefault_page_set(void *data, u64 val)
{
	if (val / PAGE_SIZE > PTRS_PER_PTE)
		return -EINVAL;
	if (val > PAGE_SIZE)
		nr_prefault_page = rounddown_pow_of_two(val) / PAGE_SIZE;
	else
		nr_prefault_page = 1; /* rounddown_pow_of_two(0) is undefined */
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(nr_prefault_page_fops,
		nr_prefault_page_get, nr_prefault_page_set, "%llu\n");

static int __init nr_prefault_page_debugfs(void)
{
	debugfs_create_file_unsafe("nr_prefault_page", 0644, NULL, NULL,
				   &nr_prefault_page_fops);
	return 0;
}
late_initcall(nr_prefault_page_debugfs);



static int tracked_pid_get(void *data, u64 *val)
{
	*val = (u64)tracked_pid;
	return 0;
}

static int tracked_pid_set(void *data, u64 val)
{
	tracked_pid = (long int) val; /* rounddown_pow_of_two(0) is undefined */
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE_SIGNED(track_pid_fops,
		tracked_pid_get, tracked_pid_set, "%llu\n");

static int __init tracked_pid_debugfs(void)
{
	debugfs_create_file_unsafe("tracked_pid", 0644, NULL, NULL,
				   &track_pid_fops);
	return 0;
}
late_initcall(tracked_pid_debugfs);
#endif

void my_prefault_handler(struct vm_fault *vmf){
	pte_t entry;
	bool free_all = false;
	unsigned long address = vmf->address;
	unsigned int off, nr_pages;
	struct vm_area_struct *vma = vmf->vma;
	pte_t *pte = vmf->pte;
	struct page** page_array = NULL;
    off = address & ((1 << 21) - 1);
    off = (off & ~((1 << PAGE_SHIFT) - 1)) >> PAGE_SHIFT;
    nr_pages = min3((u64)(nr_prefault_page - 1u), (u64)(PTRS_PER_PTE - off - 1u), (u64)((vmf->vma->vm_end - address) >> PAGE_SHIFT));
	page_array = kzalloc(nr_pages * sizeof(struct page *), GFP_KERNEL);
	if (!page_array)
        return;

	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	if (userfaultfd_missing(vma))
		goto oom;

	nr_pages = alloc_pages_bulk_array(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, nr_pages, page_array);
	if(nr_pages == 0)
		goto oom;
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, address,
                                               &vmf->ptl);
	for( unsigned int i = 0; i < nr_pages; i += 1){
		if(free_all)
			goto free_page;

		if(mem_cgroup_charge(page_folio(page_array[i]), vma->vm_mm, GFP_KERNEL))
			goto free_page;
		cgroup_throttle_swaprate(page_array[i], GFP_KERNEL);

		__SetPageUptodate(page_array[i]);

		entry = mk_pte(page_array[i], vma->vm_page_prot);
		entry = pte_sw_mkyoung(entry);

		if (vma->vm_flags & VM_WRITE)
			entry = pte_mkwrite(pte_mkdirty(entry));
		
		vmf->pte = (pte_t *)((void *)vmf->pte + sizeof(pte_t));
		address = address + PAGE_SIZE;
		if (!pte_none(*vmf->pte)){
			update_mmu_tlb(vma, address, vmf->pte);
			goto free_page;
		}

		
		if(check_stable_address_space(vma->vm_mm)){
			free_all = true;
			goto free_page;
		}
		
		inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
		page_add_new_anon_rmap(page_array[i], vma, address);
		lru_cache_add_inactive_or_unevictable(page_array[i], vma);

		set_pte_at(vma->vm_mm, address, vmf->pte, entry);
		update_mmu_cache(vma, address, vmf->pte);

		continue;
free_page:
		put_page(page_array[i]);
	}
	pte_unmap_unlock(vmf->pte, vmf->ptl);
oom:
	kfree(page_array);
	vmf->pte = pte;
}