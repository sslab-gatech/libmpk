/// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/mprotect.c
 *
 *  (C) Copyright 1994 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 *
 *  Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 *  (C) Copyright 2002 Red Hat Inc, All Rights Reserved
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/personality.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/perf_event.h>
#include <linux/pkeys.h>
#include <linux/ksm.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/khugepaged.h>
#include <linux/userfaultfd_k.h>
#include <linux/module.h>
#include <linux/binfmts.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

#include <linux/sched/signal.h> /* send_sig */
#include <linux/sched.h>        /*kick_process */
#include <asm/fpu/xstate.h>     /*get_xsave_addr */
#include <linux/tracehook.h>
#include <linux/task_work.h>
#include <asm/msr.h> /*rdtsc()*/

#include "internal.h"

static unsigned long change_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable, int prot_numa)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte, oldpte;
	spinlock_t *ptl;
	unsigned long pages = 0;
	int target_node = NUMA_NO_NODE;

	/*
	 * Can be called with only the mmap_sem for reading by
	 * prot_numa so we must check the pmd isn't constantly
	 * changing from under us from pmd_none to pmd_trans_huge
	 * and/or the other way around.
	 */
	if (pmd_trans_unstable(pmd))
		return 0;

	/*
	 * The pmd points to a regular pte so the pmd can't change
	 * from under us even if the mmap_sem is only hold for
	 * reading.
	 */
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);

	/* Get target node for single threaded private VMAs */
	if (prot_numa && !(vma->vm_flags & VM_SHARED) &&
	    atomic_read(&vma->vm_mm->mm_users) == 1)
		target_node = numa_node_id();

	flush_tlb_batched_pending(vma->vm_mm);
	arch_enter_lazy_mmu_mode();
	do {
		oldpte = *pte;
		if (pte_present(oldpte)) {
			pte_t ptent;
			bool preserve_write = prot_numa && pte_write(oldpte);

			/*
			 * Avoid trapping faults against the zero or KSM
			 * pages. See similar comment in change_huge_pmd.
			 */
			if (prot_numa) {
				struct page *page;

				page = vm_normal_page(vma, addr, oldpte);
				if (!page || PageKsm(page))
					continue;

				/* Avoid TLB flush if possible */
				if (pte_protnone(oldpte))
					continue;

				/*
				 * Don't mess with PTEs if page is already on the node
				 * a single-threaded process is running on.
				 */
				if (target_node == page_to_nid(page))
					continue;
			}

			ptent = ptep_modify_prot_start(mm, addr, pte);
			ptent = pte_modify(ptent, newprot);
			if (preserve_write)
				ptent = pte_mk_savedwrite(ptent);

			/* Avoid taking write faults for known dirty pages */
			if (dirty_accountable && pte_dirty(ptent) &&
					(pte_soft_dirty(ptent) ||
					 !(vma->vm_flags & VM_SOFTDIRTY))) {
				ptent = pte_mkwrite(ptent);
			}
			ptep_modify_prot_commit(mm, addr, pte, ptent);
			pages++;
		} else if (IS_ENABLED(CONFIG_MIGRATION)) {
			swp_entry_t entry = pte_to_swp_entry(oldpte);

			if (is_write_migration_entry(entry)) {
				pte_t newpte;
				/*
				 * A protection check is difficult so
				 * just be safe and disable write
				 */
				make_migration_entry_read(&entry);
				newpte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(oldpte))
					newpte = pte_swp_mksoft_dirty(newpte);
				set_pte_at(mm, addr, pte, newpte);

				pages++;
			}

			if (is_write_device_private_entry(entry)) {
				pte_t newpte;

				/*
				 * We do not preserve soft-dirtiness. See
				 * copy_one_pte() for explanation.
				 */
				make_device_private_entry_read(&entry);
				newpte = swp_entry_to_pte(entry);
				set_pte_at(mm, addr, pte, newpte);

				pages++;
			}
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);

	return pages;
}

static inline unsigned long change_pmd_range(struct vm_area_struct *vma,
		pud_t *pud, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	pmd_t *pmd;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long next;
	unsigned long pages = 0;
	unsigned long nr_huge_updates = 0;
	unsigned long mni_start = 0;

	pmd = pmd_offset(pud, addr);
	do {
		unsigned long this_pages;

		next = pmd_addr_end(addr, end);
		if (!is_swap_pmd(*pmd) && !pmd_trans_huge(*pmd) && !pmd_devmap(*pmd)
				&& pmd_none_or_clear_bad(pmd))
			continue;

		/* invoke the mmu notifier if the pmd is populated */
		if (!mni_start) {
			mni_start = addr;
			mmu_notifier_invalidate_range_start(mm, mni_start, end);
		}

		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
			if (next - addr != HPAGE_PMD_SIZE) {
				__split_huge_pmd(vma, pmd, addr, false, NULL);
			} else {
				int nr_ptes = change_huge_pmd(vma, pmd, addr,
						newprot, prot_numa);

				if (nr_ptes) {
					if (nr_ptes == HPAGE_PMD_NR) {
						pages += HPAGE_PMD_NR;
						nr_huge_updates++;
					}

					/* huge pmd was handled */
					continue;
				}
			}
			/* fall through, the trans huge pmd just split */
		}
		this_pages = change_pte_range(vma, pmd, addr, next, newprot,
				 dirty_accountable, prot_numa);
		pages += this_pages;
	} while (pmd++, addr = next, addr != end);

	if (mni_start)
		mmu_notifier_invalidate_range_end(mm, mni_start, end);

	if (nr_huge_updates)
		count_vm_numa_events(NUMA_HUGE_PTE_UPDATES, nr_huge_updates);
	return pages;
}

static inline unsigned long change_pud_range(struct vm_area_struct *vma,
		p4d_t *p4d, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	pud_t *pud;
	unsigned long next;
	unsigned long pages = 0;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		pages += change_pmd_range(vma, pud, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (pud++, addr = next, addr != end);

	return pages;
}

static inline unsigned long change_p4d_range(struct vm_area_struct *vma,
		pgd_t *pgd, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long pages = 0;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		pages += change_pud_range(vma, p4d, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (p4d++, addr = next, addr != end);

	return pages;
}

static unsigned long change_protection_range(struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable, int prot_numa)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	unsigned long next;
	unsigned long start = addr;
	unsigned long pages = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	inc_tlb_flush_pending(mm);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		pages += change_p4d_range(vma, pgd, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (pgd++, addr = next, addr != end);

	/* Only flush the TLB if we actually modified any entries: */
	if (pages)
		flush_tlb_range(vma, start, end);
	dec_tlb_flush_pending(mm);

	return pages;
}

unsigned long change_protection(struct vm_area_struct *vma, unsigned long start,
		       unsigned long end, pgprot_t newprot,
		       int dirty_accountable, int prot_numa)
{
	unsigned long pages;

	if (is_vm_hugetlb_page(vma))
		pages = hugetlb_change_protection(vma, start, end, newprot);
	else
		pages = change_protection_range(vma, start, end, newprot, dirty_accountable, prot_numa);

	return pages;
}

int
mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned long newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	long nrpages = (end - start) >> PAGE_SHIFT;
	unsigned long charged = 0;
	pgoff_t pgoff;
	int error;
	int dirty_accountable = 0;

	if (newflags == oldflags) {
		*pprev = vma;
		return 0;
	}

	/*
	 * If we make a private mapping writable we increase our commit;
	 * but (without finer accounting) cannot reduce our commit if we
	 * make it unwritable again. hugetlb mapping were accounted for
	 * even if read-only so there is no need to account for them here
	 */
	if (newflags & VM_WRITE) {
		/* Check space limits when area turns into data. */
		if (!may_expand_vm(mm, newflags, nrpages) &&
				may_expand_vm(mm, oldflags, nrpages))
			return -ENOMEM;
		if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_HUGETLB|
						VM_SHARED|VM_NORESERVE))) {
			charged = nrpages;
			if (security_vm_enough_memory_mm(mm, charged))
				return -ENOMEM;
			newflags |= VM_ACCOUNT;
		}
	}

	/*
	 * First try to merge with previous and/or next vma.
	 */
	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*pprev = vma_merge(mm, *pprev, start, end, newflags,
			   vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma),
			   vma->vm_userfaultfd_ctx);
	if (*pprev) {
		vma = *pprev;
		VM_WARN_ON((vma->vm_flags ^ newflags) & ~VM_SOFTDIRTY);
		goto success;
	}

	*pprev = vma;

	if (start != vma->vm_start) {
		error = split_vma(mm, vma, start, 1);
		if (error)
			goto fail;
	}

	if (end != vma->vm_end) {
		error = split_vma(mm, vma, end, 0);
		if (error)
			goto fail;
	}

success:
	/*
	 * vm_flags and vm_page_prot are protected by the mmap_sem
	 * held in write mode.
	 */
	vma->vm_flags = newflags;
	dirty_accountable = vma_wants_writenotify(vma, vma->vm_page_prot);
	vma_set_page_prot(vma);

	change_protection(vma, start, end, vma->vm_page_prot,
			  dirty_accountable, 0);

	/*
	 * Private VM_LOCKED VMA becoming writable: trigger COW to avoid major
	 * fault on access.
	 */
	if ((oldflags & (VM_WRITE | VM_SHARED | VM_LOCKED)) == VM_LOCKED &&
			(newflags & VM_WRITE)) {
		populate_vma_page_range(vma, start, end, NULL);
	}

	vm_stat_account(mm, oldflags, -nrpages);
	vm_stat_account(mm, newflags, nrpages);
	perf_event_mmap(vma);
	return 0;

fail:
	vm_unacct_memory(charged);
	return error;
}

/*
static int dup_mmap_mpk(struct mm_struct *mm, struct mm_struct *oldmm) {
  struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
  struct rb_node **rb_link, *rb_parent;
  int retval;
  unsigned long charge;
  LIST_HEAD(uf);

  uprobe_start_dup_mmap();
  if(down_write_killable(&oldmm->mmap_sem)) {
    retval = -EINTR;
    goto fail_uprobe_end;
  }
  flush_cache_dup_mm(oldmm);
  uprobe_dup_mmap(oldmm, mm);

  down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);

  RCU_INIT_POINTER(mm->exe_file, get_mm_exe_file(oldmm));

  mm->total_vm = oldmm->total_vm;
  mm->data_vm = oldmm->data_vm;
  mm->exec_vm = oldmm->exec_vm;
  mm->stack_vm = oldmm->exec_vm;

  rb_link = &mm->mm_rb.rb_node;
  rb_parent = NULL;
  pprev = &mm->mmap;
  retval = ksm_fork(mm, oldmm);
  if(retval)
    goto out;
  retval = khugepaged_fork(mm, oldmm);
  if(retval)
    goto out;

  prev = NULL;
  for(mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
    struct file* file;
    if(mpnt->vm_flags & VM_DONTCOPY) {
      vm_stat_account(mm, mpnt->vm_flags, -vma_pages(mpnt));
      continue;
    }
    charge = 0;
    if(mpnt->vm_flags & VM_ACCOUNT) {
      unsigned long len = vma_pages(mpnt);

      if(security_vm_enough_memory_mm(oldmm, len))
        goto fail_nomem;
      charge = len;
    }
    tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
    if(!tmp)
      goto fail_nomem;
    *tmp = *mpnt;
    INIT_LIST_HEAD(&tmp->anon_vma_chain);
    retval = vma_dup_policy(mpnt, tmp);
    if(retval)
      goto fail_nomem_policy;
    tmp->vm_mm = mm;
    retval = dup_userfaultfd(tmp, &uf);
    if(retval)
      goto fail_nomem_anon_vma_fork;
    if(tmp->vm_flags & VM_WIPEONFORK) {
      tmp->anon_vma = NULL;
      if(anon_vma_prepare(tmp))
        goto fail_nomem_anon_vma_fork;
    } else if (anon_vma_fork(tmp, mpnt))
      goto fail_nomem_anon_vma_fork;
    tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
    tmp->vm_next = tmp->vm_prev = NULL;
    file = tmp->vm_file;
    if(file) {
      struct inode *inode = file_inode(file);
      struct address_space *mapping = file->f_mapping;

      get_file(file);
      if (tmp->vm_flags & VM_DENYWRITE)
    }
  }

out:
  up_write(&mm->mmap_sem);
  up_write(&oldmm->mmap_sem);
  dup_userfaultfd_complete(&uf);
fail_uprobe_end:
  uprobe_end_dup_mmap();
  return retval;
fail_nomem_anon_vma_fork:
  mpol_put(vma_policy(tmp));
fail_nomem_policy:
  kmem_cache_free(vm_area_cachep, tmp);
fail_nomem:
  retval = -ENOMEM;
  vm_unacct_memory(charge);
  goto out;
} */


/*#define allocate_mm() (kmem_cache_alloc(mm_cachep, GFP_KERNEL))

static struct mm_struct * dup_mm_mpk(struct mm_struct* oldmm) {
  struct mm_struct *mm = mm_copy(oldmm);
  //int err;

  clone_pgd_range(mm->pgd, oldmm->pgd, PTRS_PER_PGD);
  //err = dup_mmap_mpk(mm, oldmm);
  //if(err)
  //  goto fail_mm;
  
  //mm->hiwater_rss = get_mm_rss(mm);
  //mm->hiwater_vm = mm->total_vm;

  //if(mm->binfmt && !try_module_get(mm->binfmt->module))
  //  goto free_pt;
  return mm;

//free_pt:
//  mm->binfmt = NULL;
//  mmput(mm);

//fail_mm:
//  return NULL;
}

static int copy_pgd_mpk(int pkey) {
  int retval = -ENOMEM;
  pgd_node* current_pgd, *ptr_pgd, *pgd_start;
  pgd_start = current->mm->pgd_start;

  if(pkey / 15 == 0) {
    pgd_start = kmalloc(sizeof(pgd_node), GFP_KERNEL);
    if(!pgd_start)
      goto fail;
    pgd_start->pgd = current->mm->pgd;
    pgd_start->next = NULL;
  }
  
  ptr_pgd = pgd_start;
  while(ptr_pgd->next != NULL)
    ptr_pgd = ptr_pgd->next;
 
  current_pgd = kmalloc(sizeof(pgd_node), GFP_KERNEL);
  if(!current_pgd)
    goto fail;
  current_pgd->pgd = _pgd_alloc();
  current_pgd->next = NULL;
  ptr_pgd->next = current_pgd;

  clone_pgd_range(current_pgd->pgd, pgd_start->pgd, PTRS_PER_PGD);

  //printk("current->pgd : %p", current->pgd);
  current->pgd = pgd_start->pgd;
  //printk("current->pgd : %p", current->pgd);

  return 0;

fail:
  return retval;
}
*/
/*
 * pkey==-1 when doing a legacy mprotect()
 */
static int do_mprotect_pkey(unsigned long start, size_t len,
		unsigned long prot, int pkey)
{
	unsigned long nstart, end, tmp, reqprot;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	const bool rier = (current->personality & READ_IMPLIES_EXEC) &&
				(prot & PROT_READ);

	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /* can't be both */
		return -EINVAL;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return 0;
	len = PAGE_ALIGN(len);
	end = start + len;
	if (end <= start)
		return -ENOMEM;
	if (!arch_validate_prot(prot))
		return -EINVAL;

	reqprot = prot;

	if (down_write_killable(&current->mm->mmap_sem))
		return -EINTR;

	/*
	 * If userspace did not allocate the pkey, do not let
	 * them use it here.
	 */
	error = -EINVAL;
  if (pkey == 0) {}
  else if ((pkey != -1) && !mm_pkey_is_allocated(current->mm, pkey))
		goto out;

  /*
  if (pkey > 0 && (pkey % 15) + 1 == 2) {
    mpk_ext = true;
  printk("current->pgd : %p", current->pgd);
    error = -ENOMEM;
    if(copy_pgd_mpk(pkey))
      goto out;
  printk("current->pgd : %p", current->pgd);
  } */


	vma = find_vma(current->mm, start);
	error = -ENOMEM;
	if (!vma)
		goto out;
	prev = vma->vm_prev;
	if (unlikely(grows & PROT_GROWSDOWN)) {
		if (vma->vm_start >= end)
			goto out;
		start = vma->vm_start;
		error = -EINVAL;
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto out;
	} else {
		if (vma->vm_start > start)
			goto out;
		if (unlikely(grows & PROT_GROWSUP)) {
			end = vma->vm_end;
			error = -EINVAL;
			if (!(vma->vm_flags & VM_GROWSUP))
				goto out;
		}
	}
	if (start > vma->vm_start)
		prev = vma;


	for (nstart = start ; ; ) {
		unsigned long mask_off_old_flags;
		unsigned long newflags;
		int new_vma_pkey;

		/* Here we know that vma->vm_start <= nstart < vma->vm_end. */

		/* Does the application expect PROT_READ to imply PROT_EXEC */
		if (rier && (vma->vm_flags & VM_MAYEXEC))
			prot |= PROT_EXEC;

		/*
		 * Each mprotect() call explicitly passes r/w/x permissions.
		 * If a permission is not passed to mprotect(), it must be
		 * cleared from the VMA.
		 */
		mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
					ARCH_VM_PKEY_FLAGS;

		new_vma_pkey = arch_override_mprotect_pkey(vma, prot, pkey);
		newflags = calc_vm_prot_bits(prot, new_vma_pkey);
		newflags |= (vma->vm_flags & ~mask_off_old_flags);

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
		if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			goto out;
		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			goto out;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			goto out;
		}
		prot = reqprot;
	}
out:
	up_write(&current->mm->mmap_sem);
	return error;
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	return do_mprotect_pkey(start, len, prot, -1);
}

#ifdef CONFIG_ARCH_HAS_PKEYS

SYSCALL_DEFINE4(pkey_mprotect, unsigned long, start, size_t, len,
		unsigned long, prot, int, pkey)
{
	return do_mprotect_pkey(start, len, prot, pkey);
}

SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
{
	int pkey;
	int ret;

	/* No flags supported yet. */
	if (flags)
		return -EINVAL;
	/* check for unsupported init values */
	if (init_val & ~PKEY_ACCESS_MASK)
		return -EINVAL;

	down_write(&current->mm->mmap_sem);
	pkey = mm_pkey_alloc(current->mm);

	ret = -ENOSPC;
	if (pkey == -1)
		goto out;

	ret = arch_set_user_pkey_access(current, pkey, init_val);
	if (ret) {
		mm_pkey_free(current->mm, pkey);
		goto out;
	}
	ret = pkey;
out:
	up_write(&current->mm->mmap_sem);
	return ret;
}

/*
Note on pkey_sync.


--> use tracehook..

** Unhandled corner case: 
  The current implementation may not handle the synchronization correctly if
  more than one threads initiates the synchronization at the same time. 
  A naive solution will be to introduce a lock...
**

1. Add tracehook to all threads
2. set notify resume
3. the hooks update pkru and remove themselves.

Overheads
- Space: one u32 field in task_struct to pass new pkru value. Better place would
be task_struct.thread.fpu
- Time:
1. No overhead when pkey_sync is not in progress because we are leveraging an
existing hook before return to user.
2. sys_pkey_sync latency (creating hooks) will depend on the number of hooks
(threads), but
  - 2 threads (1 hook) ~ 1us = 3k cycles
  - 11 threads (10 hooks) ~ 6us = 15k cycles
  - 101 threads (100 hooks) ~ 43us = 104k cycles
3. hook latency: this does not increase as the # hooks increases.
  - mostle hundreds of cycles 



*** Abandaned way ***


Implemented least invasive, but a slow way.

1. STOP all the other thread by sending SIGSTOP and kick_process
  - kick_process is required because we want to update pkru values in memory and
    let the threads restore the new value
2. update the pkru field in xstate region.
  - It seems that if fpu.last_cpu == cpu, switch_to may not restore xstate
  - We should manually update last_cpu into -1
    (arch/x86/include/asm/fpu/types.h)
3. send SIGCONT

+ If a thread is not running, the overhead should only come from (possibly)
  additional xstate restore.
+ If a thread is running, this causes unnecessary context switch.
+ Possible semantic issue: not waiting for the threads to stop yet, but expect
  that kick_process kinda does that for us.
+ Latency increases as the number of thread increases
  e.g. ~90us for 10 thread, ~1000us for 100 threads. (n^2?)


.. It seems non-trivial to reliably/efficiently wait until all thread stops.


 */

void update_pkey_hook(struct callback_head* work) {
  
  // unsigned long long clk_beg, clk_end;
  struct pkru_state* xsave_pkru;

  //  printk(KERN_INFO "update_pkey_hook called by pid(%d), tgid(%d)\n",
  //	 current->pid, current->tgid);
  
  //clk_beg = rdtsc();
  
  xsave_pkru = (struct pkru_state*)get_xsave_addr(&current->thread.fpu.state.xsave,
						  XFEATURE_MASK_PKRU);
  if(xsave_pkru == NULL){
    printk(KERN_INFO "failed to get xsave_pkru @ %s:%d\n",__FUNCTION__,__LINE__); 
    return;
  }
  if(current->new_pkru != xsave_pkru->pkru) {
    //printk(KERN_INFO "found a mismatch, %08x, %08x\n",current->new_pkru, xsave_pkru->pkru);
  }
  
  write_pkru(current->new_pkru);
  xsave_pkru->pkru = current->new_pkru;


  //printk(KERN_INFO "new pkru: %08x\n",read_pkru());
  //  printk(KERN_INFO "update_pkey_hook latency: %llu0(ns)\n",
  //  div_u64((clk_end - clk_beg),24LLU));
//printk(KERN_INFO "update_pkey_hook latency: %llu(cycles)\n", div_u64((clk_end - clk_beg),1LLU));
}


/*
Stolen from kernel/sched/core.c
 */
void pkey_sync_dummy(void* info) {
  return;
}

void kick_process_wait(struct task_struct *p)
{
	int cpu;

	preempt_disable();
	cpu = task_cpu(p);
	if ((cpu != smp_processor_id()) && task_curr(p)) {
	  //	  		smp_send_reschedule(cpu);
	  smp_call_function_many(cpumask_of(cpu),pkey_sync_dummy, NULL, true);
	}
	
	preempt_enable();
}



int do_pkey_sync(unsigned int val_pkru) {
  /* x86_64 with mpk only */
  
  int cpu;
  cpumask_t cpumask;  
  struct task_struct* p;
  uint64_t clk_beg, clk_end, tw_beg, tw_end, wait_beg, wait_end;
  struct callback_head* work;
  //  char* bytemap_cpus;


  cpu = get_cpu();
  //      clk_beg = rdtsc();
  //printk(KERN_INFO "sync called from pid(%d), tgid(%d)\n",current->pid,current->tgid);

  
  /*
  for_each_thread(current,p){
    if(p == current) continue;
    //Do I need this?
    xsave_pkru = (struct pkru_state*)get_xsave_addr(&p->thread.fpu.state.xsave,
						    XFEATURE_MASK_PKRU);
    if(xsave_pkru == NULL) {
      //printk(KERN_INFO "failed to get xsave_pkru @ %s:%d\n",__FUNCTION__,__LINE__);    
      return -1;
    }
    
    p->thread.fpu.last_cpu = -1;
    xsave_pkru->pkru = val_pkru;

    // the value the hook will fetch and use to update

  }
  */

      //      tw_beg = rdtsc();
  cpumask_clear(&cpumask);
  for_each_thread(current,p){

    p->new_pkru = val_pkru;
    work = &p->pkru_callback_head;
    task_work_cancel(p, update_pkey_hook);
    if(p == current) continue;
    init_task_work(work, update_pkey_hook);
    if(task_work_add(p,work,false) != 0){
      printk(KERN_INFO "failed to add task for thread(%d)\n",p->pid);
    }
#ifdef TIF_NOTIFY_RESUME
    test_and_set_tsk_thread_flag(p, TIF_NOTIFY_RESUME);
#else

#error Need TIF_NOTIFY_RESUME
      
#endif
    cpu = task_cpu(p);
    if ((cpu != smp_processor_id()) && task_curr(p)) {
      cpumask_or(&cpumask, &cpumask, cpumask_of(cpu));
    }
  }
  //tw_end = rdtsc();
  //	wait_beg = rdtsc();
  smp_call_function_many(&cpumask,pkey_sync_dummy, NULL, true);
  //wait_end = rdtsc();

  

  // XXX: hardcode for now..
  //bytemap_cpus = kmalloc(sizeof(char) * 255,GFP_ATOMIC);
  //for(i = 0; i < 255; i+=1) {
  //  bytemap_cpus[i] = 0;
  //}
  //for_each_thread(current,p){
    /* TODO: mimic kick_process impl to avoid calling reschedule more than once
     *  per core
     */
  //  if(bytemap_cpus[task_cpu(p)] == 0) {
  //    kick_process(p);
  //    bytemap_cpus[i] = 1;
  //  }
  //}
  
  /*
  mask = mm_cpumask(current->mm);
  printk(KERN_INFO "mask: %x\n",mask);
  for_each_cpu(cpu,mask) {
    printk(KERN_INFO "reschedule for cpu: %d\n",cpu);
    if(cpu != current->cpu)
      smp_send_reschedule(cpu);
  }
  */
  //clk_end = rdtsc();
  put_cpu();
  


  
  //printk(KERN_INFO "pkey_sync latency: %llu\n", (clk_end - clk_beg));
  //  printk(KERN_INFO "task_work latency: %llu\n", (tw_end - tw_beg));
  //    printk(KERN_INFO "wait latency: %llu\n", (wait_end - wait_beg));

  return 0;
}

SYSCALL_DEFINE1(pkey_sync, unsigned int, val_pkru)
{
	int ret;

	//printk("called pkey_sync with %u\n",val_pkru);
	ret = do_pkey_sync(val_pkru);

	return ret;
}

struct mprot
{
  unsigned long start;
  size_t len;
  unsigned long prot;
  int pkey;
};
SYSCALL_DEFINE2(pkey_evict, struct mprot __user*, m1, struct mprot __user*, m2)
{
  struct mprot m, m0;
  copy_from_user(&m, m1, sizeof(struct mprot));
//  printk("addr : %p, size : %d, prot : %ld, pkey : %d\n", m.start, m.len, m.prot, m.pkey);
  do_mprotect_pkey(m.start, m.len, m.prot, m.pkey);
  copy_from_user(&m0, m2, sizeof(struct mprot));
//  printk("addr : %p, size : %d, prot : %ld, pkey : %d\n", m0.start, m0.len, m0.prot, m0.pkey);
  do_mprotect_pkey(m0.start, m0.len, m0.prot, m0.pkey);
  return 0;
}


#endif /* CONFIG_ARCH_HAS_PKEYS */
