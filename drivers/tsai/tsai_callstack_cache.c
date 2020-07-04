/*
 * tsai_callstack_cache.c
 *
 *  Created on: 13 Jul 2018
 *      Author: cheng.tsai
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <asm/processor.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/version.h>


#include "tsai_callstack_cache.h"
#include "tsai_spy_user.h"
#include "tsai_macro.h"

struct ts_rb_node* ts_rb_find(struct rb_root* root, unsigned int key) {
	struct ts_rb_node* ret = 0;
	struct ts_rb_node* n = (struct ts_rb_node*)root->rb_node;
	while(n) {
		if (key > n->key)
			n = (struct ts_rb_node*)n->n.rb_right;
		else if (key < n->key)
			n = (struct ts_rb_node*)n->n.rb_left;
		else {
			ret = n;
			break;
		}
	}
	return ret;
}

void ts_rb_insert(struct rb_root* root, struct ts_rb_node* n) {
	struct rb_node **pnew = &root->rb_node;
	struct ts_rb_node* parent = NULL;
	while (*pnew) {
		parent = (struct ts_rb_node*)*pnew;
		if (n->key < parent->key)
			pnew = &parent->n.rb_left;
		else
			pnew = &parent->n.rb_right;
	}
	rb_link_node(&n->n, &parent->n, pnew);
	rb_insert_color(&n->n, root); /* insert is already done, change color, or rotate if necessary */
}

/* remove n from the RB tree root, but caller still need to kfree(n) */
void ts_rb_remove(struct rb_root* root, struct ts_rb_node* n) {
	rb_erase(&n->n, root);
}


void ts_callstack_binary_cache_init(struct ts_callstack_binary_cache* bc) {
	bc->root_bin.rb_node = 0;
}

unsigned int ts_binary_hash_from_fullpath(const char* fullpath) {
	int i;
	struct {
		union {
		unsigned int value;
		unsigned char c[4];
		};
	} hash;

	hash.value = 0;
	for (i=0; fullpath[i]; i++) {
		int idx = (i & 0x3);
		hash.c[idx] = (hash.c[idx] + fullpath[i]);
	}
	return hash.value;
}

unsigned int ts_binary_hash(struct file* filp) {
	char* p;
	char full_path[256];
	p = d_path(&(filp->f_path), full_path, sizeof(full_path) );
	return ts_binary_hash_from_fullpath(p);
}

struct ts_binary_node* ts_binary_node_get(struct ts_callstack_binary_cache* bincache, struct file* filp) {
	struct ts_rb_node* n;
	unsigned int hash = ts_binary_hash(filp);
	n = ts_rb_find(&bincache->root_bin, hash);
	if (!n) {
		struct ts_binary_node* tn;
		tn = kzalloc(sizeof(struct ts_binary_node), GFP_KERNEL|GFP_ATOMIC);
		tn->rb.key = hash;
		strncpy(tn->filename, filp->f_path.dentry->d_name.name, 32);

		ts_rb_insert(&bincache->root_bin, &(tn->rb));
		n = &tn->rb;
	}
	return (struct ts_binary_node*)n;
}

#include <linux/elf.h>
#include <linux/vmalloc.h>

void ts_binary_node_elf_free(struct ts_binary_node* bn) {
	if (bn->pelf) {
		if (bn->pelf->section_str_ptr_array) {
			kfree(bn->pelf->section_str_ptr_array);
			bn->pelf->section_str_ptr_array = 0;
		}
		if (bn->pelf->section_string_table) {
			kfree(bn->pelf->section_string_table); bn->pelf->section_string_table = 0;
		}
		if (bn->pelf->symbol_table_sorted) {
			vfree(bn->pelf->symbol_table_sorted);
			bn->pelf->symbol_table_sorted = 0;
		}
		if (bn->pelf->symbol_string_table) {
			vfree(bn->pelf->symbol_string_table);
			bn->pelf->symbol_string_table = 0;
		}
		if (bn->pelf->symbol_table) {
			vfree(bn->pelf->symbol_table);
			bn->pelf->symbol_table = 0;
		}
		kfree(bn->pelf);
		bn->pelf = 0;
	}
}

/* remove bn from RB tree and kfree bn, caller need to erase the pointer */
void ts_binary_node_remove(struct ts_callstack_binary_cache* bincache, struct ts_binary_node* bn) {
	ts_rb_remove(&bincache->root_bin, &(bn->rb));

	/* clean the allocated memory */
	ts_binary_node_elf_free(bn);

	/* free all the de-mangle information */
	if (bn->demangled_symbol_string) {
		vfree(bn->demangled_symbol_string);
		bn->demangled_symbol_string = 0;
		bn->demangled_alloc_size = 0;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
	{
		struct ts_rb_node* node;
		struct ts_rb_node* n;
		struct rb_root* root;
		struct ts_demangle_entry* tde;
		root = &bn->root_demangle;
		rbtree_postorder_for_each_entry_safe(node, n, root, n) {
			tde = container_of(node, struct ts_demangle_entry, rb);
			kfree(tde);
		}
	}
#else
		BKPT;
#endif

	kfree(bn);
}


static int tsai_cmp_symbol_info(const void *va, const void *vb)
{
	const Elf32_Sym *a = *(const Elf32_Sym **)va;
	const Elf32_Sym *b = *(const Elf32_Sym **)vb;
	return  (int)a->st_value - (int)b->st_value;
}

static void tsai_swap_symbol_info(void *va, void *vb, int size)
{
	u32* pa = (u32*)va;
	u32* pb = (u32*)vb;
	*pa ^= *pb;
	*pb ^= *pa;
	*pa ^= *pb;
}

#include <linux/sort.h>

int ts_binary_node_parse_elf(struct ts_binary_node* bn, struct file* filp) {
	Elf32_Ehdr*	pelf_hdr = 0;				/* ELF Header */
	Elf32_Phdr* pprg_hdr = 0;		/* Program Header */
	Elf32_Shdr* psec_hdr = 0;		/* Section Header */
	loff_t file_cursor;
	int size;
	unsigned int hash = ts_binary_hash(filp);
	int ret = 0;
	if (bn->rb.key != hash) {
		/* fatal bug */
		BKPT;
		BUG_ON(bn->rb.key != hash);
	}
	BUG_ON(bn->pelf);
	bn->pelf = kzalloc(sizeof(struct ts_elf_info), GFP_KERNEL|GFP_ATOMIC);


	/* elf header */
	pelf_hdr = kzalloc(sizeof(Elf32_Ehdr), GFP_KERNEL|GFP_ATOMIC);
	file_cursor = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
	__vfs_read(filp, (char*)pelf_hdr, sizeof(Elf32_Ehdr), &file_cursor);
#else
	BKPT;
#endif

	if (memcmp(pelf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		ret = -EINVAL;
		goto Leave;
	}


	/* program headers */
	pprg_hdr = kzalloc(sizeof(Elf32_Phdr) * pelf_hdr->e_phnum, GFP_KERNEL|GFP_ATOMIC );
	file_cursor = pelf_hdr->e_phoff;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
	__vfs_read(filp, (char*)pprg_hdr, sizeof(Elf32_Phdr) * pelf_hdr->e_phnum, &file_cursor);
#else
	BKPT;
#endif

	{
		Elf32_Phdr* pp;
		int idx;
		for (pp = pprg_hdr, idx=0; idx < pelf_hdr->e_phnum; idx++, pp++) {

			if (pp->p_type == PT_LOAD && (pp->p_flags & PF_X)==PF_X ) {
				bn->pelf->load_virtual_address = pp->p_vaddr;
			}
		}
	}

	/* section headers */
	bn->pelf->section_count = pelf_hdr->e_shnum;
	size = (sizeof(Elf32_Shdr)*pelf_hdr->e_shnum);
	psec_hdr = kzalloc(size, GFP_KERNEL|GFP_ATOMIC);
	file_cursor = pelf_hdr->e_shoff;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
	__vfs_read(filp, (char*)psec_hdr, size, &file_cursor);
#else
	BKPT;
#endif

	size = sizeof(const char*) * pelf_hdr->e_shnum;
	bn->pelf->section_str_ptr_array = (const char**)kzalloc(size, GFP_KERNEL|GFP_ATOMIC);

	/* walk through the sections */
	{
		Elf32_Shdr* ps;		/* Section Header */
		int idx;
		int idx_to_sym_str = 0; /* index to symbol string table section */
		for (ps = psec_hdr, idx=0; idx < pelf_hdr->e_shnum; idx++, ps++) {
			bn->pelf->section_str_ptr_array[idx] = (const char*)(NATIVE_UINT)ps->sh_name;
			if (idx == pelf_hdr->e_shstrndx) {
				/* section name string */
				size = ps->sh_size;
				bn->pelf->section_string_table = kmalloc(size, GFP_KERNEL|GFP_ATOMIC);
				file_cursor = ps->sh_offset;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
				__vfs_read(filp, (char*)bn->pelf->section_string_table, size, &file_cursor);
#endif
			}
			else if (ps->sh_type == SHT_SYMTAB) {
				/* symbol table section */
				size = ps->sh_size;
				bn->pelf->symbol_table = vmalloc(size);
				file_cursor = ps->sh_offset;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
				__vfs_read(filp, (char*)bn->pelf->symbol_table, size, &file_cursor);
#endif

				bn->pelf->symbol_count = ps->sh_size / ps->sh_entsize;
				idx_to_sym_str  = ps->sh_link;
			}
			else if ((idx == idx_to_sym_str) && idx_to_sym_str) {
				size = ps->sh_size;
				bn->pelf->symbol_string_table = vmalloc(size);
				file_cursor = ps->sh_offset;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
				__vfs_read(filp, (char*)bn->pelf->symbol_string_table, size, &file_cursor);
#endif
			}
		}

		if (bn->pelf->section_string_table) {
			for (idx = 0; idx < pelf_hdr->e_shnum; idx++ ) {
				int offset = (int)(NATIVE_UINT)bn->pelf->section_str_ptr_array[idx];
				bn->pelf->section_str_ptr_array[idx] = (const char*)bn->pelf->section_string_table + offset;
			}
		}
	}

	/* sort the symbols */
	size = sizeof(Elf32_Sym*) * bn->pelf->symbol_count;
	bn->pelf->symbol_table_sorted = vmalloc(size);
	if (bn->pelf->symbol_table_sorted)
	{
		Elf32_Sym** psort = (Elf32_Sym**)bn->pelf->symbol_table_sorted;
		Elf32_Sym* psym;
		int i;
		int accepted_cnt = 0;
		psym = (Elf32_Sym*)bn->pelf->symbol_table;
		for (i=0; i<bn->pelf->symbol_count; i++, psym++) {
			if (psym->st_shndx != SHN_UNDEF && (psym->st_shndx < SHN_LORESERVE) && ELF_ST_TYPE(psym->st_info) )
			{
				psort[accepted_cnt++] = psym;
			}
		}

		sort(psort, accepted_cnt, sizeof(Elf32_Sym*), tsai_cmp_symbol_info, tsai_swap_symbol_info );
		bn->pelf->symbol_sorted_count = accepted_cnt;
	}

Leave:
	if (ret != 0) {
		ts_binary_node_elf_free(bn);
	}

	if (psec_hdr) {
		kfree(psec_hdr); psec_hdr = 0;
	}
	if (pprg_hdr) {
		kfree(pprg_hdr); pprg_hdr = 0;
	}
	if (pelf_hdr) {
		kfree(pelf_hdr); pelf_hdr = 0;
	}

	return ret;
}

extern char *cplus_demangle(const char *mangled, int options);
#include <linux/vmalloc.h>

TSAI_STATIC const char* ts_binary_node_add_demangle(struct ts_binary_node* bn, const char* mangled, const char* demangled) {
	//const char* ret;
	struct ts_demangle_entry* n;
	int len;
	int max;
	int offset = 0;
	len = strlen(demangled);
Retry:
	max = bn->demangled_alloc_size - bn->demangled_symbol_string_write_cursor;

	if (!(max > (len+1)) ) {
		void* newbuf;
		bn->demangled_alloc_size = bn->demangled_alloc_size + 4096;
		newbuf = vmalloc(bn->demangled_alloc_size);

		if (bn->demangled_symbol_string) {
			memcpy(newbuf, bn->demangled_symbol_string, bn->demangled_symbol_string_write_cursor);
			vfree(bn->demangled_symbol_string);
		}
		bn->demangled_symbol_string = newbuf;
		goto Retry;
	}

	{
		char* dst = (char*)bn->demangled_symbol_string + bn->demangled_symbol_string_write_cursor;
		offset = bn->demangled_symbol_string_write_cursor;
		memcpy(dst, demangled, len);
		dst[len] = 0;
		bn->demangled_symbol_string_write_cursor += (len + 1);
	}

	n = kzalloc(sizeof(struct ts_demangle_entry), GFP_KERNEL|GFP_ATOMIC);
	n->rb.key = (unsigned int)(NATIVE_UINT)mangled;
	n->offset = offset;
	ts_rb_insert(&bn->root_demangle, &n->rb);

	return (const char*)bn->demangled_symbol_string + n->offset;
}

const char* ts_binary_node_find_demangle(struct ts_binary_node* bn, const char* mangled) {
	const char* ret = mangled;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		BKPT;
#elif	LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
		struct ts_rb_node* n;
		n = ts_rb_find(&bn->root_demangle, (unsigned int)(NATIVE_UINT)mangled);
		if (n) {
			struct ts_demangle_entry* dn = (struct ts_demangle_entry*)n;
			ret = (const char*)bn->demangled_symbol_string + dn->offset;
		}
		else {
			/* try to demangle it and then add an entry */
			char* demangled = cplus_demangle(mangled, 0);
			if (demangled)
				ret = ts_binary_node_add_demangle(bn, mangled, demangled);
			kfree(demangled);
		}
#else
		BKPT;
#endif
	return ret;
}


/* avoid IRQ happen within get_task_mm and spinlokc re-enter */
struct mm_struct *tsai_get_task_mm_no_irq(struct task_struct *task) {
	struct mm_struct* mm;
	unsigned long flags;
	local_irq_save(flags);
	mm = get_task_mm(task);
	local_irq_restore(flags);
	return mm;
}

#include <linux/mmu_context.h>
/* after this function, the saved mm(*out_mm) reference count remains the same, mm reference ++ */
void tsai_backup_mm(unsigned int* out_save_mm, struct mm_struct** out_mm, struct mm_struct* mm)  {
	/* TODO: use_mm need to get hold of task_lock, if it's on interrupt and re-entering, it would cause deadlock
	 * if current task has already locked task lock and this function is in interrupt context,
	 * then it should be re-entering case
	 * */
	struct task_struct* cur = current;
	if (cur->mm != mm ) {
		int in_int = in_interrupt();
		int task_locked;
		int reenter_lock = 0;

		task_locked = spin_is_locked(&cur->alloc_lock);
		if (task_locked) {
			if (in_int)
				reenter_lock = 1;
			else
				BKPT; /* I don't think this can happen, if it happens, investigate it */
		}

		if (reenter_lock) {
			spin_unlock(&cur->alloc_lock);
		}
#if 0
		if (cur->mm)
			BKPT;
#endif
		*out_mm = cur->mm;
		if (cur->mm)
			atomic_inc(&cur->mm->mm_count);
		use_mm(mm);
		*out_save_mm = 1;

		if (reenter_lock) {
			spin_lock(&cur->alloc_lock);
		}

	}
}

void tsai_restore_mm(unsigned int* out_save_mm, struct mm_struct** out_mm)  {
	struct task_struct* cur = current;
	if (*out_save_mm) {
		if (*out_mm) {
			use_mm(*out_mm);
			atomic_dec(&(*out_mm)->mm_count);
		}
		else {
			unuse_mm(cur->mm);
		}
	}
}

#ifdef __aarch64__
	//kernel/arch/arm64/include/asm/tlbflush.h
	#include "asm/tlbflush.h"
#endif

void tsai_force_load_user_address(struct mm_struct *tsk_mm, unsigned int addr) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* not implemented, handle_mm_fault has changed*/
#else
	int ret;
	int is_atomic;
	struct vm_area_struct* vma;
	vma = find_vma(tsk_mm, addr);
	is_atomic = preempt_count();
	if (!is_atomic)
		down_write(&tsk_mm->mmap_sem);

	flush_cache_range(vma, vma->vm_start, vma->vm_end); /* Invalidating all cache entries for vma range */
	ret = handle_mm_fault(tsk_mm, vma, addr & PAGE_MASK, FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE | FAULT_FLAG_USER);
	flush_tlb_range(vma, vma->vm_start, vma->vm_end); /* Ensuring MMU/TLB doesn't contain stale translation */

	if (!is_atomic)
		up_write(&tsk_mm->mmap_sem);
#endif
}

unsigned int tsai_force_read_user_address(struct mm_struct *tsk_mm, unsigned int addr) {
	long ret = 0;
	unsigned int insn = 0;
	do {
		ret = __copy_from_user(&insn, (void *)(NATIVE_UINT)addr, 4);
		if (ret) {
			tsai_force_load_user_address(tsk_mm, addr);
			ret = __copy_from_user(&insn, (void *)(NATIVE_UINT)addr, 4);
		}
	}while(0);

	if (ret) {
		BKPT;
	}

	return insn;
}

int tsai_force_read_user_address_size(struct mm_struct *tsk_mm, unsigned int addr, void* buf, int size) {
	long ret = 0;
	do {
		ret = __copy_from_user(buf, (void *)(NATIVE_UINT)addr, size);
		if (ret) {
			tsai_force_load_user_address(tsk_mm, addr);
			ret = __copy_from_user(buf, (void *)(NATIVE_UINT)addr, size);
		}
	}while(0);

	if (ret) {
		BKPT;
	}

	return ret;
}

/* during atomic operation, if user address is not accessible, data abort cannot happen and map the pages,
 * so we need to map it on our own
 * */
int tsai_force_write_user_address_size(struct mm_struct *tsk_mm, unsigned int addr, void* buf, int size) {
	long ret = 0;
	do {
		ret = __copy_to_user((void *)(NATIVE_UINT)addr, buf, size);
		if (ret) {
			tsai_force_load_user_address(tsk_mm, addr);
			ret = __copy_to_user((void *)(NATIVE_UINT)addr, buf, size);
		}
	}while(0);

	if (ret) {
		BKPT;
	}

	return ret;
}


/* sometimes code that just executed seems to be swapped out, so the content is still in physical memory
 * but not accessible through virtual address space
 * in T32, in such cases, the page would be labelled 'aged', see example:
_____________logical|_physical_____________________________________|sec|_d_|_size____|_permissions__________________________|_glb|_shr|_pageflags_(remapped)___________|_ta
N:A22B0000--A22B0FFF|                         AN:8CBFA000--8CBFAFFF| ns| 01| 00001000|                          exec        | yes| no | aged                           | AN
N:A22B1000--A22B1FFF|                         AN:8CBF9000--8CBF9FFF| ns| 01| 00001000|                          exec        | yes| no | aged                           | AN

is_locked:[out], whether the spinlock is locked, if so, means it's interrupt on mm_fault handler
and should not enter mm_fault handler again (causing deadlock)

 * return: pte if it can be found in MMU
 * */
pte_t* tsai_address_is_on_mmu(struct mm_struct* mm, uint64_t address, unsigned int* is_locked) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* not implemented, error: invalid operands to binary && (have 'int' and 'pmd_t {aka struct <anonymous>}')
  if (!(pmd && *pmd) )
  */
	return NULL;
#else
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte = NULL;
	spinlock_t *ptl = NULL;

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		goto Leave;
	pmd = pmd_alloc(mm, pud, address);
	if (!(pmd && *pmd) )
		goto Leave;

	pte = pte_offset_map(pmd, address);
	if (pmd && pte) {
		ptl = pte_lockptr(mm, pmd);
	}

	if (is_locked) {
		if (pte && ptl ) {
			*is_locked = spin_is_locked(ptl);
		}
		else
			*is_locked = 0;
	}
Leave:
	return pte;
#endif
}

#if 0

/* this used to be working on Kant-SU, but on Muse-M different MMU configuration so doesn't work */
pte_t* tsai_address_not_accessible_but_on_mmu_KantSU(struct mm_struct* mm, unsigned int address, unsigned int* is_locked) {
	pgd_t *pgd;
	pte_t *pte;
	spinlock_t *ptl = NULL;
	pgd = pgd_offset(mm, address);
	if (pgd[0][0]) {
		pte = pte_offset_map((pmd_t *)&pgd[0], address);
		ptl = pte_lockptr(mm, (pmd_t *)&pgd[0]);

	}
	else
		pte = 0;

	if (is_locked) {
		if (pte && ptl ) {
			*is_locked = spin_is_locked(ptl);
		}
		else
			*is_locked = 0;
	}
	return pte;
}

#endif

/* ============================================================================================================== */

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	#define DEBUG
#else
#endif

struct tsai_spy_mem_log;
extern int tsai_spy_log(const char* fmt, ...);
extern int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...);

extern unsigned int tsai_show_unwinding_log;

#if defined(DEBUG)
#define TSAI_UNWIND_LOG(fmt,...) 	if (tsai_show_unwinding_log) tsai_spy_log(fmt, __VA_ARGS__)
#else
#define TSAI_UNWIND_LOG(...)
#endif

#include <linux/highmem.h>

struct TSAI_MMU_PFN {
	unsigned int last_pfn;

	/* when a page is 'aged'?, it is not accessible through virtual address , cannot do memcpy directly
	 * but can be accessible through physical address, for that case, need to use ioremap to access physical address
	 * */
	struct page* remap_page;
	void* remap_paddr;
	void* remap_vaddr;
} tsai_mmu_pfn;
DEFINE_SPINLOCK(tsai_mmu_pfn_lock);

TSAI_STATIC void tsai_mmu_pfn_reset_nolock(void) {
#ifdef __aarch64__
	BKPT;
#else
	if (tsai_mmu_pfn.remap_vaddr) {
		kunmap_high(tsai_mmu_pfn.remap_page);
		tsai_mmu_pfn.remap_vaddr = 0;
		tsai_mmu_pfn.remap_paddr = 0;
		tsai_mmu_pfn.remap_page = 0;
	}
#endif
}

void tsai_mmu_pfn_reset(void) {
	/* TODO: kunmap cannot be in interrupt */
	unsigned long flags;
	spin_lock_irqsave(&tsai_mmu_pfn_lock, flags);

	tsai_mmu_pfn_reset_nolock();

	spin_unlock_irqrestore(&tsai_mmu_pfn_lock, flags);

}

#include <linux/swap.h>
#include <linux/swapops.h>

/* if a function is very big, some part of it may have not been PABORT and not in memory yet
 * whenever crossing page boundary, try it with cautious
 * return: 0 = OK
 * error otherwise
 * */
int tsai_get_user_data_caution(struct mm_struct* mm, unsigned int pc, long sz, void* pinsn)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* not implemented, error: invalid operands to binary && (have 'int' and 'pmd_t {aka struct <anonymous>}')
  if (!(pmd && *pmd) )
  */
	return 0;
#else

	int err;
	unsigned int pfn;
	int retry = 0;
	unsigned int is_locked;

	pfn = pc >> 12;
	if (pc >= mm->task_size) { /* not valid user space address */
		return -1;
	}
Retry:
	err = __copy_from_user(pinsn, (void*)(NATIVE_UINT)pc, sz);
	if (err && !retry) {
		pte_t* pte;
		retry++;
		pte = tsai_address_is_on_mmu(mm,pc, &is_locked);
		if (pte && *pte) {
			unsigned int paddr = (*pte & ~(0x1000-1));
			struct page* page;
			if (is_swap_pte(*pte)) {
				TSAI_UNWIND_LOG("MMU: vaddr %08x paddr %08x is a swap entry, need to read from file system @%d\n",
						pc, (unsigned int)paddr ,__LINE__);
				goto Leave;
			}
			page = 0;
			if (paddr)
				page = phys_to_page((unsigned int)paddr);

			if (is_locked) {
				TSAI_UNWIND_LOG("MMU: vaddr %08x spinlock is already locked, is it an interrupt on abort handler? @%d\n",
						pc,  __LINE__);
				goto Leave;

			}
			tsai_force_load_user_address(mm, pc);
			TSAI_UNWIND_LOG("MMU: vaddr %08x forced load on MMU @%d\n",
					pc,  __LINE__);
			goto Retry;
		}
		else {
			TSAI_UNWIND_LOG("MMU: vaddr %08x cannot be accessed with paddr, could be PABORT @%d\n",
										pc, __LINE__);
		}
	}
Leave:
	return err;
#endif
}

#if 0
int tsai_get_user_data_caution(struct mm_struct* mm, unsigned int pc, long sz, void* pinsn)
{
	int err;
	unsigned int pfn;
	unsigned long flags;

	pfn = pc >> 12;
	spin_lock_irqsave(&tsai_mmu_pfn_lock, flags);
Retry:
	if (pfn != tsai_mmu_pfn.last_pfn) {
		tsai_mmu_pfn_reset_nolock();
		err = __copy_from_user(pinsn, (void*)pc, sz);
		if (err) {
			pte_t* pte;
			pte = tsai_address_is_on_mmu(mm,pc);
			if (pte && *pte) {
				void* paddr = (void*)(*pte & ~(0x1000-1));
				struct page* page = 0;
				if (paddr)
					page = phys_to_page((unsigned int)paddr);
				//tsai_mmu_pfn.remap_page = pte_page(*pte);
				tsai_mmu_pfn.remap_page = page;
				if (tsai_mmu_pfn.remap_page) {
					tsai_mmu_pfn.remap_paddr = paddr;
					tsai_mmu_pfn.remap_vaddr = kmap(tsai_mmu_pfn.remap_page);
					tsai_mmu_pfn.last_pfn = pfn;
					TSAI_UNWIND_LOG("MMU: vaddr %08x cannot be accessed, use paddr %08x to access @%d\n",
							pc, tsai_mmu_pfn.remap_paddr, __LINE__);
					goto Retry;
				}
			}
			else {
				TSAI_UNWIND_LOG("MMU: vaddr %08x cannot be accessed with paddr, could be PABORT @%d\n",
											pc, __LINE__);
			}
		}
		else {
			tsai_mmu_pfn.last_pfn = pfn;
		}
	}
	else {
		if (tsai_mmu_pfn.remap_vaddr) {
			unsigned int offset = pc & (0x1000-1);
			memcpy(pinsn, tsai_mmu_pfn.remap_vaddr+offset, sz);
		}
		else {
			err = __copy_from_user(pinsn, (void*)pc, sz);
			if (err && !tsai_mmu_pfn.remap_vaddr) {
				tsai_mmu_pfn.last_pfn = 0;
				goto Retry;
			}
		}
		err = 0;
	}
	spin_unlock_irqrestore(&tsai_mmu_pfn_lock, flags);
	return err;
}
#endif

#include <../kernel/sched/sched.h>

/* return:
 * 1: RQ is locked for this cpu core
 * 0: RQ is not locked
 * */
int tsai_rq_is_locked(void) {
	int locked;
	int cpu = smp_processor_id();
	struct rq *rq;
	rq = cpu_rq(cpu);
	locked = raw_spin_is_locked(&rq->lock);
	return locked;
}

/*
 * For Linux 4, task_rq_lock is
 * static inline struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
 * linux-4.1.10/kernel/sched/sched.h
 *
 * For Linux 3,
 * static struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
 * kernel/kernel/sched/core.c
 *
 */
void* tsai_task_rq_lock(struct task_struct *p, unsigned long *flags) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* not implemented, error: passing argument 3 of 'task_rq_unlock' from incompatible pointer type [-Werror=incompatible-pointer-types]
  task_rq_unlock((struct rq*)rq, p, flags);
  */
	return NULL;
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct rq* rq;
	rq = task_rq_lock(p, flags);
	return (void*)rq;
#else
	return 0;
#endif
}

void tsai_task_rq_unlock(void* rq, struct task_struct *p, unsigned long *flags) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* not implemented, error: passing argument 2 of 'task_rq_lock' from incompatible pointer type [-Werror=incompatible-pointer-types]
  rq = task_rq_lock(p, flags);
  */
	return ;
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	task_rq_unlock((struct rq*)rq, p, flags);
#else
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 18, 0)
/* Linux 4.1
static inline int task_on_rq_queued(struct task_struct *p)
linux-4.1.10/kernel/sched/sched.h
*/
#else
	/* Linux 3 doesn't define this function
	 * doesn't define TASK_ON_RQ_QUEUED, but simply hard code value 1 ;
	 * */
	static inline int task_on_rq_queued(struct task_struct *p) {
		return (p->on_rq == 1);
	}
#endif

/* return:
 * 0: OK and removed from rq if it was already on
 * -1: task already on cpu, *out_on_core will contain which core it is on
 * */
int tsai_task_prevent_run(struct task_struct* p, int skip_lock, atomic_t* success, int* out_state, int* out_on_rq, int* out_on_core) {
	int ret = 0;
	int queued;
	unsigned long flags;
	struct rq* rq;
	int on_core;
	int on_rq = 0;
	int state = 0;

	if (skip_lock) {
		local_irq_save(flags);
		rq= task_rq(p);
	}
	else {
		rq = tsai_task_rq_lock(p, &flags);
	}

	state = p->state;
	on_rq = p->on_rq;
	on_core = tsai_task_on_cpu(p);


	if (p->on_cpu) {
		ret = -1;
	}
	else {
		queued = task_on_rq_queued(p);
		if (queued) {
			*out_on_rq = p->on_rq;
			deactivate_task(rq, p, DEQUEUE_SLEEP);
			p->on_rq = 0;
			p->state = TASK_UNINTERRUPTIBLE;
			ret = 0;
		}
	}
	if (out_state)
		*out_state = state;
	if (out_on_rq)
		*out_on_rq = on_rq;
	if (on_core)
		*out_on_core = on_core;

	if (success)
		atomic_set(success, 1);


	if (skip_lock)
		local_irq_restore(flags);
	else
		tsai_task_rq_unlock(rq, p, &flags);

	return ret;
}

/* atomic_t* atmflag: [out]on_return, this atomic variable will be set to 0
 *
 * */
void tsai_task_restore_run(struct task_struct* p, int skip_lock, atomic_t* atmflag, int* p_state, int* p_on_rq ) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 1, 100)
	/* error: 'ENQUEUE_WAKING' undeclared (first use in this function) */
#else
	//int queued;
	unsigned long flags;
	struct rq* rq;
	if (skip_lock) {
		local_irq_save(flags);
		rq= task_rq(p);
	}
	else {
		rq = tsai_task_rq_lock(p, &flags);
	}

	if (*p_on_rq) {
		activate_task(rq, p, ENQUEUE_WAKEUP | ENQUEUE_WAKING);
		p->on_rq = *p_on_rq;
		p->state = TASK_RUNNING; /* if a task is on_rq, then it has to be running */
	}

	if (atmflag) {
		atomic_set(atmflag, 0);
	}

	if (skip_lock)
		local_irq_restore(flags);
	else
		tsai_task_rq_unlock(rq, p, &flags);
#endif
}

int tsai_task_on_cpu(struct task_struct* p) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
	BKPT;
	return 0;
#else
	int ret = -1;
	if (p->on_cpu) {
		struct thread_info* ti = task_thread_info(p);
		ret = ti->cpu;
	}
	return ret;
#endif
}

const char* tsai_task_on_cpu_str(struct task_struct* p) {
	const char* core_str[] = { "N/A", "0", "1", "2", "3", "4", "5", "6", "7" };
	int core = tsai_task_on_cpu(p);
	return core_str[core+1];
}

