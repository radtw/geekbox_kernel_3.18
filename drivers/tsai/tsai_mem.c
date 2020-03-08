/*
 * tsai_mem.c
 *
 *  Created on: 31 Oct 2018
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
#include <linux/mmu_context.h>

#include <linux/swap.h>
#include <linux/swapops.h>


#include "tsai_mem.h"
#include "tsai_spy_user.h"
#include "tsai_callstack_cache.h"

#define DBG 1

#if DBG
struct tsai_spy_mem_log* g_tsai_rss_log;
#endif

struct tsai_process_rss {
	struct file* file_output;
	struct tsai_spy_mem_log log;
	unsigned int virtual_address; /* begin of virtual address for this lib */
	struct ts_binary_node* bn;
};

struct tsai_process_rss_walk {
	struct tsai_process_rss* rs;
	int swap_size;
	int total_size;
};

#include <linux/elf.h>

const char* elf_type_string[] = {
	"STT_NOTYPE",
	"STT_OBJECT",
	"STT_FUNC",
	"STT_SECTION",
	"STT_FILE",
	"STT_COMMON",
	"STT_TLS"
};

const char* elf_bind_string[] = {
"STB_LOCAL",
"STB_GLOBAL",
"STB_WEAK"
};


/* */
static void tsai_mem_print_symbol(struct tsai_process_rss_walk *rw, unsigned long addr, unsigned long addr_end) {
	const Elf32_Sym** psort = (const Elf32_Sym**) rw->rs->bn->pelf->symbol_table_sorted;
	int sort_cnt = rw->rs->bn->pelf->symbol_sorted_count;
	const char* sym_string_table = (const char*)rw->rs->bn->pelf->symbol_string_table;
	int lo = 0;
	int hi = sort_cnt - 1;
	int mid;
	int idx;
	unsigned long lib_addr = rw->rs->virtual_address;
	unsigned long sym_addr = rw->rs->bn->pelf->load_virtual_address;
	unsigned long addr_adj = (addr - lib_addr) + sym_addr;
	unsigned long addr_end_adj = (addr_end - lib_addr) + sym_addr;

	for (;lo != mid; ) {
		const Elf32_Sym* plo = psort[lo];
		const Elf32_Sym* phi = psort[hi];
		const Elf32_Sym* pmid;

		mid = (lo + hi) / 2;
		pmid = psort[mid];

		if (pmid->st_value > addr_adj ) {
			hi = mid;
		}
		else if (pmid->st_value < addr_adj) {
			lo = mid;
		}
		else if (pmid->st_value == addr_adj) { /* note, there could be multiple symbols with same address, so treat it as high point*/
			hi = mid;
		}
	}
	idx = lo;
	for (;;idx++) {
		int st_info;
		unsigned long sym_addr_lib;
		const char* sym_string;
		const char* section_str;
		const char* elf_type;
		const char* elf_bind;
		const Elf32_Sym* psym = psort[idx];
		if (psym->st_value < addr_adj)
			continue;
		if (psym->st_value > addr_end_adj)
			break;

		sym_addr_lib = (psym->st_value - sym_addr) + lib_addr;
		sym_string = sym_string_table + psym->st_name;

		if (psym->st_shndx < rw->rs->bn->pelf->section_count)
			section_str = rw->rs->bn->pelf->section_str_ptr_array[psym->st_shndx];
		else
			section_str = "";

		elf_type = elf_type_string[ ELF_ST_TYPE(psym->st_info) ];
		elf_bind = elf_bind_string[ ELF_ST_BIND(psym->st_info) ];

		tsai_spy_mem_log(&rw->rs->log, "    %08x %08x %s %s %s %s\n",
				sym_addr_lib, psym->st_size, section_str, elf_type, elf_bind, sym_string);

	}

}

static void tsai_mem_flush_log(void* cb_data, void* ptr, int len) {
	struct tsai_process_rss* rs = (struct tsai_process_rss*)cb_data;
	if (rs->file_output) {
		__vfs_write(rs->file_output, ptr, len, &rs->file_output->f_pos);
	}
}

static void tsai_pte_entry(pte_t *pte, unsigned long addr,
		struct mm_walk *walk)
{
	struct tsai_process_rss_walk *rw = (struct tsai_process_rss_walk*)walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page = NULL;
	u64 phys = 0;

	if (pte_present(*pte)) {
		page = vm_normal_page(vma, addr, *pte);
		phys = page_to_phys(page);
		tsai_spy_mem_log(&rw->rs->log, "%08x--%08x (Phys:%08llx) offset (%08x)\n",
			addr, (addr+PAGE_SIZE-1), phys, (addr - rw->rs->virtual_address));
		rw->total_size += PAGE_SIZE;
	}
	else if (is_swap_pte(*pte)) {
		swp_entry_t swpent = pte_to_swp_entry(*pte);
		__asm("bkpt");

		if (!non_swap_entry(swpent)) {
			int mapcount;

			rw->swap_size += PAGE_SIZE;
#if 0
			mapcount = swp_swapcount(swpent);
			if (mapcount >= 2) {
				u64 pss_delta = (u64)PAGE_SIZE << PSS_SHIFT;

				do_div(pss_delta, mapcount);
				mss->swap_pss += pss_delta;
			} else {
				mss->swap_pss += (u64)PAGE_SIZE << PSS_SHIFT;
			}
#endif
		}
		else if (is_migration_entry(swpent)) {
			page = migration_entry_to_page(swpent);
			phys = page_to_phys(page);
		}
	}

	if (page) {
		/* go through the symbols and print*/
		tsai_mem_print_symbol(rw, addr, addr+PAGE_SIZE);
	}

#if 0
	if (!page)
		return;
	smaps_account(mss, page, PAGE_SIZE, pte_young(*pte), pte_dirty(*pte));
#endif
}

static int tsai_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
		    struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->vma;
	pte_t *pte;
	spinlock_t *ptl;
#if 0
	if (pmd_trans_huge_lock(pmd, vma, &ptl) == 1) {
		smaps_pmd_entry(pmd, addr, walk);
		spin_unlock(ptl);
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
#endif
	/*
	 * The mmap_sem held all the way back in m_start() is what
	 * keeps khugepaged out of here and from collapsing things
	 * in here.
	 */
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE)
		tsai_pte_entry(pte, addr, walk);
	pte_unmap_unlock(pte - 1, ptl);
	return 0;
}

static int tsai_print_process_rss_vma(struct tsai_process_rss* rs, struct vm_area_struct* vma) {
	struct tsai_process_rss_walk rw;
	struct mm_walk smaps_walk = {
		.pmd_entry =tsai_pte_range,
		.mm = vma->vm_mm,
		.private = &rw,
	};


	memset(&rw, 0, sizeof(rw));
	rw.rs = rs;
	rw.total_size = 0;
	rw.swap_size = 0;

	tsai_spy_mem_log(&rs->log, "VMA %08x--%08x %d KB\n", vma->vm_start, vma->vm_end, ((vma->vm_end - vma->vm_start) >> 10) );

	/* mmap_sem is held in m_start */
	walk_page_vma(vma, &smaps_walk);

	tsai_spy_mem_log(&rs->log, "RSS %d KB / Swap %d KB / Total %d KB\n", ((rw.total_size) >> 10), ((rw.swap_size) >> 10),
			((vma->vm_end - vma->vm_start) >> 10) );

	return 0;
}

/*
 * lib: which lib to print */
int tsai_print_process_rss(struct task_struct* p, const char* lib) {
	int ret = 0;
	struct tsai_process_rss* rs;
	rs = kzalloc(sizeof(struct tsai_process_rss), GFP_KERNEL);
	if (!rs) {
		ret = -ENOMEM;
		goto Leave;
	}

	/* open a trace binary file */
	{
		char tmp_filename[256] = {0} ;
		sprintf(tmp_filename, "/tmp/rsspage_%d.txt", p->pid);
		rs->file_output = filp_open(tmp_filename, O_RDWR|O_CREAT|O_TRUNC|O_LARGEFILE, S_IRWXU|S_IRWXG|S_IRWXO);
		if (IS_ERR(rs->file_output )) {
			ret = (int)rs->file_output;
			rs->file_output = 0;
		}
	}
	if (rs->file_output) {
		struct ts_callstack_binary_cache* bc;
		struct vm_area_struct* gate_vma;
		struct vm_area_struct* vma;
		struct mm_struct* saved_mm;
		int save_mm = 0;

		bc = tsai_spy_get_bincache();

		tsai_backup_mm(&save_mm, &saved_mm, p->mm);

		tsai_spy_mem_log_init(&rs->log, "RSS", 512*1024, tsai_mem_flush_log, rs);
		rs->log.opt_no_header = 1;
#if DBG
		g_tsai_rss_log = &rs->log;
#endif

		gate_vma = get_gate_vma(p->mm);

		vma = p->mm->mmap;
		if (!vma)
			vma = gate_vma;

		while (vma) {
			struct file* file;
			file = vma->vm_file;

			if (file && strcmp(file->f_path.dentry->d_iname, lib)==0) {
				if ((vma->vm_flags & VM_EXEC) && rs->virtual_address==0) {
					rs->virtual_address = vma->vm_start;
					rs->bn = ts_binary_node_get(bc, file);
					ts_binary_node_parse_elf(rs->bn, file);
				}
				tsai_print_process_rss_vma(rs, vma);
			}

			if (vma->vm_next)
				vma = vma->vm_next;
			else if (vma == gate_vma)
				vma = NULL;
			else
				vma = gate_vma;
		}


		if (rs->bn) {
			ts_binary_node_remove(bc, rs->bn);
			rs->bn = 0;
		}

		tsai_restore_mm(&save_mm, &saved_mm);

		tsai_spy_mem_log_flush(&rs->log, 1);
		filp_close(rs->file_output, (fl_owner_t)current->pid);
		rs->file_output = 0;
#if DBG
		g_tsai_rss_log = 0;
#endif
	}

	kfree(rs);
Leave:
	return ret;
}
