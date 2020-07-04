/*
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

#include "tsai_callstack_arm.h"
#include "tsai_callstack_cache.h"

/* Note, current config linux kernel only has 2 pages (8192) bytes stack
 *
 * */
#define DEBUG
#include "tsai_macro.h"

struct tsai_spy_mem_log;
extern int tsai_spy_log(const char* fmt, ...);
extern int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...);

static unsigned int tsai_bkpt_disasm = 0;
unsigned int tsai_show_unwinding_log = 1;

extern struct tsai_spy_mem_log* tsai_unwind_log;

#if defined(DEBUG)
#define TSAI_UNWIND_LOG(fmt,...) 	if (tsai_show_unwinding_log) tsai_spy_log(fmt, __VA_ARGS__)
#else
#define TSAI_UNWIND_LOG(...)
#endif


static const char* STR_ANDEQ = "andeq";
static const char* STR_ADD = "add";
static const char* STR_ADR = "adr";
static const char* STR_B = "b";
static const char* STR_BLX = "blx";
static const char* STR_BL = "bl";
static const char* STR_BX = "bx";
static const char* STR_CBZ = "cbz";
static const char* STR_CBNZ = "cbnz";

static const char* STR_DCD = "dcd";
static const char* STR_NOP = "nop";
static const char* STR_POP = "pop";
static const char* STR_LDR = "ldr";
static const char* STR_LDRB = "ldrb";
static const char* STR_LDRD = "ldrd";
static const char* STR_LDREX = "ldrex";

static const char* STR_PUSH = "push";
static const char* STR_STR = "str";
static const char* STR_STRB = "strb";
static const char* STR_STRD = "strd";
static const char* STR_STREX = "strex";
static const char* STR_SUB = "sub";

static const char* STR_VADDL = "vaddl";
static const char* STR_VSUBL = "vsubl";


static const char STR_EQ[] = "eq";
static const char STR_NE[] = "ne";
static const char STR_CS[] = "cs";
static const char STR_CC[] = "cc";
static const char STR_MI[] = "mi";
static const char STR_PL[] = "pl";
static const char STR_VS[] = "vs";
static const char STR_VC[] = "vc";
static const char STR_HI[] = "hi";
static const char STR_LS[] = "ls";
static const char STR_GE[] = "ge";
static const char STR_LT[] = "lt";
static const char STR_GT[] = "gt";
static const char STR_LE[] = "le";
static const char STR_AL[] = "";
static const char STR_UNCOND[] = "UNCONDITIONAL";

int tsai_cpu_core_id(void) {
	unsigned int MPIDR;
	asm volatile("mrc p15, 0, %0, c0, c0, 5" : "=r" (MPIDR));
	/* MRC p15, 0, <Rt>, c0, c0, 5; Read Multiprocessor Affinity Register */
	return (MPIDR & 3);
}

/* this function cannot dealt with mounted file, eg /mnt/nfs/....  use d_path() instead */
static char* tsai_get_full_path(const struct path *path, char *buf, int buflen, char** out_file)
{
	char* fullpath;
	char* filename;
	struct dentry* d = path->dentry;
	int len = buflen;

	buf[len-1] = 0;
	len--;
	for (;d->d_parent != d; d=d->d_parent) {
		int offset = (len) - d->d_name.len;
		memcpy(&buf[offset], d->d_name.name, d->d_name.len);

		if (d==path->dentry) {
			filename = &buf[offset];
		}

		len -= d->d_name.len;

		buf[len-1] = '/';
		len--;
	}

	fullpath=&buf[len];
	if (out_file) {
		*out_file = filename;
	}
	return fullpath;
}

struct TSAI_FAKE_STACK {
	unsigned int bytes_used;
	char buf[8192-8];
};

struct TSAI_FAKE_STACK_TICKET {
	unsigned int byte_offset;
	unsigned int size;
};

struct TSAI_FAKE_STACK tsai_fake_stack[4];

void* tsai_fake_stack_get(unsigned int size, struct TSAI_FAKE_STACK_TICKET* ticket) {
	int cpu = tsai_cpu_core_id();
	void* ret = 0;
	struct TSAI_FAKE_STACK* ps = &tsai_fake_stack[cpu];
	int remain = (char*)(ps + 1) - &ps->buf[ps->bytes_used];
	ticket->byte_offset = ps->bytes_used;
	ticket->size = size;
#if defined(DEBUG)
	if (ps->bytes_used >= 8192) {
		__asm("bkpt");
	}
#endif
	if (size <= remain) {
		ret = &ps->buf[ps->bytes_used];
		ps->bytes_used += size;
#if defined(DEBUG)
		if (ps->bytes_used >= 8192) {
			__asm("bkpt");
		}
#endif
	}
	else {
		__asm("bkpt");
	}
	return ret;
}

void tsai_fake_stack_put(unsigned int size, struct TSAI_FAKE_STACK_TICKET* ticket) {
	int cpu = tsai_cpu_core_id();
	struct TSAI_FAKE_STACK* ps = &tsai_fake_stack[cpu];

	if (ticket->size != size) {
		__asm("bkpt");
	}
	ps->bytes_used -= size;

	if (ticket->byte_offset != ps->bytes_used) {
		__asm("bkpt");
	}

#if defined(DEBUG)
	if (ps->bytes_used >= 8192) {
		__asm("bkpt");
	}
#endif
}

static void* tsai_callstack_load_symbol_file(const char* fname, int do_not_open);
static unsigned int tsai_lookup_symbol(void* symbol_key, unsigned int addr, unsigned int vma_start, const char** out_symbol_string, unsigned int* out_start_len);

struct kdbg_elf_usb_elf_list_item;

struct TSAI_VMA_WRAPPER {
	struct rb_node rb; /* has to be first one */
	unsigned long vm_start;
	unsigned long vm_end;
	struct vm_area_struct* vma; /* */

	union {
		void* symbol_key; /* to be used in kdebugd symbol system */
		struct kdbg_elf_usb_elf_list_item* symbol_key_debug;
	};

	struct ts_binary_node* binnode;

	unsigned int vaddr; /* vaddr recorded in program header */
	void* arm_exidx;
	int arm_exidx_offset;
	int arm_exidx_size;
	void* plt; /* pointer to plt (user mode) address*/
	void* arm_extab;
	int arm_extab_size;

	unsigned int f_non_elf:1; /* flag: it's not ELF, cannot parse the header */
};


static void tsai_insert_vma_wrapper(struct TSAI_VMA_MGR* mgr, struct TSAI_VMA_WRAPPER* n) {
	struct rb_node **pnew = &mgr->root.rb_node;
	struct TSAI_VMA_WRAPPER* parent = NULL;
	unsigned long irqflags;
	u32 key = n->vm_start;

	spin_lock_irqsave(&mgr->lock, irqflags);
	while (*pnew) {
		parent = (struct TSAI_VMA_WRAPPER*)*pnew;
		if (key < parent->vm_start)
			pnew = &parent->rb.rb_left;
		else
			pnew = &parent->rb.rb_right;
	}
	rb_link_node(&n->rb, &parent->rb, pnew);
	//print_tree(root->rb_node, 0);
	rb_insert_color(&n->rb, &mgr->root); /* insert is already done, change color, or rotate if necessary */
	//print_tree(root->rb_node, 0);
	spin_unlock_irqrestore(&mgr->lock, irqflags);

}

static void tsai_remove_vma_wrapper(struct TSAI_VMA_MGR* mgr, struct TSAI_VMA_WRAPPER* n) {
	unsigned long irqflags;
	spin_lock_irqsave(&mgr->lock, irqflags);
	rb_erase(&n->rb, &mgr->root);
	spin_unlock_irqrestore(&mgr->lock, irqflags);
}

/* path_buf:[in] for temporary storage, must not be NULL*/
static struct TSAI_VMA_WRAPPER* tsai_find_vma_wrapper_by_addr(struct TSAI_VMA_MGR* mgr, unsigned int addr, struct mm_struct *tsk_mm, char* path_buf)
{
	struct TSAI_VMA_WRAPPER* ret = 0;
	struct TSAI_VMA_WRAPPER* n = (struct TSAI_VMA_WRAPPER*)mgr->root.rb_node;
	unsigned long irqflags;

	spin_lock_irqsave(&mgr->lock, irqflags);
	while (n) {
		u32 key = n->vm_start;

		if (addr >= key) {
			if (addr > n->vm_end) {
				n = (struct TSAI_VMA_WRAPPER*)n->rb.rb_right;
			}
			else {
				ret = n;
				break;
			}
		}
		else if (addr < key) {
			n = (struct TSAI_VMA_WRAPPER*)n->rb.rb_left;
		}
	}
	spin_unlock_irqrestore(&mgr->lock, irqflags);

	if (ret) {
		/* still need to check whether it is still valid or things have changed?? */
		if (ret->vma->vm_start == ret->vm_start)
		{
			if (ret->vma->vm_end == ret->vm_end) {
				;
			}
			else {
				ret->vm_end = ret->vma->vm_end;
			}
		}
		else {
			/* remove this node as it is no longer valid! */
			tsai_remove_vma_wrapper(mgr, ret);
			kfree(ret);
			ret = 0;
		}
	}

	if (!ret)
	{ /* create a new one */
		struct vm_area_struct* vma;
		char* p;

		vma = find_vma(tsk_mm, addr);
		if (vma) {
			if (!(vma->vm_file && (vma->vm_flags & (VM_READ|VM_EXEC))==(VM_READ|VM_EXEC) )) {
				goto Leave;
			}

			ret = kzalloc(sizeof(struct TSAI_VMA_WRAPPER), GFP_KERNEL );
			if (!ret) {
				__asm("bkpt");
			}

			ret->vm_start = vma->vm_start;
			ret->vm_end = vma->vm_end;
			ret->vma = vma;
			if (vma->vm_file) {
				p = tsai_get_full_path(&(vma->vm_file->f_path),path_buf, 256, NULL );
				ret->symbol_key = tsai_callstack_load_symbol_file(p, 1);
			}
			else {
				ret->symbol_key = 0;
			}
			tsai_insert_vma_wrapper(mgr, ret);

			tsai_vma_walk_section_header(ret);

			if (!ret->symbol_key) {
				//TODO: add a deferred work to load symbol for futurn use!
			}
		}
	}
Leave:
	return ret;
}

static const char* tsai_get_vma_filename(struct TSAI_VMA_WRAPPER* vw)
{
	const char* filename = 0;
	struct dentry* d = 0;

	if (vw->vma && vw->vm_start==vw->vma->vm_start) {
		if (vw->vma->vm_file) {
			d = vw->vma->vm_file->f_path.dentry;
			filename = (const char*)d->d_name.name;
		}
	}
	return filename;
}

extern struct ts_callstack_binary_cache* tsai_spy_get_bincache(void);

static struct ts_binary_node* tsai_vw_get_binnode(struct TSAI_VMA_WRAPPER* vw) {
	if (!vw->binnode) {
		struct ts_callstack_binary_cache* bc = tsai_spy_get_bincache();
		vw->binnode = ts_binary_node_get(bc, vw->vma->vm_file);
	}
	return vw->binnode;
}

#define KUBT_TRACE_HEADER	"FP:0x%08x, PC:0x%08x, RA:0x%08x,"\
				"SP:0x%08x, Stack end:0x%08x\n"
#define __SUBMASK(x)	((1L << ((x) + 1)) - 1)
#define KUBT_FLAG_FUNC_EPILOGUE	(1 << 2)
#define __BIT(obj, st)	(((obj) >> (st)) & 1)
#define __BITS(obj, st, fn)	(((obj) >> (st)) & __SUBMASK((fn) - (st)))

#define __BIT_MASK_EQ(v, mask, value) ( ((v) & mask)== value  )

#define KDEBUGD_PRINT_ELF   "#%d  0x%08lx in %s () from %s\n"
#define KDEBUGD_PRINT_DWARF "#%d  0x%08lx in %s () at %s:%d\n"

struct kubt_kdbgd_sym {
	int is_valid;
	char *sym_name;
	char *lib_name;
	unsigned long start;
#ifdef CONFIG_DWARF_MODULE
	struct aop_df_info *pdf_info;
#endif
};

#define KDBG_ELF_SYM_NAME_LENGTH_MAX 	1024
#define KDBG_ELF_SYM_MAX_SO_LIB_PATH_LEN 128
#define AOP_DF_MAX_FILENAME   256


///////////////////////////////////////////////////////////////////////////////////

/* ARM Registers */
#define ARM_FP_REGNUM 11	/* current frame address */
#define ARM_SP_REGNUM 13	/* stack pointer */
#define ARM_LR_REGNUM 14	/* return address */
#define ARM_PC_REGNUM 15	/* program counter */

#define	INSN_ERR	((unsigned int)-1)

#define IS_THUMB_ADDR(a)	((a) & 1)
#define MAKE_THUMB_ADDR(a)	((a) | 1)
#define PC_NO_THUMB(x) ((x) & ~1)

#define OFFSET	128



/*
 there are some functions which will inject into another function's body, list known cases here
 eg. /usr/lib/ld-2.24.so
           NSR:01A1:4101B1E0|E3A0C000  __stpcpy:        mov     r12,#0x0         ; r12,#0
           NSR:01A1:4101B1E4|EA000002                   b       0x4101B1F4
           NSR:01A1:4101B1E8|E320F000                   nop
           NSR:01A1:4101B1EC|E320F000                   nop
           NSR:01A1:4101B1F0|E1A0C000  strcpy:          cpy     r12,r0
           NSR:01A1:4101B1F4|F5D0F000                   pld     [r0]
           NSR:01A1:4101B1F8|F5D1F000                   pld     [r1]

 * */
int tsai_known_redirection_functions(char* func_name) {
	if (strcmp(func_name, "strcpy")==0)
		return 1;
	if (strcmp(func_name, "tls_get_addr_tail")==0)
		return 1;
	if (strcmp(func_name, "read")==0)
		return 1;

	return 0;
}


static unsigned long kubt_thumb_expand_imm(unsigned int imm)
{
	unsigned long count = imm >> 7;

	if (count < 8) {
		switch (count / 2) {
		case 0:
			return imm & 0xff;
		case 1:
			return (imm & 0xff) | ((imm & 0xff) << 16);
		case 2:
			return ((imm & 0xff) << 8) | ((imm & 0xff) << 24);
		case 3:
			return (imm & 0xff) | ((imm & 0xff) << 8)
				| ((imm & 0xff) << 16) | ((imm & 0xff) << 24);
		default:
			printk(KERN_WARNING
					"Condition will never be reached\n");
		}
	}

	return (0x80 | (imm & 0x7f)) << (32 - count);
}

static unsigned int tsai_ARMExpandImm(unsigned int imm12) {
	unsigned int ret;
	unsigned int rot = __BITS(imm12, 8, 11);
	unsigned int value = __BITS(imm12, 0, 7);
	union {
		unsigned int v32[2];
		unsigned long long v64;
	} u;
	u.v32[0] = value;
	u.v32[1] = value;

	u.v64 >>= (rot*2);
	return u.v32[0];
}

static int tsai_compare_address_ignore_thumbbit(unsigned int ad1, unsigned int ad2) {
	return (ad1 & ~1)== (ad2 & ~1);
}

static unsigned long tsai_get_user(unsigned long pc, long sz)
{
	unsigned long insn = INSN_ERR;
	memcpy(&insn, (void*)pc, sz);
	return insn;
}

unsigned long tsai_callstack_copy_from_user_stack(unsigned long pc, long sz)
{
	mm_segment_t fs;
	unsigned int insn = 0;
	long ret = 0;

	if (!access_ok(VERIFY_READ, pc, sizeof(insn)))
		return 0;

	fs = get_fs();
	set_fs(KERNEL_DS);
	ret = __copy_from_user(&insn, (void *)pc, sz);
	set_fs(fs);

	if (unlikely(ret))
		return 0;
	return insn;

}

/* when expecting pre-fetch abort may have happened, use this funciton to tentatively try,
 * so if an address is not accessible, it will not get into kernel panic
 *  */
int tsai_callstack_copy_from_user_stack_caution(unsigned long pc, long sz, unsigned int* pinsn)
{
	mm_segment_t fs;
	unsigned int insn = 0;
	long ret = 0;

	/* access_ok is not useful here, it only check whether address is below 0xbe800000
	 * to determine whether it's likely to be user address*/
	if (!access_ok(VERIFY_READ, pc, sizeof(insn)))
		return 0;

	fs = get_fs();
	set_fs(KERNEL_DS);
	ret = __copy_from_user(&insn, (void *)pc, sz);
	set_fs(fs);

	if (pinsn)
		*pinsn = insn;

	return ret;

}



/* a simple wrapper to turn bad instruction into a harmless
 * NOOP (all zeros), so none of bitmask checks should pass.
 * e.g. for insn = (((unsigned int)-1) __BIT(insn, 8) check
 * will wrongly give a positive result.*/
static unsigned long kubt_get_insn(unsigned long pc, int sz)
{
	unsigned int insn = tsai_get_user(pc, sz);
	if (unlikely(insn == INSN_ERR))
		insn = 0;
	return insn;
}

static void kubt_print_symbol(struct kubt_kdbgd_sym *sym, unsigned long addr)
{
#if 0
	const char *sym_name = "??";
	const char *elf_name = "??";

	BUG_ON(!sym);

	if (sym->is_valid) {
		sym_name = sym->sym_name;
		elf_name = sym->lib_name;
	}
#ifdef CONFIG_DWARF_MODULE
	if (sym->is_valid && (sym->pdf_info->df_line_no != 0))
		pr_emerg(KDEBUGD_PRINT_DWARF, call_depth, addr,
				sym_name,
				sym->pdf_info->df_file_name,
				sym->pdf_info->df_line_no);
	else
#endif
		pr_emerg(KDEBUGD_PRINT_ELF, call_depth, addr,
				sym_name,
				elf_name);
	call_depth++;
#endif
}

static int tsai_check_termination_sym_name(const char *sym_name)
{
	/* this strcmp stuff, of course, works in some cases. alternatively we
	 * can check what function address in called from ELF entry point
	 * (_start()). the main problem here is that ELF can redefine main(),
	 * to, let's say for example, MyMainFunction(). this is for sure
	 * utterly stupid but still possible. */
	if (!strcmp(sym_name, "main") ||
			!strcmp(sym_name, "__thread_start") ||
			!strcmp(sym_name, "__cxa_finalize") ||
			!strcmp(sym_name, "__libc_start_main") ||
			!strcmp(sym_name, "start_thread") ||
			!strcmp(sym_name, "_dl_fini"))
		return 1;
	return 0;
}

/* ensure that targeted area (function `start + OFFSET') contains
 * supported prologue instructions. otherwise, we cannot jump over
 * and must continue decoding. */
static int kubt_scan_prologue(unsigned long pc, unsigned long limit)
{
	int thumb_mode = IS_THUMB_ADDR(pc);
	unsigned int insn, insn2;

	while (pc < limit) {
		if (thumb_mode)
			insn = tsai_get_user(pc - thumb_mode, 2);
		else
			insn = tsai_get_user(pc, 4);

		if (insn == INSN_ERR)
			return -EINVAL;

		if (thumb_mode) {
			/* push { rlist } */
			if ((insn & 0xfe00) == 0xb400) {
				int mask = (insn & 0xff) |
					((insn & 0x100) << 6);

				if (mask & (1 << ARM_LR_REGNUM))
					return 0;
			}
			/* sub sp, #imm */
			else if ((insn & 0xff80) == 0xb080) {
				return 0;

			/*** THUMB32 instructions ***/
			/* str Rt, {sp, +/-#imm}! */
			} else if ((insn & 0xffff) == 0xf8cd) {
				insn2 = kubt_get_insn(pc + 1, 2);
				if (__BIT(insn2, 10) && __BIT(insn2, 8))
					return 0;
				pc += 2;
			/* strd Rt, Rt2, [sp, #+/-imm]{!} */
			} else if ((insn & 0xfe5f) == 0xe84d) {
				insn2 = kubt_get_insn(pc + 1, 2);
				if (__BITS(insn2, 12, 15) == ARM_LR_REGNUM)
					return 0;
				if (__BITS(insn2, 8, 11) == ARM_LR_REGNUM)
					return 0;
				if (__BIT(insn, 5) && __BIT(insn, 8))
					return 0;
				pc += 2;
			/* str{bh}.w sp,[Rn,#+/-imm]{!} */
			} else if ((insn & 0xffdf) == 0xf88d) {
				insn2 = kubt_get_insn(pc + 1, 2);
				if (__BIT(insn2, 10) && __BIT(insn2, 8))
					return 0;
				pc += 2;
			/* stmdb sp!, { rlist } */
			} else if ((insn & 0xffff) == 0xe92d) {
				insn2 = kubt_get_insn(pc + 1, 2);
				if (insn2 & (1 << ARM_LR_REGNUM))
					return 0;
				pc += 2;
			/* sub.w sp, Rn, #imm */
			} else if ((insn & 0xfbff) == 0xf1ad) {
				return 0;
			}
		/* ARM instructions */
		/* sub sp,sp, size */
		} else if ((insn & 0xfffff000) == 0xe24dd000) {
			return 0;
		/*  stmfd sp! {rlist} */
		} else if ((insn & 0xffff0000) == 0xe92d0000) {
			int mask = insn & 0xffff;

			if (mask & (1 << ARM_LR_REGNUM))
				return 0;
		}

		pc += 2;
		if (!thumb_mode)
			pc += 2;
	}

	return 1;
}

/* EXIDX information */
enum EXIDX_CMD {
	ARM_EXIDX_CMD = 0,
	ARM_EXIDX_CMD_DATA_POP,
	ARM_EXIDX_CMD_DATA_PUSH,
	ARM_EXIDX_CMD_REFUSED,
	ARM_EXIDX_CMD_REG_POP,
	ARM_EXIDX_CMD_REG_TO_SP,
	ARM_EXIDX_CMD_FINISH,
	ARM_EXIDX_CMD_VFP_POP,
	ENDMARKER
};

static const char* STR_ARM_EXIDX_CMD[] = {
		"N/A",
		"ARM_EXIDX_CMD_DATA_POP",
		"ARM_EXIDX_CMD_DATA_PUSH",
		"ARM_EXIDX_CMD_REFUSED",
		"ARM_EXIDX_CMD_REG_POP",
		"ARM_EXIDX_CMD_REG_TO_SP",
		"ARM_EXIDX_CMD_FINISH",
		"ARM_EXIDX_CMD_VFP_POP"
};


struct TSAI_EXIDX_INS {
	enum EXIDX_CMD mnemonic;
	union {
		int vsp_offset;
		unsigned int reg_list;
		unsigned int reg_num;
	};
};

struct TSAI_EXIDX_UNWIND {
	unsigned int function_entry_point; /* the address of function entry point */
	int count;
	struct TSAI_EXIDX_INS inst[32];
};



struct tsai_instruction_cache_mgr;


struct tsai_instruction_cache {
	struct tsai_instruction_cache_mgr* pm;
	unsigned int PC; /* PC for this instruction */
	unsigned int SP; /* SP that was meant before execution of this instruction */
	unsigned int hex_code;
	unsigned int armthumb;
	const char* mnemonic; /* excluding condition code*/
	const char* condmnemonic;
	union {

		struct { /* if this is a data instruction */
			unsigned int data_bytes;
		};

		struct {
			union {
				unsigned int link_address; /* jump to address for example */
				unsigned int link_reglist; /* reg list */
				unsigned int link_imm; /* add, sub, etc*/
			};
			unsigned short link_reg; /* the register number associate, target rd */
			unsigned short link_reg2; /* eg. LDRD Thumb encoding has rt1 and rt2 */
			unsigned int link_reg_src; /* usually rn */
			unsigned int wb : 1; /* writeback */
		};
	};
};

struct tsai_instruction_cache_mgr {
	struct tsai_instruction_cache inst[32];
	unsigned int idx_next;
	unsigned int obtain_cnt;
};

static void tsai_instruction_cache_init(struct tsai_instruction_cache_mgr* im) {
	int i;
	int max = sizeof(im->inst) / sizeof (struct tsai_instruction_cache);
	im->idx_next = 0;
	im->obtain_cnt = 0;
}

static struct tsai_instruction_cache* tsai_instruction_cache_obtain(struct tsai_instruction_cache_mgr* im) {
	struct tsai_instruction_cache* ins;
	int max = sizeof(im->inst) / sizeof (struct tsai_instruction_cache);
	ins = &im->inst[im->idx_next];

	memset (ins, 0, sizeof(struct tsai_instruction_cache));
	ins->pm = im;

	im->idx_next++;
	if (im->idx_next >= max) {
		im->idx_next -= max;
	}
	im->obtain_cnt++;
	return ins;
}

static struct tsai_instruction_cache* tsai_instruction_cache_find_prev(struct tsai_instruction_cache* base, int prev) {
	struct tsai_instruction_cache* ins;
	int idx;
	int max = sizeof(base->pm->inst) / sizeof (struct tsai_instruction_cache);

	idx = (base - &base->pm->inst[0]) ;
	idx = idx + max - prev;
	if (idx >= max) {
		idx -= max;
	}
	if (idx > base->pm->obtain_cnt) {
		ins = NULL;
	}
	else {
		ins = &base->pm->inst[idx];
	}
	return ins;
}
static inline int tsai_instruction_cache_hex_len(struct tsai_instruction_cache* ic) {
	switch (ic->armthumb) {
	case 0:
		return 4;
	case 1:
		return 2;
	case 2:
		return 4;
	}
	return 0;
}

enum TSAI_CANNOT_CONTINUE {
	T_CAN_CONTINUE = 0,
	T_UNSPECIFIED = 1,
	T_INFINITE_LOOP = 2,
};

/* use this structure to represent a basic block */
struct tsai_bb {
	unsigned int pc_begin;
	unsigned int pc_end;

	//struct tsai_instruction_cache ic_begin;
	struct tsai_instruction_cache ic_end;
};

struct tsai_frame_details {
	unsigned int cannot_continue: 2; /* something unexpected has occurred, need to stop, enum TSAI_CANNOT_CONTINUE */

	unsigned int f_r14_valid:1;
	unsigned int f_r14_examined:1;
	unsigned int f_at_jump_table:1; /* it's 1st frame and is at jump table */
	unsigned int f_start_suspicious:1; /* the start address is with doubt, usually the start address from R14 directly at 1st frame*/
	unsigned int f_early_out_bb: 1; /* found a early out bb, ready to scan, meaning early_out_bb is valid */
	unsigned int f_pc_set:1; /* in forward execution, pc has been set eg. pop {pc} */
	unsigned int can_unwind_now:1;

	unsigned int flags;
	unsigned int pc_r14_retrieve; /* the PC which retrieve R14 value */
	unsigned int st_r14_retrieve; /* the address on stack where R14 is retrieved */
	struct tsai_instruction_cache* ic_r14_retrieve;
	unsigned int pc_functioncall; /* most recent function call, handy when examine tentative LR */
	unsigned int cnt_functioncall;
	unsigned int pc_bxr14; /* encountered BX R14, so if R14 information is available, do the unwind */

	/* use b / b(cond) to detect conditional basic block, when encountering B (or pop PC or other early out pattern ), mark its location */
	unsigned int pc_b;

	unsigned int pc_r13_tainted; /* eg. add r13,r13,r14*/
	unsigned int pc_most_recent_sp_sub;
	struct tsai_instruction_cache* ic_most_recent_sp_sub;
	unsigned int most_recent_r11_set; /* the most recent instruction writing to R11 based on R13 value, eg add r11,r13,#0x8*/
	unsigned int cnt_r11_use; /* how many times r11 being used to load/store variable, indicating R11 is frame pointer */
	unsigned int plt_target;

	struct tsai_bb early_out_bb;
};

static void tsai_frame_details_clear(struct tsai_frame_details* fde) {
	memset(fde, 0, sizeof(*fde));
}

static void tsai_frame_details_return_retrieve(struct tsai_frame_details* fde, struct tsai_intermediate_regs* ar, struct tsai_instruction_cache* ic, unsigned int reg, unsigned int stack_addr) {
	fde->pc_r14_retrieve = ic?ic->PC:0;
	fde->ic_r14_retrieve = ic;
	fde->st_r14_retrieve = stack_addr;
	fde->f_r14_examined = 0;
	fde->f_r14_valid = 0;

	if (reg==ARM_LR_REGNUM) {
		TSAI_UNWIND_LOG("extra R14 %08x from %08x %s from stack %08x\n", ar->lr, ic?ic->PC:0, ic?ic->mnemonic:"exidx", stack_addr);
	}
	else if (reg==ARM_PC_REGNUM) {
		fde->f_pc_set = 1;
		TSAI_UNWIND_LOG("extra R15 %08x from %08x %s from stack %08x\n", ar->pc, ic?ic->PC:0, ic?ic->mnemonic:"exidx", stack_addr);
	}
	else BKPT;
}

enum {
	EXEC_BACKWARD = 0,
	EXEC_FORWARD = 1,
	EXEC_FORWARD_EMPTY = 2,
};

static const char* exec_char[] = {
		"",
		"[fwe]",
		""
};

struct tsai_handle_insn_param {
	int cpu_core;
	struct tsai_intermediate_regs *ar;
	struct tsai_instruction_cache* ic;
	unsigned int start;
	unsigned int start_len;
	unsigned int start_found; /* from the valid LR address, extract jump function start*/
	struct tsai_frame_details* fde;
	struct TSAI_EXIDX_UNWIND* exidx;
	int call_depth; /* when depth =0, things like jump table for LD might appear */
	struct mm_struct *mm;
	struct TSAI_VMA_MGR* vma_mgr;
	struct TSAI_VMA_WRAPPER* vw;
	const char* func_name;
	unsigned int armthumb:2; /* 0=ARM, 1=Thumb(unspecified) 2=Thumb32 */
	unsigned int forward_execution:2; /* 0=default backward 1=forward 2=empty*/
	unsigned int f_start_found: 1;
};

void tsai_handle_insn_param_clear(struct tsai_handle_insn_param* p) {
	memset(p, 0, sizeof(struct tsai_handle_insn_param) );
}

/* need to roll-out these function to make sure sane outcome */
static int tsai_check_register_value(struct tsai_handle_insn_param* p, int rd, unsigned int value);
static int tsai_check_set_register_value(struct tsai_handle_insn_param* p, int rd, unsigned int value);

/*
 *
 * */
static unsigned long tsai_mark_early_out(struct tsai_instruction_cache* ic, struct tsai_frame_details* fde)
{
	unsigned long pc = ic->PC;

	if (fde->pc_b && (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) ) {
		fde->early_out_bb.pc_end = fde->pc_b;
		fde->early_out_bb.pc_begin = ic->PC + tsai_instruction_cache_hex_len(ic);
		fde->f_early_out_bb = 1;

		fde->pc_b = 0;
	}

	fde->flags |= KUBT_FLAG_FUNC_EPILOGUE;
	fde->pc_b = pc;
	TSAI_UNWIND_LOG(" @%08x %08x %s%s Rt %d sets KUBT_FLAG_FUNC_EPILOGUE \n", pc, ic->hex_code, ic->mnemonic,
			ic->condmnemonic, ic->link_reg);
	return pc;
}

/* rd: destination register
 * return: 0 nothing suspicious found
 * otherwse, fail sanity check and register value unchanged
 * */
static int tsai_check_register_value(struct tsai_handle_insn_param* p, int rd, unsigned int value) {
	int ret = -1;
	switch(rd) {
	case ARM_SP_REGNUM:
		{
			if (value >= p->ar->sp_saved && value <= p->ar->sp_end ) {
				/* Sane value */
			}
			else {
				goto Leave;
			}

		}
	case ARM_PC_REGNUM:
		{
			if (value >= p->mm->task_size) { /* kernel mode address, certainly not possible */
				goto Leave;
			}
		}
		break;
	}

	ret = 0;
Leave:
	return ret;
}

/* rd: destination register
 * return: 0 nothing suspicious found
 * otherwse, fail sanity check and register value unchanged
 * */
static int tsai_check_set_register_value(struct tsai_handle_insn_param* p, int rd, unsigned int value) {
	int ret = -1;
	if (rd==ARM_PC_REGNUM) {
		if (value >= p->mm->task_size) { /* kernel mode address, certainly not possible */
			goto Leave;
		}
	}
	else if (rd == ARM_LR_REGNUM) {
		//tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
	}
	else if (rd == ARM_SP_REGNUM) {
		if (value >= p->ar->sp_saved && value <= p->ar->sp_end ) {
			/* Stack within correct range */
		}
		else {
			goto Leave;
		}
	}

	ret = 0;
	p->ar->R[rd] = value;
	p->ar->reg_extract_mask |= 1<<rd;
	TSAI_UNWIND_LOG(" @%08x %08x %s%s R[%d]=%08x @%d\n", p->ic->PC , p->ic->hex_code, p->ic->mnemonic,
		p->ic->condmnemonic, rd, value, __LINE__);
Leave:
	if (ret) {
		TSAI_UNWIND_LOG(" @%08x %08x %s%s R[%d]=%08x Not accepted @%d\n", p->ic->PC , p->ic->hex_code, p->ic->mnemonic,
			p->ic->condmnemonic, rd, value, __LINE__);
	}
	return ret;
}

static int tsai_check_set_register_value_from_stack(struct tsai_handle_insn_param* p, int rd, unsigned int stack_addr) {
	unsigned int value;
	tsai_get_user_data_caution(p->mm, stack_addr, 4, &value);
	if (rd==ARM_LR_REGNUM) {
		tsai_frame_details_return_retrieve(p->fde, p->ar, p->ic, rd, stack_addr);
	}

	return tsai_check_set_register_value(p, rd, value);
}

static int tsai_handle_thumb_insn(struct tsai_handle_insn_param* p);
static int tsai_handle_arm_insn(struct tsai_handle_insn_param* p);

struct TSAI_FULL_PATH_BUFFER {
	char path_buffer[256];
};
static struct TSAI_FULL_PATH_BUFFER tsai_full_path_buffer[4];

/*

PLT jump table
jump table maybe begin with ADR or LDR

begin with LDR example
___________________addr/line|source
           NSR:00AB:B132A6A0|E59FC004  ___ZN4llvm3sys9MutexImplC1Eb.:ldr     r12,0xB132A6AC   ; r12,=llvm::sys::MutexImpl::MutexI
           NSR:00AB:B132A6A4|E08FC00C                                add     r12,pc,r12
           NSR:00AB:B132A6A8|E12FFF1C                                bx      r12
           NSP:00AB:B132A6AC|01642455                                dcd     0x1642455

NOTE: PLT also contains instruction like bx pc, this is to switch between ARM and thumb.

maybe_in_middle:[in] if it's first frame and in interrupt context, likely PC is not right in begining of entry, but in the middle

return value:
0: NO
1: PLT jump table
2: PLT bx pc (ARM/Thumb mode switch)
 *
 */
static int tsai_is_PLT_table(struct tsai_handle_insn_param* pa, unsigned int pc,
		struct tsai_intermediate_regs* input_ar, unsigned int is_thumb, unsigned int maybe_in_middle, unsigned int* out_jump_target)
{
	int ret = 0;
	unsigned int extracted_jump_target = 0;
	int i;
	struct tsai_handle_insn_param* p;
	struct tsai_frame_details* fde;
	struct tsai_instruction_cache_mgr* im;
	struct tsai_intermediate_regs* ar;
	unsigned int insn;
	unsigned int pc_adjusted = pc;
	struct TSAI_FAKE_STACK_TICKET ticket;
	struct TMP_PARSE_USER_CALLSTACK {
		struct tsai_intermediate_regs ar_stack;
		struct tsai_handle_insn_param param;
		struct tsai_frame_details f;
		struct tsai_instruction_cache_mgr im;
		char full_path[256];
		//char func_name[128];
	};
	struct TMP_PARSE_USER_CALLSTACK* ts =
			(struct TMP_PARSE_USER_CALLSTACK*)tsai_fake_stack_get(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	/* TODO: at first frame, PC may not be pointing to begin of a entry table, but in the middle */
RetryPC:
	TSAI_UNWIND_LOG(" checking whether pc %08x is a PLT jump table @%d\n", pc_adjusted, __LINE__);
	p = &ts->param;
	tsai_handle_insn_param_clear(p);
	*p = *pa;
	p->forward_execution = EXEC_FORWARD;
	fde = &ts->f;
	ar = &ts->ar_stack;
	*ar = *input_ar;
	im = &ts->im;

	ar->pc = pc_adjusted;
	ar->pc_saved = ar->pc;

	ar->frame_is_thumb = is_thumb;

	p->ar = ar; p->fde = fde; p->start = 0;

	tsai_frame_details_clear(fde);
	tsai_instruction_cache_init(im);

	for (i=0; i<3; i++) { /* if it's LD jump table, it should be like 3 instructions only */
		struct tsai_instruction_cache* ic;
		if (ar->frame_is_thumb) {
			unsigned t32_sig;
			tsai_get_user_data_caution(p->mm, PC_NO_THUMB(ar->pc), 4, &insn);
			/* TSAI: note, Thumb32 bit should be consider as 2 x 16bit,
			 * eg.
			 * F7DFEF86            blx     0x424D901C
			 * in the memory F7DF will appear first, followed by 0xEF86
			 * if loading 4 bytes togethr, because of endian, F7DF might end up in the lo byte
			 * */
			insn = (insn & 0x0000FFFF) << 16 | (insn & 0xFFFF0000) >> 16;
			t32_sig = (insn) >> 27;
			if (t32_sig == 0b11101 || t32_sig == 0b11110 || t32_sig == 0b11111) {
				p->armthumb = 2;
			}
			else {
				p->armthumb = 1;
				insn &= 0x0000FFFF;
			}

		} else {
			p->armthumb = 0;
			tsai_get_user_data_caution(p->mm, ar->pc, 4, &insn);
		}

		ic = tsai_instruction_cache_obtain(im); ic->hex_code = insn; ic->PC = ar->pc;
		p->ic = ic;

		if (ar->frame_is_thumb) {
			tsai_handle_thumb_insn(p);
		}
		else {
			tsai_handle_arm_insn(p);
		}
ProcessAgain:
		if (maybe_in_middle) {
			int retry = 0;
			if (ic->mnemonic == STR_ADR) {
				maybe_in_middle = 0;
				goto ProcessAgain;
			}
			else if (ic->mnemonic == STR_BX && ic->link_reg==ARM_PC_REGNUM){
				maybe_in_middle = 0;
				goto ProcessAgain;
			}
			else if (ic->mnemonic == STR_BX && ic->link_reg==ARM_PC_REGNUM) {
				maybe_in_middle = 0;
				goto ProcessAgain;
			}
			else if (ic->mnemonic == STR_ADD) {
				pc_adjusted = pc - 4;
				retry = 1;
			}
			else if (ic->mnemonic==STR_LDR && ic->link_reg==ARM_PC_REGNUM) {
				pc_adjusted = pc - 8;
				retry = 1;
			}
			else if (ic->mnemonic==STR_B || ic->mnemonic==STR_BX) {
				pc_adjusted = pc - 8;
				retry = 1;
			}

			if (retry) {
				maybe_in_middle = 0;
				goto RetryPC;
			}
			else {
				break;
			}
		}
		else {
			if (i==0) {
				if (ic->mnemonic == STR_ADR) {}
				else if (ic->mnemonic == STR_LDR && ic->link_reg==12) {
					//__asm("bkpt");
				}
				else if (ic->mnemonic == STR_BX && ic->link_reg==ARM_PC_REGNUM) {
					__asm("bkpt");
					TSAI_UNWIND_LOG(" pc %08x ARM/Thumb switch @%d\n", pc, __LINE__);
					ret = 2;
				}
				else
					break;
			}
			else if (i==1) {
				if (ic->mnemonic != STR_ADD) {
					break;
				}
			}
			else if (i==2) {
				if (ic->mnemonic==STR_LDR && ic->link_reg==ARM_PC_REGNUM)
				{
					extracted_jump_target = ar->pc;
					ret = 1;
					TSAI_UNWIND_LOG(" pc %08x is a Jump Table, real target is %08x\n",
							pc, extracted_jump_target);
					break;
				}
				if (ic->mnemonic==STR_B || ic->mnemonic==STR_BX) {
					extracted_jump_target = ar->R[ ic->link_reg ];
					ret = 1;
					TSAI_UNWIND_LOG(" pc %08x is a Jump Table, real target is %08x\n",
							pc, extracted_jump_target);
					//__asm("bkpt");
					break;
				}
			}
		}

		if (ar->frame_is_thumb) {
			if (p->armthumb == 2)
				ar->pc += 4;
			else
				ar->pc += 2;
		}
		else {
			ar->pc += 4;
		}
	}

	if (ret==1 && out_jump_target) {
		*out_jump_target = extracted_jump_target;
	}

	tsai_fake_stack_put(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	return ret;
}

static int tsai_find_jump_target(struct tsai_handle_insn_param* pa, struct tsai_instruction_cache* ic_branch, int lr_from_register) {
	int ret = 0;
	unsigned int extracted_jump_target = 0;
	unsigned int branch_jump_table = 0;
	unsigned int pabort_suspect = 0;

	if (lr_from_register) {
		/* there is small possibility that the jump target is in p-abort and not loaded into memory yet
		 * if that's the case, it won't be jump table because jump table is unlikely to suffer from p-abort??
		 * */
		unsigned int insn;
		if (tsai_get_user_data_caution(pa->mm, ic_branch->link_address, 4, &insn)) {
			pabort_suspect = 1;
		}
	}

	/* try see if the branch instruction is pointing to a jump table, to check consistency
	 * because the LR value from register could be from recent function call from this function and not for this function
	 * Note, even jumping from within the same binary may involve with a jump table!
	 * eg. /usr/lib/libevas.so.1.16.0
	 * Therefore jump table should always be examined!
	 * */
	if (pabort_suspect) {
		/* for now, since there is no evidence to prove jump target is wrong, treat it as if it's correct */
	}
	else {
		unsigned int is_thumb;
		TSAI_UNWIND_LOG(" checking @%08x %s%s %08x is it a jump table @%d\n",
				ic_branch->PC, ic_branch->mnemonic, ic_branch->condmnemonic, ic_branch->link_address, __LINE__ );
		if (ic_branch->mnemonic==STR_BLX) {
			is_thumb = (pa->ar->frame_is_thumb+1) & 1;
		}
		else {
			is_thumb = (pa->ar->frame_is_thumb);
		}

		branch_jump_table = (1 == tsai_is_PLT_table(pa, ic_branch->link_address, pa->ar, is_thumb, 0, &extracted_jump_target));
	}

	if (branch_jump_table) {
		ret = 1;
	}
	else {
		extracted_jump_target = ic_branch->link_address;
		ret = 1;
	}

	if(ret) {
		pa->f_start_found = 1;
		pa->start_found = extracted_jump_target;
	}
	else {
		pa->f_start_found = 0;
		pa->start_found = 0;
	}
	return ret;
}

/* when extracted R14 from stack, and if start is not specified use this function to examine whether it can be treated as begin to function and unwind immediately
 * lr_from_register: if lr value is not extracted from stack by immediately from register, it could be the return value from recent function call so it may look valid but not
 * */
static int tsai_examine_lr_valid(struct tsai_handle_insn_param* pa, int tentative, int lr_from_register) {
	int ret = 0;
	int inconclusive = 0;

	struct TSAI_VMA_WRAPPER* vw;
	struct tsai_intermediate_regs* ar;
	unsigned int insn = 0;
	unsigned int t32 = 0;
	int th_mode;
	int lr_ok = 0;
	struct tsai_handle_insn_param* p;
	struct tsai_frame_details* fde;
	struct tsai_instruction_cache_mgr* im;
	char* path;
	char* filename;
	char* path_buf;

	struct TMP_PARSE_USER_CALLSTACK {
		struct tsai_intermediate_regs ar_stack;
		struct tsai_handle_insn_param param;
		struct tsai_frame_details f;
		struct tsai_instruction_cache_mgr im;
		const char* func_name;
	};
	struct TSAI_FAKE_STACK_TICKET ticket;
	struct TMP_PARSE_USER_CALLSTACK* ts =
			(struct TMP_PARSE_USER_CALLSTACK*)tsai_fake_stack_get(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	pa->f_start_found = 0;
	p = &ts->param;
	*p = *pa;
	fde = &ts->f;
	ar = &ts->ar_stack;
	im = &ts->im;

	*ar = *(pa->ar);

	ar->pc = ar->lr;
	if (!ar->pc) {
		ret = 0;
		goto Leave;
	}
	ar->pc_saved = ar->pc;
	ar->frame_is_thumb = (ar->pc & 0x01);

	p->ar = ar; p->fde = fde; p->start = pa->start;

	tsai_frame_details_clear(fde);
	tsai_instruction_cache_init(im);

	/* access_ok(VERIFY_READ, ar->pc, sizeof(insn)) only test whether an address is of user mode space,
	 * not testing whether it's a valid address, so I use vma instead,
	 * */
	{
		struct mm_struct *mm = p->mm;
		path_buf = tsai_full_path_buffer[pa->cpu_core].path_buffer;
		vw = tsai_find_vma_wrapper_by_addr(p->vma_mgr, ar->pc, mm, path_buf);
		if (vw) {
			p->vw = vw;
			if (p->vw->vma && p->vw->vma->vm_file && (ar->pc >= p->vw->vma->vm_start) &&
					(ar->pc < p->vw->vma->vm_end) )
			{
			}
			else {
				goto Leave;
			}
		}
		else {
				goto Leave;
		}
	}

	/* LR is point to next instruction, what if it's across page boundary? */
	/* use cautious read to check if the memory is ok to read*/
	if (tsai_get_user_data_caution(pa->mm, PC_NO_THUMB(ar->pc) - 4, 4, &insn)) {
		/* there has been observation of LR point to libc  __libc_start_main() but the memory is not accessible,
		 * could be due to swapped out??
		 * so make extra consideration for that case and allow such case
		 * */
		if (p->vw->symbol_key) {
			p->start = tsai_lookup_symbol(p->vw->symbol_key, ar->pc, p->vw->vma->vm_start,
					&ts->func_name, &p->start_len);
			if (p->start && ts->func_name[0]) {
				if (tsai_check_termination_sym_name(ts->func_name)) {
					TSAI_UNWIND_LOG(" LR %08x even though not accessbile, but it's entry point %s @%d\n",
							ar->pc, ts->func_name, __LINE__);
					ret = 1;
					goto Leave;
				}
			}
		}

		if (p->vw->vma->vm_file && (p->vw->vma->vm_flags & (VM_READ|VM_EXEC))==(VM_READ|VM_EXEC) ) {
			TSAI_UNWIND_LOG(" Address %08x not accessible, but VMA shows it's %s @%d\n",
					ar->pc, p->vw->vma->vm_file->f_path.dentry->d_iname, __LINE__);
			inconclusive = 1;

			if (lr_from_register==0) {
				pte_t* pte;
				pte = tsai_address_is_on_mmu(p->mm, ar->pc, NULL);
				TSAI_UNWIND_LOG("phy addr %08x\n", *pte);
				if (pte) {
					if (*pte) {
					}
					else {
						TSAI_UNWIND_LOG(" unable to access VA %08x within interrupt context @%d\n", ar->pc, __LINE__);
					}
				}
			}
		}

		goto Leave;
	}

	{
		int ok;
		struct tsai_instruction_cache* ic;
		th_mode = ar->frame_is_thumb;
		/* THUMB addresses have 0 bit set, which is identical to
		 * `pc + 1'. In order to read correct `pc' we need to adjust
		 * pc address. */
		/* we read 4 bytes for ARM mode and 2 bytes for THUMB.
		 * Take special care of THUMB16/THUMB32 mode instructions */
		if (th_mode) {
			unsigned pc_tmp;
			unsigned t32_sig;
			ar->pc -= 2;
			pc_tmp = (ar->pc - 2) & ~1 ;

			ok = tsai_get_user_data_caution(pa->mm, pc_tmp, 4, &insn);
			while (ok) {
				goto Leave;
				ar->pc = ( (ar->pc - 4096) | (4096-1)) - 4 ; /* the last 4 bytes of a page*/
				pc_tmp = (ar->pc - 2) & ~1 ;
				ok = tsai_get_user_data_caution(pa->mm, pc_tmp, 4, &insn);
			}
			/* TSAI: note, Thumb32 bit should be consider as 2 x 16bit,
			 * eg.
			 * F7DFEF86            blx     0x424D901C
			 * in the memory F7DF will appear first, followed by 0xEF86
			 * if loading 4 bytes togethr, because of endian, F7DF might end up in the lo byte
			 * */
			insn = (insn & 0x0000FFFF) << 16 | (insn & 0xFFFF0000) >> 16;
			t32_sig = (insn) >> 27;
			if (t32_sig == 0b11101 || t32_sig == 0b11110 || t32_sig == 0b11111) {
				p->armthumb = 2;
				ar->pc -= 2;
			}
			else {
				p->armthumb = 1;
				insn &= 0x0000FFFF;
			}

		} else {
			ar->pc -= 4;
			p->armthumb = 0;
			ok = tsai_get_user_data_caution(pa->mm, ar->pc, 4, &insn);
			while (ok) {
				goto Leave;
				ar->pc -= 4096;
				ok = tsai_get_user_data_caution(pa->mm, ar->pc, 4, &insn);
			}
		}

		ic = tsai_instruction_cache_obtain(im); ic->hex_code = insn; ic->PC = ar->pc;
		p->ic = ic;
		if (!p->start) { /* only need to examine one instruction really, avoid recursive call */
			p->start = ar->pc - 4;
		}

		if (th_mode)
			tsai_handle_thumb_insn(p);
		else
			tsai_handle_arm_insn(p);


		if ((fde->pc_functioncall&~1) == (ar->pc&~1)) {
			lr_ok = 1;

			if (!pa->start || fde->f_start_suspicious) {
				if (ic->link_address && !ic->link_reg) {
					/* we can do more to extract the function begin address */
					tsai_find_jump_target(p, ic, lr_from_register);

					if (p->f_start_found) {
						pa->f_start_found = p->f_start_found;
						pa->start_found = p->start_found;

						TSAI_UNWIND_LOG("R14 %08x indicates the function call start %08x caller %p @%d \n",
							pa->ar->lr, pa->start_found, __builtin_return_address(0),__LINE__);
					}
				}
				else {
					if (p->call_depth==0) {
						pa->f_start_found = 1;
						pa->start_found = ar->R[ic->link_reg];
						TSAI_UNWIND_LOG("R14 points to %s r%d, for 1st frame, R%d is %08x\n",
							ic->mnemonic, ic->link_reg, ic->link_reg, pa->start_found);
					}
					else {
						if (ar->reg_extract_mask & (1<<ic->link_reg)) {
							TSAI_UNWIND_LOG("%s r%d=%08x, meant to be jump target @%d\n",
								ic->mnemonic, ic->link_reg, ar->R[ic->link_reg],__LINE__);
							pa->f_start_found = 1;
							pa->start_found = ar->R[ic->link_reg];
						}
						else {
							TSAI_UNWIND_LOG("R14 points to %s r%d cannot find jump target @%d\n",
							ic->mnemonic, ic->link_reg, __LINE__);
						}
					}
				}
			}
		}
	}


	/* if LR is included in this push, almost certain it's begin of a function*/

	if ( pa->start ) {
		if (lr_ok) {
			ret = 1;
		}
	}
	else { /* without the symbol we need to make a educated guess*/
		unsigned int pc = PC_NO_THUMB(ar->pc);

		if (lr_ok) {
			if (!tentative) {
				if ((pa->fde->most_recent_r11_set && pa->fde->pc_most_recent_sp_sub)) {
					TSAI_UNWIND_LOG("GUESS %08x push LR is begin of function, as SUB SP and ADD R11, R13 seen \n", pc);
					pa->fde->can_unwind_now = 1;
				}
				if ((pa->fde->pc_most_recent_sp_sub - pc) <= 4) {
					TSAI_UNWIND_LOG("GUESS %08x push LR is begin of function, as SUB SP follows \n", pc);
					pa->fde->can_unwind_now = 1;
				}
				else {
					/* without seeing SUB SP, but it could be this function doesn't use stack */
					pa->fde->can_unwind_now = 1;
				}
			}
			ret = 1;
		}
		else {
			//__asm("bkpt");
		}
	}
Leave:
	if (ret==0) {
		TSAI_UNWIND_LOG("examine_lr_valid LR %08x not appears valid @%d\n", ar->pc, __LINE__);
	}
	tsai_fake_stack_put(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);

	if (inconclusive)
		pa->fde->f_r14_examined = 0;
	else
		pa->fde->f_r14_examined = 1;
	pa->fde->f_r14_valid = ret;
	return ret;
}

/* TSAI: common suspicious pattern for function begin or end
 *
 * CASE:
 * bx r14 is end of prev function and nop are the padding between functions
 * the function begin  with
 * 7802                ldrb    r2,[r0]
           NST:01D0:4101AEE0|EBA20003            sub     r0,r2,r3
           NST:01D0:4101AEE4|4770                bx      r14
           NST:01D0:4101AEE6|BF00                nop
           NST:01D0:4101AEE8|F3AF8000            nop.w
           NST:01D0:4101AEEC|F3AF8000            nop.w
           NST:01D0:4101AEF0|7802                ldrb    r2,[r0]
           NST:01D0:4101AEF2|780B                ldrb    r3,[r1]


 *
 *
 *
 * */

#if 0
/* now encounter a bx R14, very likely it belongs to previous function
 * return 0: nothing suspicious
 * 1: this is end of prev func, so unwind should have happened
 * */
static int tsai_examine_branch_lr(struct tsai_handle_insn_param* p) {
	int ret = 0;
	int prev;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	struct tsai_instruction_cache* prev_ic = 0;

	//keep searching past instruction, until one which is not NOP
	for (prev=1; ;prev++) {
		prev_ic = tsai_instruction_cache_find_prev(ic, prev);
		if (!prev_ic)
			break;
		if (prev_ic->mnemonic==STR_NOP) {
			break;
		}
	}

	if (unlikely(!prev_ic)) {
		/* so many NOP? unlikely*/
		__asm("bkpt");
		goto Leave;
	}

	/* find a likely begin of function, if LR also make sense*/
	p->ar->pc = prev_ic->PC;
	p->ic = prev_ic;
	ret = tsai_examine_lr_valid(p);

Leave:
	return ret;
}
#endif

static int tsai_insn_can_be_data(unsigned int insn) {
	if ((insn&0xFFFF0000)==0xFFFF0000 )
		return 1;
	if ((insn&0xFFE00000)==0)
		return 1;
	return 0;
}

static int tsai_end_of_bb_pattern_match(struct tsai_instruction_cache* ic) {

	if (ic->mnemonic==STR_B) {
		return 1;
	}
	if (ic->mnemonic==STR_POP &&
				( (ic->link_reglist & (1 << ARM_PC_REGNUM)) || (ic->link_reg==ARM_PC_REGNUM) ) )
	{
		return 1;
	}
	else if (ic->mnemonic==STR_BX && (!ic->condmnemonic || ic->condmnemonic==STR_AL) && ic->link_reg==ARM_LR_REGNUM) {
		return 1;
	}

	return 0;
}

/* check whether this instruction could hint begin of funciton has been encoutered
 * Note if return 1, it could be also just early out block so need to consider overall criteria
 * */
static int tsai_begin_function_instruct_pattern_match(struct tsai_handle_insn_param* p, struct tsai_instruction_cache* ic, int confidence) {
	if (ic->mnemonic==STR_DCD) {
		return 1;
	}
	else if (ic->mnemonic==STR_NOP) {
		return 1;
	}
	else if (ic->mnemonic==STR_POP &&
			( (ic->link_reglist & (1 << ARM_PC_REGNUM)) || (ic->link_reg==ARM_PC_REGNUM) ) )
	{
		/* pop R14 or pop R15 could be encoutering end of previous function, or an early out block */

		return 1;
	}
	else if (ic->mnemonic==STR_BX && (!ic->condmnemonic || ic->condmnemonic==STR_AL) && ic->link_reg==ARM_LR_REGNUM) {
		return 1;
	}

	/* if there are multiple evidence suggesting high confidence, unconditional branch can also be considered */
	if (confidence) {
		{
			unsigned int clean_pc = PC_NO_THUMB(ic->PC);
			/* PC is aligned to 4 bytes*/
			if (( (clean_pc & 3)==0 )) {
				unsigned int insn = 0;
				tsai_get_user_data_caution(p->mm, clean_pc, 4, &insn);
				if (tsai_insn_can_be_data(insn))
					return 1;
			}
		}

		if (ic->mnemonic==STR_B && (!ic->condmnemonic || ic->condmnemonic==STR_AL)) {
			return 1;
		}
		if (ic->mnemonic==STR_POP) { /* found a pop before push r14, it could mean that push r14 is actual begin of function
		eg
			pop {...}
			....
			push {..., R14}
		*/
			return 1;
		}
	}

	return 0;
}

/* when we extracted function start by cross-referencing LR
 * use this function to see if the value make sense or indicates anomaly
 * return: 1 if the function start looks make sense
 * 0: not accepted, or it's anomaly that need inspection
 * */
static int tsai_examine_extracted_function_start(struct tsai_handle_insn_param* p) {
	int ret = 0;

	if (p->f_start_found && p->start_found) {
		/* check the extract start actually make sense?? */
		char* path_buf;
		struct TSAI_VMA_WRAPPER* vw_jump_target;
		unsigned int start_found_clean = p->start_found & ~1;
		path_buf = tsai_full_path_buffer[p->cpu_core].path_buffer;
		vw_jump_target = tsai_find_vma_wrapper_by_addr(p->vma_mgr, start_found_clean, p->mm, path_buf);

		if (vw_jump_target == p->vw) {
			if (start_found_clean <= p->ar->pc_saved) {
				ret = 1;
			}
			else {
				/* there are known case of this, /usr/lib/libc-2.24.so strcmp*/
				TSAI_UNWIND_LOG(" ANOMALY extracted start address %08x is after original PC %08x \n", start_found_clean, p->ar->pc_saved);
				if (p->vw->symbol_key && !p->start) {
					int distance = start_found_clean - p->ar->pc_saved;
					if (distance < 0x20) {

						TSAI_UNWIND_LOG(" SPECIAL HANDLING: ANOMALY could be a known libc case %08x\n", start_found_clean);
						p->ar->pc = start_found_clean;
						p->start = start_found_clean;
						ret = 1;
						goto Leave;
					}
				}
			}
		}

		if (ret == 1) {
			if (!p->start || p->fde->f_start_suspicious ) {
				p->start = start_found_clean;
				TSAI_UNWIND_LOG(" use the branch target from LR as start address %08x\n", p->start);
			}
		}
		else if (ret != 1){
			TSAI_UNWIND_LOG(" extracted start address %08x suspicious, ignored \n", start_found_clean);
			p->f_start_found = 0;
			p->start_found = 0;
		}
	}
Leave:
	return ret;
}

static int tsai_known_redirect_lib(const char* libname) {
	int ret = 0;
	if (libname) {
		if (strncmp(libname, "libvulkan.so", 12)==0)
			ret = 1;
		if (strncmp(libname, "libGLESv2.so.2.0", 16)==0)
			ret = 1;
	}
	return ret;
}

/* 1 = consider to be begin of a function, should unwind callstack to upper frame
 * 0 = normal
 * -1 indicates something considered wrong, and should abort callstack parsing
 * */
static int tsai_detect_begin_function(struct tsai_handle_insn_param* p) {
	int ret = 0;
	int prev;
	int lrok = 0;
	int highly_likely = 0;
	int suspicious = 0;
	int confidence = 0;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	struct tsai_frame_details* fde = p->fde;
	struct tsai_instruction_cache* prev_ic = 0;

	if (fde->pc_r14_retrieve && (p->call_depth==0 || (ar->sp > ar->sp_saved)) ) { /* SP must have changed, except the 1st frame could be not pushing to stack */
		if (PC_NO_THUMB(ar->pc) == PC_NO_THUMB(fde->pc_r14_retrieve)) {
			/* examine the R14 value, in the process it might retrieve the function start and help the unwinding */
			ASSERT(!fde->f_r14_examined);

			lrok = tsai_examine_lr_valid(p, 1, 0);
			fde->f_r14_examined = 1;
			fde->f_r14_valid = lrok;

			if (lrok) {
				int start_ok = tsai_examine_extracted_function_start(p);
				if (start_ok) {
					int distance = PC_NO_THUMB(fde->pc_r14_retrieve) - p->start;
					if (distance >= 0 && distance < 0x20 ) {
						fde->f_start_suspicious = 0;
						TSAI_UNWIND_LOG("The newly extract start address looks reasonable %08x @%d\n", p->start, __LINE__);
					}
					else {
						fde->f_start_suspicious = 1;
						TSAI_UNWIND_LOG(" extracted start address sucipicous %08x PC %08x @%d\n",
							p->start, PC_NO_THUMB(ar->pc), __LINE__);
						/* one frame might have been missing, but still LR is highly likely to be valid */
						highly_likely = 1;
						goto TakeAction;
					}
				}
			}
		}
		else if (PC_NO_THUMB(ar->pc) < PC_NO_THUMB(fde->pc_r14_retrieve)) {
			/* if R14 has been recently retrieved, from push, stm, etc..., then encountering anything like padding, nop,
			 * or pop pc would indicate already encountering begin of function
			 * keep in mind R14 could be used for general purpose register, doesn't mean it's LR
			 * */

			if (fde->pc_most_recent_sp_sub)
				confidence++;

			/* if R14 value itself looks ok, it can also be considered high confidence */
			if (fde->f_r14_examined) {
				if (fde->f_r14_valid) {
					lrok = 1;
				}
			}
			else {
				lrok = tsai_examine_lr_valid(p, 1, 0);
				fde->f_r14_examined = 1;
				fde->f_r14_valid = lrok;
			}

			if (lrok)
				confidence++;

			if (confidence && tsai_begin_function_instruct_pattern_match(p, ic, confidence) ) {
				TSAI_UNWIND_LOG(" %s pc %08x pc_r14 %08x pc_most_recent_sp_sub %08x, lrok=%d confidence=%d @%d\n",
					ic->mnemonic, ar->pc, fde->pc_r14_retrieve,fde->pc_most_recent_sp_sub, lrok, confidence, __LINE__);

				//keep searching past instruction, until one which is not NOP
				for (prev=1; ;prev++) {
					prev_ic = tsai_instruction_cache_find_prev(p->ic, prev);
					if (!prev_ic)
						break;
					if (tsai_begin_function_instruct_pattern_match(p, prev_ic, confidence)) {
						/* continue */;
					}
					else
						break;
				}

				if (unlikely(!prev_ic)) {
					/* unlikely*/
					__asm("bkpt");
					goto Leave;
				}

				highly_likely = 1;
			}
			else {
				//__asm("bkpt");
			}
		}
	} /* if (fde->pc_r14_retrieve ) */
	else if (p->start && fde->f_start_suspicious && (PC_NO_THUMB(ar->pc) - PC_NO_THUMB(p->start) < 0x20) ) {
		/* the start address now almost certain is valid */
		fde->f_start_suspicious = 0;
		TSAI_UNWIND_LOG("start address %08x now almost certain to be valid @%d\n", p->start, __LINE__);
		goto Leave;
	}
	else if (p->call_depth==0 && ar->interrupt_on_user) {
		/* is it jump table?? */
		if (ic->mnemonic==STR_ADR || ic->mnemonic==STR_LDR) {
			int is_jump_table;
			/* check whether it is a jump table */
			is_jump_table = (1 == tsai_is_PLT_table(p, ic->PC, p->ar,ic->armthumb, 1, NULL));
			/* check whether LR is valid, it should be! */
			if (is_jump_table) {
				fde->f_at_jump_table = 1;
				fde->f_r14_examined = 0;
				fde->f_r14_valid = 0;
				highly_likely = 1;

				goto TakeAction;
			}
		}
		else if (fde->pc_most_recent_sp_sub) { /* it could be R14 is valid in the register */
			if (fde->f_r14_examined)
				lrok = fde->f_r14_valid;
			else
				lrok = tsai_examine_lr_valid(p, 1, 1);

			if (!lrok) {
				goto Leave;
			}

			if (fde->ic_most_recent_sp_sub->mnemonic == STR_STR || fde->ic_most_recent_sp_sub->mnemonic == STR_STRD) {
				if (p->start) {
					int distance = fde->pc_most_recent_sp_sub - p->start;
					if (distance >=0 && distance < 0x20) {
						fde->f_start_suspicious = 0;
						/* treat it as the case which start is known*/
						ret = 0;
						goto Leave;
					}
				}

				confidence++;
				highly_likely = 1;
				__asm("bkpt");
			}
		}
		else if (p->armthumb && p->ic->mnemonic==STR_PUSH && p->fde->cnt_functioncall==0 && fde->pc_r14_retrieve==0) {
			if (p->ic->mnemonic==STR_PUSH) {
			/* sometimes there are some tiny functions that doesn't call other functions and R14 is not pushed to stack,
			 * for such case R14 is immediately in register, see this example
___________________addr/line|source
           NST:0FA9:B3156C9C|B480                push    {r7}
           NST:0FA9:B3156C9E|447A                add     r2,r2,pc
           NST:0FA9:B3156CA0|AF00                add     r7,sp,#0x0
           NST:0FA9:B3156CA2|6059                str     r1,[r3,#0x4]
           NST:0FA9:B3156CA4|601A                str     r2,[r3]
           NST:0FA9:B3156CA6|46BD                mov     r13,r7
           NST:0FA9:B3156CA8|F85D7B04            pop     {r7}
           NST:0FA9:B3156CAC|4770                bx      r14
           NST:0FA9:B3156CAE|BF00                nop
			 * */
				if (p->ic->link_reg==7 || (p->ic->link_reglist & (1<<7) ) ) {
					TSAI_UNWIND_LOG(" Thumb push R7 onto stack, no extracting R14 from stack, no function call @%d \n", __LINE__);
					highly_likely = 1;
					goto TakeAction;
				}
				else {
					/* libvulkan known to have re-direction table,
					 * we verify whether it's libvulkan and whether LR appears to be acceptable
					___________________addr/line|source
					           NST:0634:A951351C|B410                push    {r4}
					           NST:0634:A951351E|6804                ldr     r4,[r0]
					           NST:0634:A9513520|F8D44134            ldr     r4,[r4,#0x134]
					           NST:0634:A9513524|46A4                mov     r12,r4
					           NST:0634:A9513526|F85D4B04            pop     {r4}
					           NST:0634:A951352A|4760                bx      r12
					*/
					const char* libname = NULL;
					lrok = tsai_examine_lr_valid(p, 1, 1);
					{
						struct dentry* d = p->vw->vma->vm_file->f_path.dentry;
						if (d)
							libname = d->d_iname;

					}
					if (lrok) {
						if (tsai_known_redirect_lib(libname)) {
							TSAI_UNWIND_LOG(" likely a re-direction function in %s @%d \n", libname,__LINE__);
						}
						else {
							TSAI_UNWIND_LOG(" TOVERIFY: is it a re-direction function in %s @%d \n", libname,__LINE__);
						}

						highly_likely = 1;
						goto TakeAction;
					}
					__asm("bkpt");
				}
			}
			else if (p->ic->mnemonic==STR_BX && (!p->ic->condmnemonic || p->ic->condmnemonic==STR_AL) ) {
				/* in the first frame, encountering BX without extracting R14 and encounter no function call, indicating this is likely a re-direction table */
				/* for the first frame it could also be a re-direction table, libvulkan uses that
		___________________addr/line|code_____|label____|mnemonic________________|comment
		                        1565|LOADER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL vkResetCommandBuffer(VkCommandBuffer commandBuffer, VkC
		                            |    const VkLayerDispatchTable *disp;
		                            |
		                            |    disp = loader_get_dispatch(commandBuffer);
		                            |
		                        1570|    return disp->ResetCommandBuffer(commandBuffer, flags);
		           NST:0175:A685F514|6803      vkResetC.:ldr     r3,[r0]
		           NST:0175:A685F516|F8D33130            ldr     r3,[r3,#0x130]
		           NST:0175:A685F51A|4718                bx      r3
		                            |}
		                            |
		                            |LOADER_EXPORT VKAPI_ATTR void VKAPI_CALL vkCmdBindPipeline(VkCommandBuffer commandBuffer, VkPipeline
		                        1574|                                                           VkPipeline pipeline) {
		           NST:0175:A685F51C|B410      vkCmdBin.:push    {r4}
				 * */

				TSAI_UNWIND_LOG(" Likely re-direction table BX %d, no extracting R14 from stack, no function call @%d \n",
					p->ic->link_reg, __LINE__);
				highly_likely = 1;
				goto TakeAction;
			}
		}
		else {
			/* if this is the 1st frame, and pc is right at begin of function (even thought we don't know)
			 * check the R14 content, even if the called uses blx register, register value is reliable for 1st frame
			 * so we might be likely to extract start address!
			 * */

		}

		if (tsai_begin_function_instruct_pattern_match(p, ic, confidence)) {
			/* PC may point to begin of function at already when begin to parse */
			TSAI_UNWIND_LOG("examine_begin_function %08x %08x %s check R14 %08x @%d\n",
					ar->pc, p->ic->hex_code, p->ic->mnemonic, ar->lr, __LINE__);

			if (fde->f_r14_examined)
				lrok = fde->f_r14_valid;
			else {
				lrok = tsai_examine_lr_valid(p, 1, 1);
			}

			if (lrok) {
				//keep searching past instruction, until one which is not NOP
				for (prev=1; ;prev++) {
					prev_ic = tsai_instruction_cache_find_prev(p->ic, prev);
					if (!prev_ic)
						break;
					if (tsai_begin_function_instruct_pattern_match(p, prev_ic, confidence)) {
						/* continue */;
					}
					else
						break;
				}

				if (prev_ic) {
					if (prev_ic->pm != p->ic->pm) {
						__asm("bkpt"); /* something has gone wrong */
					}

					p->ar->pc = prev_ic->PC;
					p->ic = prev_ic;
				}
				TSAI_UNWIND_LOG("Verdict %08x %08x %s appears begin of function, [tentative test] @%d\n",
						ar->pc, p->ic->hex_code, p->ic->mnemonic, __LINE__);
				ret = 1;
				fde->can_unwind_now = 1;
				goto Leave;
			}
		}
	} /* p->call_depth==0 && ar->interrupt_on_user */

TakeAction:
	if (highly_likely) {
		/* find a likely begin of function, if LR also make sense*/
		/* we are almost certain this is right before a function when we see this
	00000000            andeq   r0,r0,r0
		 */

		TSAI_UNWIND_LOG("examine_begin_function %08x %08x %s check R14 %08x @%d \n",
				ar->pc, p->ic->hex_code, p->ic->mnemonic, ar->lr, __LINE__);

		if (fde->f_r14_examined)
			ret = fde->f_r14_valid;
		else
			ret = tsai_examine_lr_valid(p, 0, 0);

		if (ret) {
			/* if LR was not extract from stack, it is likely to result in infinite loop, filter out that case*/
			if ( (ar->lr==ar->pc_saved) && !fde->pc_r14_retrieve) {
				//__asm("bkpt");
				fde->cannot_continue = T_INFINITE_LOOP;
				ret = -1;
				goto Leave;
			}

			if (prev_ic) {
				if (prev_ic->pm != p->ic->pm) {
					__asm("bkpt"); /* something has gone wrong */
				}

				p->ar->pc = prev_ic->PC;
				p->ic = prev_ic;
			}

			TSAI_UNWIND_LOG("Verdict %08x %08x %s appears begin of function @%d\n",
					ar->pc, p->ic->hex_code, p->ic->mnemonic, __LINE__);
			if (p->ic->SP != ar->sp) {
				TSAI_UNWIND_LOG("Adjust SP from %08x to %08x @%d\n", ar->sp, p->ic->SP, __LINE__);
				ar->sp = p->ic->SP;
			}
			fde->can_unwind_now = 1;
			ret = 1;
			goto Leave;
		}
		else {
			if (tsai_bkpt_disasm)
				__asm("bkpt");
			fde->cannot_continue = T_UNSPECIFIED;
			ret = -1;
			goto Leave;
		}
	}
Leave:
	return ret;
}

/* detecting jump table is already handled in tsai_detect_begin_function*/
static int tsai_detect_for_first_frame(struct tsai_handle_insn_param* p) {
	int ret = 0;
	return ret;
}

const char* ARM_COND[16] = { /* see A8.3 Conditional execution */
	STR_EQ, /* Equal Equal Z == 1 */
	STR_NE, /* Not equal Not equal, or unordered Z == 0 */
	STR_CS, /* Carry set Greater than, equal, or unordered C == 1*/
	STR_CC, /* Carry clear Less than C == 0 */
	STR_MI, /* Minus, negative Less than N == 1 */
	STR_PL, /* Plus, positive or zero Greater than, equal, or unordered N == 0 */
	STR_VS, /* Overflow Unordered V == 1 */
	STR_VC, /* No overflow Not unordered V == 0 */
	STR_HI, /* Unsigned higher Greater than, or unordered C == 1 and Z == 0 */
	STR_LS, /* Unsigned lower or same Less than or equal C == 0 or Z == 1 */
	STR_GE, /* Signed greater than or equal Greater than or equal N == V */
	STR_LT, /* Signed less than Less than, or unordered N != V */
	STR_GT, /* Signed greater than Greater than Z == 0 and N == V */
	STR_LE, /* Signed less than or equal Less than, equal, or unordered Z == 1 or N != V */
	STR_AL, /* Always (unconditional) Always (unconditional) Any */
	STR_UNCOND, /* unconditional, see A5.7 Unconditional instructions. eg. BLX */
};

#ifdef DEBUG
#define IGNORE_COND_BLOCK 	if ( (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) || (fde->pc_b)) {\
								TSAI_UNWIND_LOG(" ignore %08x %s due to KUBT_FLAG_FUNC_EPILOGUE or conditional block\n", ar->pc, ic->mnemonic);\
								ret = 1;\
								goto Leave;\
							}

#else
#define IGNORE_COND_BLOCK 	if ( (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) || (fde->pc_b)) {\
								ret = 1;\
								goto Leave;\
							}
#endif

static int tsai_sign_extend_imm10h_imm10l(unsigned int insn) {
	int imm32;

	unsigned s = (insn >> 26) & 1;
	unsigned j1 = (insn >> 13) & 1;
	unsigned j2 = (insn >> 11) & 1;
	unsigned imm10h = (insn >> 16) & 0b1111111111;
	unsigned imm10l = (insn >> 1 ) & 0b1111111111;

	imm32 = 0;
	imm32 |= !s << 24; /* bit 24 */
	imm32 |= !(j1 ^ s) << 23; /* bit 23 */
	imm32 |= !(j2 ^ s) << 22; /* bit 22 */
	imm32 |= imm10h << 12; /* bit 21..12*/
	imm32 |= imm10l << 2; /* bit 11..2*/
	imm32 -= (1 << 24);

	return imm32;
}


static int tsai_sign_extend_imm10_imm11(unsigned int insn) {
	int imm32;

	unsigned s = (insn >> 26) & 1;
	unsigned j1 = (insn >> 13) & 1;
	unsigned j2 = (insn >> 11) & 1;
	unsigned imm10 = (insn >> 16) & 0b1111111111;
	unsigned imm11 = (insn) & 0b11111111111;

	imm32 = 0;
	imm32 |= !s << 24; /* bit 24 */
	imm32 |= !(j1 ^ s) << 23; /* bit 23 */
	imm32 |= !(j2 ^ s) << 22; /* bit 22 */
	imm32 |= imm10 << 12; /* bit 21..12*/
	imm32 |= imm11 << 1; /* bit 11..1*/
	imm32 -= (1 << 24);

	return imm32;
}

static int tsai_sign_extend_imm6_imm11(unsigned int insn) {
	int imm32;

	unsigned s = (insn >> 26) & 1;
	unsigned j1 = (insn >> 13) & 1;
	unsigned j2 = (insn >> 11) & 1;
	unsigned imm6 = (insn >> 16) & 0b111111;
	unsigned imm11 = (insn) & 0b11111111111;

	imm32 = 0;
	imm32 |= !s << 20; /* bit 20 */
	imm32 |= j1 << 19; /* bit 19 */
	imm32 |= j2 << 18; /* bit 18 */
	imm32 |= imm6 << 12; /* bit 17..12*/
	imm32 |= imm11 << 1; /* bit 11..1*/
	imm32 -= (1 << 20);

	return imm32;
}

/* could be either T32 or ARM, can't be T16 */
static int tsai_ASIMD_three_reg_diff_len(struct tsai_handle_insn_param* p) {
	int ret = 0;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	unsigned int insn = p->ic->hex_code;
	unsigned long start = p->start;
	struct tsai_frame_details* fde = p->fde;
	int spshift;
	int decodable = 0;

	unsigned int u;
	unsigned int a;
	unsigned int b;

	if (p->armthumb)
		u = __BITS(insn, 28,28);
	else
		u = __BITS(insn, 24,24);

	a = __BITS(insn, 8,11);
	b = __BITS(insn, 20,21);

	if ((a &0b1110)==0b0000) { /* A=000x VADDL, VADDW on page A8-834*/
		ic->mnemonic = STR_VADDL;
		decodable = 1;
	}
	else if ( (a &0b1110)==0b0010 ) { /* A=001x VSUBL, VSUBW on page A8-1090*/
		ic->mnemonic = STR_VSUBL;
		decodable = 1;
	}
	else if ( a ==0b0100 ) { /* A=0100 VADDHN on page A8-832*/
		ic->mnemonic = "vaddhn";
		decodable = 1;
	}
	else if ( a == 0b0101) {
		unsigned int size = __BITS(insn, 20,21);
		unsigned int vn = __BITS(insn, 16,19);
		unsigned int vd = __BITS(insn, 12,15);
		unsigned int vm = __BITS(insn, 0,3);
		unsigned int q = __BIT(insn, 6);
		unsigned int b9 = __BIT(insn, 9);
		unsigned int b23 = __BIT(insn, 23);

		if (b23==0 && b9==1) {
			ic->mnemonic = "vaba";
			if (size==0b11)
				goto Leave;
			if (q==1 && ( (vn &0b1000) || (vd &0b1000) || (vm &0b1000)) )
				goto Leave;
		}
		else if (b23==1 && b9==0) {
			ic->mnemonic = "vabal";
			if ((vd &0b1000))
				goto Leave;
		}
		else {
			goto Leave;
		}

		decodable = 1;
	}
	else if ( a == 0b0110) {
		ic->mnemonic = "vsubhn";
		decodable = 1;
	}
	else if ( a == 0b0111) {
		ic->mnemonic = "vabd";
		decodable = 1;
	}
	else if ( (a &0b1101)==0b1000 ) { /* A=10x0 VMLA, VMLAL, VMLS, VMLSL (integer) on page A8-930*/
		ic->mnemonic = "Vector Multiply Accumulate or Subtract";
		decodable = 1;
	}
	else if (u==0 && (a &0b1101)==0b1001   ) { /* A=10x1 Vector Saturating Doubling Multiply Accumulate or Subtract Long */
		ic->mnemonic = "Vector Saturating Doubling Multiply Accumulate or Subtract Long";
		decodable = 1;
	}
	else if (a==0b1100   ) { /* A=1100 */
		ic->mnemonic = "Vector Multiply (integer)";
		decodable = 1;
	}
	else if (u==0 && a==0b1101   ) { /* A=1101 */
		ic->mnemonic = "Vector Saturating Doubling Multiply Long";
		decodable = 1;
	}
	else if (a==0b1110   ) { /* A=1110 */
		ic->mnemonic = "Vector Multiply (polynomial)";
		decodable = 1;
	}

Leave:
	if (!decodable) {
		ret = -1;
	}

	return ret;
}

/* test
 * return: 1, successfully decoded
 * 0 = inconclusive
 * -1: definitely not T32
 *
 * */
static int tsai_handle_thumb_32(struct tsai_handle_insn_param* p) {
	int ret = 0;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	unsigned int insn = p->ic->hex_code;
	unsigned long start = p->start;
	struct tsai_frame_details* fde = p->fde;
	int spshift;
	int decodable = 0;

	/* Thumb32 begin with 0b111, if not match, this definitely is not T32 */
	if (__BITS(insn, 29,31) != 0b111) {
		ret = -1;
		goto Leave;
	}

	{
			unsigned int op1;
			unsigned int op2;
			unsigned insn2;
			op1 = (insn >> 27) & 0b11;
			op2 = (insn >> 20) & 0b1111111;

			switch (op1) {
			case 0: /* this is thumb 16! */
				ret = -1;
				break;
			case 1:
				if (__BITS(op2, 6,6)==1 ) { /* op2 1xxxxxx , Coprocessor, Advanced SIMD, and Floating-point instructions on page A6-251 */
					if ((insn & 0xffff0000) == 0xed2d0000) {
						/* vpush { rlist },
						 * eg ED2D8B02 vpush.64 {d8} */
						unsigned int imm8 = __BITS(insn, 0, 7);
						ic->mnemonic = "vpush.64";
						ar->sp += 8 * (imm8 >> 1);
						TSAI_UNWIND_LOG("%08x %08x %s sp %08x\n", ar->pc, insn, ic->mnemonic, ar->sp);
						ret = 1;
						goto Leave;
					}
					if ((insn & 0xffff0000) == 0xecbd0000) {
						/* eg. ECBD8B06 vpop.64 {d8-d10}  */
						unsigned int imm8 = __BITS(insn, 0, 7);
						ic->mnemonic = "vpop.64";
						switch (p->forward_execution) {
						case EXEC_BACKWARD:
							IGNORE_COND_BLOCK;
							ar->sp -= 8 * (imm8 >> 1);
							break;
						case EXEC_FORWARD:

							ar->sp += 8 * (imm8 >> 1);
							break;
						}
						TSAI_UNWIND_LOG(" %s @%08x %08x %s sp %08x\n", exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, ar->sp);
						ret = 1;
						goto Leave;
					}
				}
				else if (__BITS(op2, 5,5)==1  ) { /* op2 01xxxxx, Data-processing (shifted register) on page A6-243 */

				}
				else if ( (op2 & 0b1100100)== 0b0000100 ) { /* op2 00xx1xx, Load/store dual, load/store exclusive, table branch on page A6-238 */
					unsigned int op_23_24 = __BITS(insn, 23, 24);
					unsigned int op_20_21 = __BITS(insn, 20, 21);
					unsigned int rn = __BITS(insn, 16, 19);

					ic->link_reg_src = rn;
					if (op_23_24==0 ) {
						if (op_20_21==0) {	/* STREX on page A8-690 */
							ic->mnemonic = STR_STREX;
							ret = 1; goto Leave;
						}
						else if (op_20_21==1) { /* LDREX on page A8-432 */
							ic->mnemonic = STR_LDREX;
							ret = 1; goto Leave;
						}
					}
					else if ( (__BIT_MASK_EQ(op_23_24, 0b10, 0b00) && op_20_21==0b10) ||
							  (__BIT_MASK_EQ(op_23_24, 0b10, 0b10) && __BIT_MASK_EQ(op_20_21, 0b01, 0b00 ) )
							)
					{ /* STRD (immediate) on page A8-686 */
						unsigned int rt = __BITS(insn, 12, 15);
						unsigned int rt2 = __BITS(insn, 8, 11);
						unsigned int u = __BIT(insn, 23);
						unsigned int pb = __BIT(insn, 24);
						unsigned int w = __BIT(insn, 21);
						int imm32;
						unsigned int value;
						ic->mnemonic = STR_STRD;
						if (u)
							imm32 = __BITS(insn, 0, 7) << 2;
						else
							imm32 = -__BITS(insn, 0, 7) << 2;

						ic->link_reg = rt;
						ic->link_reg2 = rt2;

						if (rn==ARM_SP_REGNUM) {
							unsigned int sp_addr;
							if (pb==1)
								sp_addr = ar->sp + imm32;
							else
								sp_addr = ar->sp;

							tsai_check_set_register_value_from_stack(p, rt, sp_addr);
							tsai_check_set_register_value_from_stack(p, rt2, sp_addr+4);

							if (pb==0 || w==1) {
								value = ar->R[rn] + imm32;
								tsai_check_set_register_value(p, rn, value);
								fde->pc_most_recent_sp_sub = ar->pc;
								fde->ic_most_recent_sp_sub = ic;
							}
						}
						ret = 1;
						goto Leave;
					}
#if 0
					if ((insn & 0xff7f0000) == 0xe96d0000) {
						/* eg E96D4508 strd r4,r5,[r13,#0xFFFFFFE0]!  */
							ic->mnemonic = STR_STRD;
							/* strd Rt, Rt2, [sp, #+/-imm]{!} */
							if (__BITS(insn, 12, 15) == ARM_LR_REGNUM) {
								tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->lr );
								tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
							}
							if (__BITS(insn, 8, 11) == ARM_LR_REGNUM) {
								tsai_get_user_data_caution(p->mm, ar->sp + 4, 4, &ar->lr);
								tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp+4);
							}
							ar->sp += __BITS(insn, 0, 7) << 2;
							fde->pc_most_recent_sp_sub = ar->pc;
							fde->ic_most_recent_sp_sub = ic;
							ret = 1;
							goto Leave;
					}
					else if ((insn & 0xff7f0000) == 0xe94d0000) {
					/* eg E9CD5E02 strd r5,r14,[r13,#0x8]*/
						/* strd Rt, Rt2, [sp, #+/-imm] */
						unsigned long addr = ar->sp;
						unsigned long offt = ar->sp;
						ic->mnemonic = STR_STRD;
						if (__BIT(insn, 7+16))
							offt += __BITS(insn, 0, 7) << 2;
						else
							offt -= __BITS(insn, 0, 7) << 2;

						if (__BIT(insn, 8+16))
							addr = offt;

						if (__BITS(insn, 12, 15) == ARM_LR_REGNUM) {
							tsai_get_user_data_caution(p->mm, addr, 4, &ar->lr);
							tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, addr);
						}
						if (__BITS(insn, 8, 11) == ARM_LR_REGNUM) {
							tsai_get_user_data_caution(p->mm, addr + 4, 4, &ar->lr);
							tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, addr+4);
						}
						ret = 1;
						goto Leave;
					}
					else
#endif
					if ((insn & 0xFE500000) == 0xE8500000) { /* LDRD T1 11101 , the mask 0xE8500000 covers all pattern in A8.8.72 LDRD (immediate)*/
						/* LDRD<c> <Rt>,<Rt2>,[<Rn>{,#+/-<imm>}]
						 * LDRD<c> <Rt>,<Rt2>,[<Rn>],#+/-<imm>
						 * LDRD<c> <Rt>,<Rt2>,[<Rn>,#+/-<imm>]!
						 * eg E8FD4502 ldrd r4,r5,[r13],#0x8
						 * E8FD4504 ldrd r4,r5,[r13],#0x10 (p=0 w=1 post-index and write back)
						 * */
						int rt = __BITS(insn, 12, 15);
						int rt2 = __BITS(insn, 8, 11);
						int imm = __BITS(insn, 0, 7) << 2;
						int pbit = (insn & (1<<24));
						int wbit = (insn & (1<<21));
						if (!(insn & (1<<23))) {
							imm = -imm; /* u bit, indicates add/sub */
						}

						ic->mnemonic = STR_LDRD;
						ic->link_reg = rt;
						ic->link_reg2 = rt2;
						ic->link_reg_src = __BITS(insn, 16, 19);
						ic->wb = (wbit)?1:0;

						if (ic->link_reg_src==ARM_SP_REGNUM) {
							switch (p->forward_execution) {
							case EXEC_BACKWARD:
								IGNORE_COND_BLOCK;
								if (rt == ARM_FP_REGNUM || rt == ARM_PC_REGNUM)
									ar->pc = tsai_mark_early_out(ic, fde);

								if (rt2 == ARM_FP_REGNUM || rt2 == ARM_PC_REGNUM)
									ar->pc = tsai_mark_early_out(ic, fde);

								if (ic->wb) { /* TODO: it will affect SP, do something! */
									ar->sp -= imm;
								}
								break;
							case EXEC_FORWARD:
								{
									unsigned int tmp_sp = ar->sp + imm;
									tsai_get_user_data_caution(p->mm, tmp_sp+0, 4, &ar->R[rt] );
									ar->reg_extract_mask |= 1 << rt;

									if (rt == ARM_LR_REGNUM || rt == ARM_PC_REGNUM) {
										tsai_frame_details_return_retrieve(fde, ar,ic, rt, tmp_sp+0);
									}
									tsai_get_user_data_caution(p->mm, tmp_sp+4, 4, &ar->R[rt2]);
									ar->reg_extract_mask |= 1 << rt2;
									if (rt2 == ARM_LR_REGNUM || rt2 == ARM_PC_REGNUM) {
										tsai_frame_details_return_retrieve(fde, ar,ic, rt2, tmp_sp+0);
									}
									if (ic->wb) {
										ar->sp = tmp_sp;
									}
								}
								break;
							}

							TSAI_UNWIND_LOG(" %s @%08x %08x %s%s R%d [R%d, #%d(%08x)]%s sp %08x @%d\n",
								exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, ic->condmnemonic,
								ic->link_reg, ic->link_reg_src, imm, imm, ic->wb?"!":"", ar->sp, __LINE__);

						}

						ret = 1;
						goto Leave;
					}
				}
				else if ((op2 & 0b1100100)== 0b0000000) { /* op2 00xx0xx, Load/store multiple on page A6-237 */
					unsigned op8_7 = (insn >> 23) & 0b11;
					unsigned lbit = (insn>>20) &0b1;
					switch (op8_7) {
					case 0b01:
						spshift = 0;
						if (lbit==0) { /* Store Multiple (Increment After, Empty Ascending) STM (STMIA, STMEA) on page A8-664 */


						}
						else {
							unsigned op22_16 = (insn >> 16) & 0b111111;
							if (op22_16==0b111101) { /* Pop Multiple Registers from the stack POP (Thumb) on page A8-534 */
								int rn = 0;
								unsigned int mask = insn & 0xFFFF;
								ic->mnemonic = STR_POP;
								ic->link_reglist = insn & 0xFFFF;

								switch(p->forward_execution) {
								case EXEC_BACKWARD:
									{
										if ((insn & (1 << ARM_PC_REGNUM)) ) { /* pop to R15, so it must be either early out or epilogue */
											fde->pc_b = ar->pc;
											ar->pc = tsai_mark_early_out(ic, fde);
										}
										else {
											IGNORE_COND_BLOCK;
											for (; mask; rn++, mask>>=1) {
												if (mask & 1) {
													ar->sp -= 4;
													spshift += 4;
												}
											}

											TSAI_UNWIND_LOG("%08x %08x %s sp %08x shift %d reglist %08x\n", ar->pc, insn, ic->mnemonic, ar->sp, spshift, ic->link_reglist);

										}

									}
									break;
								case EXEC_FORWARD:
									{
										if (fde->pc_r13_tainted) {
											fde->cannot_continue = 1;
										}
										else {
											for (; mask; rn++, mask>>=1) {
												if (mask & 1) {
													tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->R[rn]);
													ar->reg_extract_mask |= 1<<rn;
													TSAI_UNWIND_LOG("R[%d]=%08x ", rn, ar->R[rn]);
													if (rn==ARM_LR_REGNUM || rn==ARM_PC_REGNUM) {
														tsai_frame_details_return_retrieve(fde, ar, ic, rn, ar->sp);
													}
													ar->sp += 4;
													spshift += 4;
												}
											}
											TSAI_UNWIND_LOG(" %s %s @%d\n", exec_char[p->forward_execution], ic->mnemonic, __LINE__);
										}
									}
								}

								ret = 1;
								goto Leave;
							}
							else { /* Load Multiple (Increment After, Full Descending) LDM/LDMIA/LDMFD (Thumb) on page A8-396 */
								ic->mnemonic = "ldm";
								if ((insn & 0xffff0000) == 0xe8bd0000) { /* LDMIA T1 11001 T2 1110100010 */
									/* ldmia can be detected as `(insn & 0xffd0) == 0xe890', but
									 * we are insterested only in sp! case, which has Rn set to
									 * 1101 */
									/* ldmia sp!, { rlist } */
									int rn = 0;

									if ((insn & (1 << ARM_PC_REGNUM)) ||
											(insn & (1 << ARM_FP_REGNUM))) {
										ar->pc = tsai_mark_early_out(ic, fde);

									} else {
										__asm("bkpt");

										/* ldmi instruction, if instrcution kept "lr" as register
										 * it will consider as the instrcution is not executed
										 * if so, branch will never return in current frame.
										 * skip sp adjustment in this case */
										if (insn & (1 << ARM_LR_REGNUM)) {
											ret = 1;
											goto Leave;
										}

										IGNORE_COND_BLOCK;

										for (; rn <= ARM_PC_REGNUM; rn++) {
											if (insn & (1 << rn))
												ar->sp -= 4;
										}

									}
									ret = 1;
									goto Leave;
								}
							}
						}
						break;
					case 0b10:
						if (lbit==0) {
							unsigned op22_16 = (insn >> 16) & 0b111111;
							if (op22_16==0b101101) { /*PUSH on page A8-538*/
								/* eg: E92D41F0            push    {r4-r8,r14}*/
								int mask, rn = 0;
								int lr = 0;
								spshift = 0;
								ic->mnemonic = STR_PUSH;
								/* registers = '0':M:’000000’:register_list */
								switch(p->forward_execution) {
								case EXEC_BACKWARD:
									mask = insn & 0xFFFF;
									for (rn = 0; mask ; rn++, mask>>=1 ) {
										if (mask & 1) {
											if (tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->R[rn]) )
												goto Leave;
											ar->reg_extract_mask |= 1 << rn;
											TSAI_UNWIND_LOG("R[%d]=%08x \n", rn, ar->R[rn]);
											if (rn == ARM_LR_REGNUM) {
												lr = 1;
												tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
											}
											ar->sp += 4;
											spshift += 4;
										}
									}
									TSAI_UNWIND_LOG(" %08x %08x %s @%d\n", ar->pc, insn, ic->mnemonic, __LINE__ );
									TSAI_UNWIND_LOG("%08x %08x %s sp %08x shift %d @%d\n", ar->pc, insn, ic->mnemonic, ar->sp, spshift, __LINE__);
									break;
								case EXEC_FORWARD:
									break;
								}

								ret = 1;
								goto Leave;
							}
							else { /* Store Multiple (Decrement Before, Full Descending) STMDB (STMFD) on page A8-668 */
								int mask, rn = 0;
								int reg = (insn >> 16) & 0xF;
								int lr = 0;

								ASSERT(__BITS(insn, 29,31)==0b111);

								spshift = 0;
								mask = insn & 0xFFFF;
								ic->mnemonic = "stmdb";
								ic->link_reg = reg;
								ic->link_reglist = mask;
								if (reg==ARM_SP_REGNUM) {
									for (rn = 0; mask ; rn++, mask>>=1 ) {
										if (mask & 1) {
											if (rn == ARM_LR_REGNUM) {
												tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->lr);
												lr = 1;
												tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
											}
											ar->sp += 4;
											spshift += 4;
										}
									}

								}
								TSAI_UNWIND_LOG("%08x %08x %s r%d %08x shift %d @%d\n", ar->pc, insn, ic->mnemonic, reg, ar->sp, spshift, __LINE__);
								ret = 1;
								goto Leave;
							}
						}
						else {

						}

						break;
					}
				}
				else {
					ret = -1;
				}

				break;
			case 2:
				{
					if (insn & 0x8000) { /* bit 15=1, A6.3.4 Branches and miscellaneous control*/
						unsigned int op_14_12;

						if (insn==0xF3AF8000) {
							/* NOP.W */
							ic->mnemonic = STR_NOP;
							ret = 1;
							goto Leave;
						}

						op_14_12 = (insn >> 12) & 0b101;
						if (op_14_12==0b100) { /* BLX exchange*/
							int imm;
							unsigned int addr;
							imm = tsai_sign_extend_imm10h_imm10l(insn);
							addr = (ar->pc & ~1) + 4 + imm;
							addr &= ~3;
							/* target is ARM, align to ARM address */
							ic->link_address = addr;

							fde->pc_functioncall = ar->pc;
							fde->cnt_functioncall++;
							ic->mnemonic = STR_BLX;
						}
						else if (op_14_12==0b101) { /* BL */
							int imm;
							fde->pc_functioncall = ar->pc;
							fde->cnt_functioncall++;
							ic->mnemonic = STR_BL;

							imm = tsai_sign_extend_imm10_imm11(insn);
							ic->link_address = (ar->pc & ~1) + 4 + imm;
						}
						else if (op_14_12==0b000) { /* B, with or without condition */
							int imm;
							unsigned int cond = (insn >> 22) & 0b1111;
							ic->mnemonic = STR_B;
							ic->condmnemonic = ARM_COND[cond];

							imm = tsai_sign_extend_imm6_imm11(insn);
							ic->link_address = (ar->pc & ~1) + 4 + imm;
						}
						else if (op_14_12==0b001) { /* B, Encoding T4 */
							int imm;
							ic->mnemonic = STR_B;
							imm = tsai_sign_extend_imm10_imm11(insn);
							ic->link_address = (ar->pc & ~1) + 4 + imm;
						}
						ret = 1;
						goto Leave;
					}
					else { /* bit 15=0 */
						//__asm("bkpt");
						/* eg F50D7D27                              add     r13,r13,#0x29C*/
						/* for Sub, there are two encoding
						 * T2:
						 * T3 SUBW<c> <Rd>, SP, #<imm12>, eg F6AD0D34 sub r13,r13,#0x834:
						 *
						 */
						if ( ((insn & 0xfbff0000) == 0xf1ad0000) || /* T2 encoding */
								((insn & 0xfbff0000) == 0xf2ad0000)	) /* T3 encoding */
						{
								/* sub.w sp, Rn, #imm */
								int imm;
								ic->mnemonic = STR_SUB;
								ic->link_reg = ARM_SP_REGNUM;
								fde->pc_most_recent_sp_sub = ar->pc;
								fde->ic_most_recent_sp_sub = ic;

								if (__BITS(insn, 8, 11) != ARM_SP_REGNUM) {
									ret = 1;
									goto Leave;
								}
								imm = ((__BITS(insn, 10+16, 10+16) << 11) | /* i bit */
									(__BITS(insn, 12, 14) << 8) |
									__BITS(insn, 0, 7));
								/* depending on encoding, imm value is interpreted differently*/
								if (((insn >>24) & 0xB)==1)
									spshift = kubt_thumb_expand_imm(imm);
								else
									spshift = imm;

								ar->sp += spshift;
								TSAI_UNWIND_LOG("%08x %08x %s sp imm %d(%x) sp %08x\n", ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp);
								ret = 1;
								goto Leave;
						}
						else if ( ((insn & 0xfbf00000) == 0xf1000000) || /* T3 encoding */
								((insn & 0xfbf00000) == 0xf2000000) /* T4 encoding */
								)
						{
								/* F1070938 add r9,r7,#0x38 */
							int imm;
							int rd;
							int rn;
							ic->mnemonic = STR_ADD;
							rn = __BITS(insn, 16, 19);
							rd = __BITS(insn, 8, 11);

							ic->link_reg = rd;
							ic->link_reg_src = rn;
							ic->link_imm = imm;

							imm = ((__BITS(insn, 10+16, 10+16) << 11) | /* i bit*/
								(__BITS(insn, 12, 14) << 8) |
								__BITS(insn, 0, 7));
							if (((insn >>24) & 0xB)==1)
								imm = kubt_thumb_expand_imm(imm);

							switch(p->forward_execution) {
							case EXEC_BACKWARD:
								IGNORE_COND_BLOCK;
								if (tsai_check_set_register_value(p, rd, ar->R[rn] - imm)) {
									ret = -1;
									goto Leave;
								}

								break;
							case EXEC_FORWARD:
								if (tsai_check_set_register_value(p, rd, ar->R[rn] + imm)) {
									ret = -1;
									goto Leave;
								}
								break;
							}

							TSAI_UNWIND_LOG(" %s %08x %08x %s R%d, R%d imm %d(%x) R%d=%08x @%d\n",
								exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, rd, rn, imm, imm,
								rd, ar->R[rd],__LINE__);

							ret = 1;
							goto Leave;
						}
					}
					break;
				}
			case 3:
				{
					if (op2 & 0b1000000) { /* 1xxxxxx Coprocessor, Advanced SIMD, and Floating-point instructions on page A6-251*/
						unsigned int op_29_24 = __BITS(insn, 20, 29);

						if ((op_29_24 & 0B110000)==0B110000) { /* Advanced SIMD data-processing instructions on
page A7-261
						 test case to try
						 FFB2E00F vswp    d14,d15
						 */
							unsigned int u = __BITS(insn, 28,28);
							unsigned int a = __BITS(insn, 19,23);
							unsigned int c = __BITS(insn, 4, 7);


							if ((a & 0b10000)==0b00000) { /* A=0xxxx, Three registers of the same length on page A7-262*/
								decodable = 1;
							}
							else if ((a & 0b10111)==0b10000 && (c & 0b1001)==0b0001) { /* A=1x000 C=0xx1 One register and a modified immediate value on page A7-269*/
								decodable = 1;
							}
							else if ((a & 0b10111)==0b10001 && (c & 0b1001)==0b0001) { /* A=1x001 C=0xx1 Two registers and a shift amount on page A7-266*/
								decodable = 1;
							}
							else if ((a & 0b10110)==0b10010 && (c & 0b1001)==0b0001) { /* A=1x01x C=0xx1 Two registers and a shift amount on page A7-266*/
								decodable = 1;
							}
							else if ((a & 0b10100)==0b10100 && (c & 0b1001)==0b0001) { /* A=1x1xx C=0xx1 Two registers and a shift amount on page A7-266*/
								decodable = 1;
							}
							else if ((a & 0b10000)==0b10000 && (c & 0b1001)==0b1001) { /* A=1xxxx C=1xx1 Two registers and a shift amount on page A7-266*/
								decodable = 1;
							}
							else if ((a & 0b10100)==0b10000 && (c & 0b0101)==0b0000) { /* A=1x0xx C=x0x0 Three registers of different lengths on page A7-264*/
								decodable = (tsai_ASIMD_three_reg_diff_len(p) != -1);
							}
							else if ((a & 0b10110)==0b10100 && (c & 0b0101)==0b0000) { /* A=1x10x C=x0x0 Three registers of different lengths on page A7-264*/
								decodable = (tsai_ASIMD_three_reg_diff_len(p) != -1);
							}
							else if ((a & 0b10100)==0b10000 && (c & 0b0101)==0b0100) { /* A=1x0xx C=x1x0 Two registers and a scalar on page A7-265 */
								decodable = 1;
							}
							else if ((a & 0b10110)==0b10100 && (c & 0b0101)==0b0100) { /* A=1x10x C=x1x0 Two registers and a scalar on page A7-265 */
								decodable = 1;
							}
							else if (u==0 && (a & 0b10110)==0b10110 && (c & 0b0001)==0b0000) {
								/* u = 0, A=1x11x C=xxx0 Vector Extract, VEXT on page A8-890 */
								decodable = 1;
							}

							if (!decodable) {
								ret = -1;
								goto Leave;
							}
						}
					}
					else if (op2 & 0b0100000) {
						/*
						010xxxx - Data-processing (register) on page A6-245
						0110xxx - Multiply, multiply accumulate, and absolute difference on page A6-249
						0111xxx - Long multiply, long multiply accumulate, and divide on page A6-250
						*/

					}
					else {
						/*
							000xxx0 - Store single data item on page A6-242
							00xx001 - Load byte, memory hints on page A6-241
							00xx011 - Load halfword, memory hints on page A6-240
							00xx101 - Load word on page A6-239
							00xx111 - UNDEFINED
						*/


						if ((op2 & 0b1110001) == 0) { /* 000xxx0 - Store single data item on page A6-242 */
							unsigned int op1_21_23 = __BITS(insn,21,23);
							unsigned int op2_6_11 = __BITS(insn,6,11);

							switch(op1_21_23) {
							case 0b010:
								if ( ((op2_6_11 & 0b100100)==0b100100) ||
										((op2_6_11 & 0b100100)==0b100100)
									)
								{
									if ((insn & 0xfff00000) == 0xf8400000) {
										/* STR<c>.w <Rt>,[<Rn>,#+/-<imm8>]! */
									/* eg F84D4D14 str r4,[r13,#0xFFFFFFEC]!
									 *
									 * */
									int imm;
									unsigned int rt,rn;
									unsigned int u;
									unsigned int pbit;
									unsigned int wbit;
									rt = __BITS(insn, 12, 15);
									rn = __BITS(insn, 16, 19);
									u = __BITS(insn, 9, 9);
									pbit = __BITS(insn, 10, 10);
									wbit = __BITS(insn, 8, 8);

									ic->mnemonic = STR_STR;
									ic->link_reg = rt;
									ic->link_reg_src = rn;
									ic->wb = wbit?1:0;
									imm = __BITS(insn, 0, 7);
									if (!u) {
										imm = -imm;
									}

									switch (p->forward_execution) {
									case EXEC_BACKWARD:
										{
											if (rn == ARM_SP_REGNUM) {
												unsigned int tmp_sp;
												/* post-index str.... not encountered yet
												eg. F84DB928 str r11,[r13],#0xFFFFFFD8
												*/
												if (tsai_bkpt_disasm) {
													ASSERT(pbit);
												}

												if (ic->wb && pbit) {
													tmp_sp = ar->sp;
												}
												else {
													if (rt==ARM_SP_REGNUM)
														tmp_sp = ar->sp - imm;
													else
														tmp_sp = ar->sp + imm;
												}

												if (rt == ARM_LR_REGNUM) {
													tsai_get_user_data_caution(p->mm, tmp_sp, 4, &ar->lr);
													tsai_frame_details_return_retrieve(fde,ar,ic, ARM_LR_REGNUM, tmp_sp);
												}
												if (ic->wb) {
													ASSERT(imm < 0);
													ar->sp -= imm;
												}

												TSAI_UNWIND_LOG(" %08x %08x %s%s R%d [R%d, #%d(%08x)]%s sp %08x @%d\n", ar->pc, insn,
													ic->mnemonic, ic->condmnemonic,
													ic->link_reg, ic->link_reg_src, imm, imm, ic->wb?"!":"", ar->sp, __LINE__);
											}
										}
										break;
									default:
										TSAI_UNWIND_LOG(" pc %08x NO EXECUTION \n", ar->pc);
									}
									ret = 1;
									goto Leave;
									}
								}
								else if ( (op2_6_11 )==0b000000  ) { /* 000000 Store Register STR (register) on page A8-676 */
									ic->mnemonic = STR_STR;
									ret = 1;
									goto Leave;

								}
								else if ( (op2_6_11 & 0b111100)==0b111000  ) { /* 1110xx Store Register Unprivileged STRT on page A8-706 */
									ic->mnemonic = STR_STR;
									ret = 1;
									goto Leave;
								}
								else {
									ret = -1;
									goto Leave;
								}
								break;
							case 0b100: /* STRB (immediate, Thumb) on page A8-678 */
								{
									 /* F884B064 strb r11,[r4,#0x64]
									 * */
									int rn = __BITS(insn, 16, 19);
									int rt = __BITS(insn, 12, 15);
									ic->mnemonic = STR_STRB;
									ic->link_reg_src = rn;
									ic->link_reg = rt;
									ic->link_imm = __BITS(insn, 0, 11);

									switch (p->forward_execution) {
									case EXEC_BACKWARD:
										if (rn==ARM_SP_REGNUM) {
											unsigned int addr;
											addr = ar->sp + ic->link_imm;
											tsai_get_user_data_caution(p->mm, addr, 4, &ar->R[rt]);
											TSAI_UNWIND_LOG(" R[%d]=%08x @%d\n", rt, ar->R[rt], __LINE__);
										}
										break;
									case EXEC_FORWARD:
										break;
									default:
										;
									}

									ret = 1;
									goto Leave;

								}
								break;
							default:
								;
							} /* switch(op1_21_23) */

							if ((insn & 0xfff00000) == 0xf8c00000) {
								/* eg F8CDB02C str r11,[r13,#0x2C] (no write back) */
								unsigned int rt,rn;
								unsigned int imm;
								unsigned int u;
								rt = __BITS(insn, 12, 15);
								rn = __BITS(insn, 16, 19);

								ic->mnemonic = STR_STR;
								ic->link_reg = rt;
								ic->link_reg_src = rn;
								imm = __BITS(insn, 0, 11);

								switch (p->forward_execution) {
								case EXEC_BACKWARD:
									{
										unsigned int value;
										if (rn == ARM_SP_REGNUM) {
											unsigned int tmp_sp;

											if (rt==ARM_SP_REGNUM) {
												tmp_sp = ar->sp - imm;
											}
											else {
												tmp_sp = ar->sp + imm;
											}

											if (rt == ARM_SP_REGNUM) {
												/* considering this case, it is pointless to retrieve SP out of stack
												 * F8CDD018            str     r13,[r13,#0x18]
												 * */
											}
											else {
												tsai_check_set_register_value_from_stack(p, rt, tmp_sp);
											}

											TSAI_UNWIND_LOG(" %08x %08x %s%s R%d [R%d, #%d(%08x)]%s sp %08x @%d\n", ar->pc, insn, ic->mnemonic, ic->condmnemonic,
												ic->link_reg, ic->link_reg_src, imm, imm, ic->wb?"!":"", ar->sp, __LINE__);
										}
									}
									break;
								default:
									TSAI_UNWIND_LOG(" pc %08x NO EXECUTION \n", ar->pc);
								}
								ret = 1;
								goto Leave;
							}


						if (((insn & 0xfff00000) == 0xf8500000) ||
								((insn & 0xfff00000) == 0xf8d00000)) {
							/* F8DDB020 ldr r11,[r13,#0x20]  */
							unsigned int rn, rt;
							int imm;
							unsigned int u;
							unsigned int pbit;
							unsigned int wbit;

							ic->mnemonic = STR_LDR;
							ic->link_reg_src = rn = __BITS(insn, 16, 19);
							ic->link_reg = rt = __BITS(insn, 12, 15);
							if (__BITS(insn, 23, 23)) { /* imm 12*/
								u = 1;
								pbit = 1;
								wbit = 0;
								imm = __BITS(insn, 0, 11);
							}
							else { /* imm8 */
								u = __BITS(insn, 9, 9);
								pbit = __BITS(insn, 10, 10);
								wbit = __BITS(insn, 8, 8);
								imm = __BITS(insn, 0, 7);
							}
							ic->wb = wbit?1:0;

							switch(p->forward_execution) {
							case EXEC_BACKWARD:
								if (rn == ARM_SP_REGNUM) {
									if (rt == ARM_PC_REGNUM) {
										ar->pc = tsai_mark_early_out(ic, fde);
										ret = 1;
										goto Leave;
									}
									/* TSAI: LDR to R14 may only be using R14 as general purpose register, not necessarily means LR */
									IGNORE_COND_BLOCK;
									if (wbit) {
										if (u)
											ar->sp -= __BITS(insn, 0, 7);
										else
											ar->sp += __BITS(insn, 0, 7);
									}
								}
								break;
							case EXEC_FORWARD:

							default:
								TSAI_UNWIND_LOG(" pc %08x NO EXECUTION \n", ar->pc);

							}

							ret = 1;
							goto Leave;
						}


					}
					else if ((op2 & 0b1100111) == 0b0000001) { /*00xx001 - Load byte, memory hints on page A6-241*/
						unsigned int op23_24 = __BITS(insn, 23, 24);
						unsigned int op_6_11 = __BITS(insn, 6, 11);
						unsigned int rt = __BITS(insn, 12, 15);
						unsigned int rn = __BITS(insn, 16, 19);
						ic->mnemonic = STR_LDRB;
						ic->link_reg = rt;
						ic->link_reg_src = rn;
						ret = 1;
						goto Leave;

					}
					else if ((op2 & 0b1100111) == 0b0000101) { /* 00xx101 Load word on page A6-239 */
						ic->mnemonic = STR_LDR;
						ret = 1;
						goto Leave;
					}
				}
				break;
				} /* end of case 3*/
			} /* end of switch op1 */
		} /* End of T32*/

	/* copied from kdebugd */
	if ((insn & 0xfe7f0000) == 0xe82d0000) {
			/*  stm{db} sp!, { rlist } */
			int rn = 0;
			/* pc - IS_THUMB_ADDR(pc) + 2 */
			__asm("bkpt");
			ic->mnemonic="stm";
			for (; rn <= ARM_LR_REGNUM; rn++) {
				if (!(insn & (1 << rn)))
					continue;
				if (rn == ARM_LR_REGNUM) {
					tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->lr);
					tsai_frame_details_return_retrieve(fde,ar,ic, ARM_LR_REGNUM, ar->sp);
				}
				ar->sp += 4;
			}
			if (insn & (1 << ARM_LR_REGNUM))
				ar->pc = tsai_mark_early_out(ic, fde);

			ret = 1;
			goto Leave;
	}

 		/*** THUMB32 NEON instructions ***/
	else if ((insn & 0xfe2f0000) == 0xec2d0000) {
					/* vstm{ia,db} sp!, { rlist } */
					/* pc - IS_THUMB_ADDR(pc) + 2 */
/* a counter case ECAD8DBC stc     p13,c8,[r13],#+0x2F0 */
					unsigned int i = __BITS(insn, 0, 7);
					__asm("bkpt");
					ar->sp += 8 * i;
					ret = 1;
					goto Leave;
	} else if ((insn & 0xfe3f0000) == 0xec3d0000) {
		/* vldm{ia,db} sp!, { rlist } */
		unsigned int i = __BITS(insn, 0, 7);
		__asm("bkpt");
		if (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) {

			TSAI_UNWIND_LOG(" ignore %08x %s due to KUBT_FLAG_FUNC_EPILOGUE \n", ar->pc, ic->mnemonic);

			goto Leave;
		}
		ar->sp -= 8 * i;
		ret = 1;
		goto Leave;
	}
Leave:
	return ret;
}

/* this function uses 1872 bytes stack! */
static int tsai_handle_thumb_insn(struct tsai_handle_insn_param* p) {
	int ret;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	unsigned int insn = p->ic->hex_code;
	unsigned long start = p->start;
	struct tsai_frame_details* fde = p->fde;
	int spshift;

Retry:
	ret = 0;
	if (p->armthumb==2 ) {
		ret = tsai_handle_thumb_32(p);
		if (ret == 1)
			goto Leave;

		if (ret == 0) { /* inconclusive, do a further test */
			unsigned int pc_saved = ar->pc;
			unsigned int tmp_insn;
			struct tsai_instruction_cache local_ic;
			int readerr;
			int ret2;
			local_ic = *ic;
			local_ic.PC = ar->pc = ar->pc-2;
			readerr = tsai_get_user_data_caution(p->mm, PC_NO_THUMB(ar->pc), 4, &tmp_insn);

			if (readerr) {
				ret2 = 0;
			}
			else {
				local_ic.hex_code = (tmp_insn & 0x0000FFFF) << 16 | (tmp_insn & 0xFFFF0000) >> 16;
				p->ic = &local_ic;
				ret2 = tsai_handle_thumb_32(p);
			}

			if (ret2==1) {
				/*this should be a t16 instruction instead of t32 */
				ar->pc = pc_saved + 2;
				ic->PC = ar->pc;
				ic->hex_code = ic->hex_code & 0xFFFF;
				ic->armthumb = 1;
				p->ic = ic;
				p->armthumb = ic->armthumb;
				goto Retry;
			}
			else {
				/* when entering here, it's not T32+T16, but still could be T16+T16, do an exam to filter such case*/
				int ret_t1;
				int ret_t2;
				ar->pc = pc_saved;
				local_ic.PC = ar->pc;
				local_ic.hex_code = (ic->hex_code & 0xFFFF0000) >> 16;
				local_ic.armthumb = 1;
				p->armthumb = 1;
				ret_t1 = tsai_handle_thumb_insn(p);

				if (ret_t1==1) {
					ar->pc = pc_saved+2;
					local_ic.PC = ar->pc;
					local_ic.hex_code = ic->hex_code & 0x0000FFFF;
					local_ic.armthumb = 1;
					p->armthumb = 1;
					__asm("bkpt");
					ret_t2 = tsai_handle_thumb_insn(p);

					if (ret_t2==1) {
						p->ic = ic;
						ret = 1;
						goto Leave;
					}
				}

				p->ic = ic;
				ar->pc = pc_saved;
				p->armthumb = 2;
			}
		}
	}
	else
	{ /* T16 */
		unsigned int op1;
		op1 = (insn >> 10) & 0b111111;

		if ((op1 & 0b110000)==0) {
			/* 00xxxx, Shift (immediate), add, subtract, move, and compare on page A6-224*/
			unsigned op_9_13 = __BITS(insn, 9, 13);
			if ((op_9_13 & 0b11100)==0b11000) { /* Add 8-bit immediate ADD (immediate, Thumb) on page A8-306 */
				/* Encoding T2 */
				int rn = __BITS(insn, 8, 10);
				ic->mnemonic = STR_ADD;
				ic->link_reg = rn;
				ic->link_imm = insn & 0xFF;
				switch (p->forward_execution) {
				case EXEC_FORWARD:
					ar->R[rn] += ic->link_imm;
					TSAI_UNWIND_LOG(" %s R%d, #%08x = %08x @%d\n", ic->mnemonic, rn, ic->link_imm, ar->R[rn], __LINE__);
					ret = 1;
					goto Leave;
					break;
				}
			}
		}
		switch (op1) {
		/* 00xxxx handled in if above */
		case 0b010001: /* A6.2.3 Special data instructions and branch and exchange */
			{
				unsigned int op_9_6 = (insn >> 6) & 0b1111;
				switch(op_9_6) {
				case 0b1000: /* MOV (register, Thumb) on page A8-486 */
				case 0b1001:
				case 0b1010:
				case 0b1011: /*MOV (register, Thumb) on page A8-486*/
					{
						int rm = __BITS(insn, 3,6);
						int rd = ((insn & 0x80)>>4) | __BITS(insn, 0, 2);
						ic->mnemonic = "mov";
						ic->link_reg = rd;
						ic->link_reg_src = rm;

						switch (p->forward_execution) {
						case EXEC_FORWARD:
							ar->R[rd] = ar->R[rm];
							if (rd==ARM_SP_REGNUM) {
								if (ar->reg_extract_mask_prv & 1<<rm) {
									TSAI_UNWIND_LOG(" @%08x %s R%d=R%d=%08x @%d\n",
											ar->pc, ic->mnemonic, ic->link_reg, ic->link_reg_src, ar->R[rd], __LINE__);
								}
								else {
									fde->pc_r13_tainted = ar->pc;
									TSAI_UNWIND_LOG(" @%08x R13 tainted by %s %d %d @%d\n",
											ar->pc, ic->mnemonic, ic->link_reg, ic->link_reg_src, __LINE__);
								}
							}
						}

						ret = 1;
						goto Leave;
					}
					break;
				case 0b1100:
				case 0b1101: /* BX */
					{
						unsigned int reg = (insn >> 3) & 0b1111;
						p->ic->mnemonic = STR_BX;
						p->ic->link_reg = reg;

						switch (p->forward_execution) {
						case EXEC_BACKWARD:
							tsai_mark_early_out(ic, fde);
							break;
						case EXEC_FORWARD:
							{
								if (reg==ARM_LR_REGNUM) {
									int allow_r14 = 0;
									if (fde->pc_r14_retrieve)
										allow_r14 = 1;
									else {
										if (p->call_depth==0)
											allow_r14 = 1;
									}

									if (allow_r14) {
										ar->pc = ar->lr;
										tsai_frame_details_return_retrieve(fde, ar, ic, ARM_PC_REGNUM, fde->st_r14_retrieve);
									}
								}
								else {

								}
								TSAI_UNWIND_LOG(" %s %s%s r%d\n",
										exec_char[p->forward_execution], ic->mnemonic, ic->condmnemonic, ic->link_reg);
							}
							break;
						}

						ret = 1;
						goto Leave;
					}
					break;
				case 0b1110:
				case 0b1111:/* BLX register */
					{
						unsigned int reg = (insn >> 3) & 0b1111;
						p->ic->mnemonic = STR_BLX;
						p->ic->link_reg = reg;
						fde->pc_functioncall = ar->pc;
						fde->cnt_functioncall++;
						/* BLX R14 doesn't make sense, because if it's returning it wouldn't use BL/BLX */
						ret = 1;
						goto Leave;
					}
					break;
				}
			}
			break;
		case 0B101101:
		{ /* PUSH 0B 1011010 */
			if ((insn & 0xfe00) == 0xb400) {
				/* push { rlist } */
				/* __BITS 0-7 contain a mask for registers R0-R7.
				 * Bit 8 says whether to save LR (R14).*/
				/* eg. B5F0 push    {r4-r7,r14} */
				int mask, rn = 0;
				int lr = 0;
				ic->mnemonic = STR_PUSH;
				/* registers = '0':M:’000000’:register_list */
				mask = insn & 0x1ff;
				for (rn = 0; mask ; rn++, mask>>=1) {
					int trans_rn = rn;
					if (mask & 1) {
						if (rn==8)
							trans_rn = ARM_LR_REGNUM;
						tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->R[trans_rn]);
						ar->reg_extract_mask |= 1 << trans_rn;
						TSAI_UNWIND_LOG("R[%d]=%08x \n", trans_rn, ar->R[trans_rn]);

						if (trans_rn == ARM_LR_REGNUM) {
							lr = 1;
							tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
						}
						ic->link_reglist |= 1<< trans_rn;
						ar->sp += 4;
					}
				}
				TSAI_UNWIND_LOG(" %08x %08x %s sp %08x @%d\n", ar->pc, insn, ic->mnemonic, ar->sp, __LINE__ );
				ret = 1;
				goto Leave;
			}
			break;
		}
		case 0B101111:
		{
			if ((insn & 0xfe00) == 0xbc00) { /* POP 1011110 */
				/* pop { rlist } */
				int mask, rn = 0;
				ic->mnemonic = STR_POP;
				ic->link_reglist = (insn & 0xFF) | ((insn & 0x100)<<7);
				/* registers = P:’0000000’:register_list */
				insn = insn & 0xffff;
				mask = insn & 0x1ff;
				/* reglist can only include the Lo registers and the pc */
				switch (p->forward_execution) {
				case EXEC_BACKWARD:
					{
						if (mask & (1 << 8)) {
							ar->pc = tsai_mark_early_out(ic, fde);
						} else {
							mask = __BITS(insn, 0, 7);

							IGNORE_COND_BLOCK;

							for (; rn <= 7 ; rn++) {
								if (mask & (1 << rn))
									ar->sp -= 4;
							}

							TSAI_UNWIND_LOG("@%08x %s sp %08x @%d\n", ar->pc, ic->mnemonic, ar->sp, __LINE__ );
						}
					}
					break;
				case EXEC_FORWARD:
					{
						unsigned int real_r;
						//__asm("bkpt");
						if (fde->pc_r13_tainted) {
							fde->cannot_continue = 1;
						}
						else {
							for (; rn <= 8 ; rn++) {
								if (mask & (1 << rn)) {
									if (rn < 8)
										real_r = rn;
									else
										real_r = rn + 7;

									tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->R[real_r]);
									ar->reg_extract_mask |= 1 << real_r;
									TSAI_UNWIND_LOG("R[%d]=%08x @%d\n", real_r, ar->R[real_r], __LINE__);
									if (!(rn < 8)) { /* pop {pc} */
										tsai_frame_details_return_retrieve(fde, ar, ic, ARM_PC_REGNUM, ar->sp);
									}
									ar->sp += 4;
								}
							}
						}
					}
					break;
				}

				ret = 1;
				goto Leave;
			}
			if (insn==0xBF00) { /* NOP */
				p->ic->mnemonic = STR_NOP;
				goto Leave;
			}
		 break;
		}
		case 0b101110: /* could be CBNZ */
			goto ExamineCBZ;
			break;
		case 0B101100: /* either SUB (SP minus immediate) or ADD (SP plus immediate) */
		{
			{
				/* example: this usually indicates begin of a function, so take special
	B5F0                push    {r4-r7,r14}
	B089                sub     sp,sp,#0x24
				 * */
				spshift = 0;
				if ((insn & 0xff80) == 0xb080) { /* A8.8.225 SUB (SP minus immediate), op1=101100 */
					/* sub sp, #imm */
					ic->mnemonic = STR_SUB;
					ic->link_reg = 13;
					spshift = ((insn & 0x7f) << 2);
					ar->sp += spshift;
					fde->pc_most_recent_sp_sub = (ar->pc) & ~1;
					fde->ic_most_recent_sp_sub = ic;
					TSAI_UNWIND_LOG("%08x %08x %s sp imm %d(%x) sp %08x @%d\n", ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp, __LINE__);
					ret = 1;
					goto Leave;
				}
				else if ((insn & 0xff80) == 0xb000) { /* ADD 0B 0001110 or 00110 */
					/* add sp, #imm */
					ic->mnemonic = STR_ADD;
					ic->link_reg = 13;
					spshift = ((insn & 0x7f) << 2);

					switch(p->forward_execution) {
					case EXEC_BACKWARD:
						{
							IGNORE_COND_BLOCK;
							ar->sp -= spshift;
						}
						break;
					case EXEC_FORWARD:
						{
							ar->sp += spshift;
						}
						break;
					}

					TSAI_UNWIND_LOG(" %s %08x %08x %s sp imm %d(%x) sp %08x @%d\n",
						exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp, __LINE__);
					ret = 1;
					goto Leave;
				}

ExamineCBZ: /* op1 1011xx*/
				if ((__BITS(insn, 8,15) & 0b11110101)==0b10110001) { /* CBZ or CBNZ */
					unsigned int bit11=__BITS(insn, 11,11);
					unsigned int biti = __BITS(insn,9,9);
					int imm;

					if (bit11)
						ic->mnemonic = STR_CBNZ;
					else
						ic->mnemonic = STR_CBZ;

					ic->link_reg_src = __BITS(insn, 0, 2);
					imm = __BITS(insn, 3, 7)<<1 | biti<<6;
					/* imm can only be positive, it is unsigned*/

					ic->link_address = (ic->PC & ~1) + 4 + imm;
					ret = 1;
					goto Leave;
				}

				break;
			}
		}
		case 0b110100:
		case 0b110101:
		case 0b110110:
		case 0b110111: /* UDF/SVC/conditional branch */
			{
				unsigned int opc = __BITS(insn, 8, 11);
				if (opc==0b1110) { /* Undefined! */
					ic->mnemonic = "udf";
				}
				else if (opc==0b1111) { /* SVC */
					ic->mnemonic = "svc";
				}
				else {
					/* A8.8.18 B */
					int imm8;
					ic->mnemonic = STR_B;
					ic->condmnemonic = ARM_COND[opc];
					imm8 = __BITS(insn, 0, 7);
					if (imm8 & 0x80) {
						imm8 |= 0xFFFFFF00;
					}
					ic->link_address = (ar->pc & ~1) + 4 + (imm8 << 1);
				}

				ret = 1;
				goto Leave;
			}
			break;
		case 0b111000: /* unconditional B */
		case 0b111001: /* unconditional B */
			{
				unsigned int imm11;
				ic->mnemonic = STR_B;
				imm11 = insn & 0x07FF;
				ic->link_address = imm11<<1;
				ret = 1;
				goto Leave;
			}
			break;
		}
	}

	/* if not found in the handler, check if it's a Thumb16 being mistaken for Thumb32?? */
	if (p->armthumb==2 && p->forward_execution==EXEC_BACKWARD) {
		if ((ret==-1) || (insn>>16)==0xFFFF) {
			struct TMP_TRY_T16 {
				struct tsai_handle_insn_param param;
				struct tsai_intermediate_regs ar_stack;
				struct tsai_instruction_cache_mgr im;
				struct tsai_instruction_cache* local_ic;
			};
			struct TSAI_FAKE_STACK_TICKET ticket;
			struct TMP_TRY_T16* ts = (struct TMP_TRY_T16*)tsai_fake_stack_get(sizeof(struct TMP_TRY_T16), &ticket);
			int leave = 0;

			tsai_instruction_cache_init(&ts->im);

			ts->local_ic = tsai_instruction_cache_obtain(&ts->im);
					ts->param.ic = ic; ts->param.start = start;
			//__asm("bkpt");

			ts->param = *p;
			ts->ar_stack = *ar;

			ts->param.ar = &ts->ar_stack;
			ts->ar_stack.pc = ar->pc + 2;
			ts->local_ic->hex_code = insn & 0xFFFF;
			ts->local_ic->PC = ar->pc + 2;
			ts->local_ic->armthumb = 1;
			ts->param.ic = ts->local_ic;
			ts->param.armthumb = 1;
			tsai_handle_thumb_insn(&ts->param);

			if (ts->local_ic->mnemonic) {
				struct tsai_instruction_cache_mgr* pm = ic->pm;
				*ic = *ts->local_ic;
				ic->pm = pm;
				*ar = ts->ar_stack;
				TSAI_UNWIND_LOG("%08x %08x %s appears to be Thumb16\n", ar->pc, ic->hex_code, ic->mnemonic);
				ret = 1;
				leave = 1;
			}
			tsai_fake_stack_put(sizeof(struct TMP_TRY_T16), &ticket);
			if (leave)
				goto Leave;
		}
	}


Leave:
	return ret;
}

static inline const char* tsai_arm_condition(unsigned int insn) {
	unsigned int cond = insn >> 28;
	return ARM_COND[cond];
}

static unsigned tsai_calculate_pc_adjust_value(unsigned int pc, int is_thumb) {
	return ((is_thumb)?((pc & ~1) + 4):(pc + 8));
}
static unsigned tsai_calculate_link_address(unsigned int pc, int is_thumb, int imm) {
	unsigned int ret;
	if (is_thumb)
		ret = (pc & ~1) + 4 + imm;
	else
		ret = pc + 8 +imm;
	return ret;
}

/* handle ARM mode instructions */
static int tsai_handle_arm_insn(struct tsai_handle_insn_param* p)
{
	int ret = 0;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	unsigned int insn = p->ic->hex_code;
	unsigned long start = p->start;
	struct tsai_frame_details* fde = p->fde;
	int spshift;
	unsigned int cond;

	unsigned opc_code;
	unsigned arm_27_25 = (insn >> 25) & 0B111;

	cond = insn >> 28;
	ic->condmnemonic = ARM_COND[cond];

	/* check FA0044A7 blx     0x4101AEF0 */

	/* when cond is 0xF */
	if (cond==0xF) {
		switch(arm_27_25) {
		case 0B101: /*BL, BLX (immediate) on page A8-348*/
			{
				int imm;
				unsigned int s = (insn >> 23) & 1;
				imm = (insn & 0x00FFFFFF) << 2;
				imm |= ((insn >> 24) & 1) << 1; /* H bit */

				if (s) {
					imm |= 0xFC000000; /* make it signed value */
				}

				fde->pc_functioncall = ar->pc;
				fde->cnt_functioncall++;
				ic->mnemonic = STR_BLX;
				ic->link_address = tsai_calculate_link_address(ar->pc, 0, imm);
				goto Leave;
			}
			break;
		}
	}

	switch(arm_27_25) {
	case 0B000: /* Data-processing and miscellaneous instructions on page A5-196. */
		{
			unsigned int op_24_20 = (insn >> 20) & 0B11111;
			unsigned int op_7_4 = __BITS(insn, 4,7);
			if ( (op_24_20 & 0b11001)!=0b10000)
			{ /* not 10xx0 xxx0 Data-processing (register) on page A5-197,
								0xx1 Data-processing (register-shifted register) on page A5-198 */

							if ((op_7_4 & 0b0001)==0b0000)
							{
								/* A5.2.1 Data-processing (register) */
								if ((op_24_20 & 0b11110)==0b00000) { /*0000x - A8.8.14 AND (register)*/
									ic->mnemonic = "and";
									goto Leave;
								}
								else if ((op_24_20 & 0b11110)==0b01000) { /* ADD (register, ARM) on page A8-312 */
									unsigned int rt = __BITS(insn, 12, 15);
									unsigned int rn = __BITS(insn, 16, 19);
									unsigned int rm = __BITS(insn, 0, 3);
									ic->mnemonic = STR_ADD;
									ic->link_reg = rt;
									ic->link_reg_src = rn;

									switch (p->forward_execution) {
									case EXEC_BACKWARD:
										if (rt==ARM_SP_REGNUM) {
											fde->pc_r13_tainted = ar->pc;
											TSAI_UNWIND_LOG("R13 value TAINTED %08x %08x %s%s R%d R%d R%d\n",
													ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, rn, rm);
										}
										break;
									case EXEC_FORWARD:
										{
											unsigned int vrn = (rn==ARM_PC_REGNUM)? tsai_calculate_pc_adjust_value(ar->R[rn], false): ar->R[rn];
											unsigned int vrm = (rm==ARM_PC_REGNUM)? tsai_calculate_pc_adjust_value(ar->R[rm], false): ar->R[rm];
											ar->R[rt] = vrn+vrm;
											TSAI_UNWIND_LOG("[fwe]%08x %08x %s%s R%d value %08x \n",
													ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, ar->R[rt]);
										}
										break;
									}

									goto Leave;
								}
								else if ((op_24_20 & 0b11110)==0b00100) { /* A8.8.223 SUB (register) */
									/* eg E04DD003 sub r13,r13,r3*/
									unsigned int rt = __BITS(insn, 12, 15);
									unsigned int rn = __BITS(insn, 16, 19);
									unsigned int rm = __BITS(insn, 0, 3);
									ic->mnemonic = STR_SUB;
									ic->link_reg = rt;
									ic->link_reg_src = rn;

									if (rt==ARM_SP_REGNUM) {
										fde->pc_r13_tainted = ar->pc;
										TSAI_UNWIND_LOG("R13 value TAINTED %08x %08x %s%s R%d R%d R%d @%d\n",
												ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, rn, rm, __LINE__);
									}

									goto Leave;
								}
								else if ((op_24_20 & 0b11110)==0b11010) {
									/* eg E1A0B00D cpy     r11,r13*/
									unsigned int rt = __BITS(insn, 12, 15);
									unsigned int rm = __BITS(insn, 0, 3);
									ic->mnemonic = "mov";
									ic->link_reg = rt;
									ic->link_reg_src = rm;

									if (rt==ARM_PC_REGNUM) {
										/* mov pc */
										ar->pc = tsai_mark_early_out(ic, fde);
										fde->pc_b = ar->pc;
									}
									else if (rt==ARM_FP_REGNUM && rm==ARM_SP_REGNUM){
										/* cpy     r11,r13 */
										if (fde->pc_r13_tainted) {
											ar->sp = ar->fp;
											TSAI_UNWIND_LOG("R13 %08x value RETRIEVED from %08x %08x %s%s R%d(%08x) R%d(%08x)\n",
												ar->sp, ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, ar->fp, rm, ar->sp);
										fde->pc_r13_tainted = 0;
										}
									}
									ret = 1;
									goto Leave;
								}
							}

							/* bit 4 set= Data-processing (register-shifted register)*/
							if ((op_7_4 & 0b1001)==0b0001)
							{
								if ((op_24_20 & 0b11110)==0b00000) { /*0000x - Bitwise AND AND (register-shifted register) on page A8-328*/
									ic->mnemonic = "and";
									goto Leave;
								}

							}
			}

			if ((op_24_20 & 0b11001)==0b10000)
			{ /* 10xx0: Miscellaneous instructions on page A5-207 */
				unsigned int op_6_4 = (insn >> 4) & 0B111;
				if (op_6_4 == 0B001) { /* BX */
					if ((insn & 0x0ffffff0) == 0x012fff10) { /* bit [31..28]cond [3..0] rm */
						/*eg 312FFF1E            bxcc    r14*/
						/* bx<c><q> */
						int regnum = insn & 0xF;
						ic->mnemonic = STR_BX;
						ic->link_reg = regnum;

						switch (p->forward_execution) {
						case EXEC_BACKWARD:
							{
								if (regnum==ARM_LR_REGNUM) {
									if (ic->condmnemonic==STR_AL) { /* if it's conditional like BXEQ, it's not really conditional black*/
										p->fde->pc_bxr14 = ar->pc;
										ar->pc = tsai_mark_early_out(ic, fde);
									}
								}
								else if (ic->condmnemonic==STR_AL) { /* BX any register still make it end of a block */
									tsai_mark_early_out(ic, fde);
								}
							}
							break;
						case EXEC_FORWARD:
							{
								if (regnum==ARM_LR_REGNUM) {
									ar->pc = ar->lr;
									fde->f_pc_set = 1;
								}
							}
							break;
						}

						ret = 1;
						goto Leave;
					}
				}
				else if (op_6_4 == 0B011) { /* A8.8.26 BLX (register)*/
					/* eg. E12FFF33            blx     r3*/
					if ((insn & 0x0ffffff0) == 0x012fff30) {
						int regnum = __BITS(insn, 0, 3);
						ic->mnemonic = STR_BLX;
						ic->link_reg = regnum;
						fde->pc_functioncall = ar->pc & ~1;
						fde->cnt_functioncall++;
						ret = 1;
						goto Leave;
					}
				}

			}

			if ((op_24_20 & 0b10010) != 0b00010) { /*not 0xx1x*/
				if (op_7_4 == 0b1011) { /* 1011  Extra load/store instructions on page A5-203*/


				}
				if ( (op_7_4 & 0b1101) == 0b1101) {/* 11x1 Extra load/store instructions on page A5-203 */
					unsigned int op_6_5 = __BITS(insn, 5,6); /* op2 in A5.2.8 Extra load/store instructions*/
					if (op_6_5==0b10) { /* LDRD */
						/*E1CDA1D8            ldrd    r10,r11,[r13,#0x18]*/
						int i;
						unsigned long imm = __BITS(insn, 8, 11) << 4;
						unsigned int w = (insn>>21) & 1;
						unsigned int tmp_sp;
						unsigned int Rt = (insn >> 12)& 0xF;
						unsigned int Rn = __BITS(insn, 16, 19);

						ic->mnemonic = STR_LDRD;
						ic->link_reg = Rt;
						ic->link_reg_src = Rn;

						imm |= insn & 0xf;

						if (Rn == ARM_SP_REGNUM) {
							tmp_sp = ar->sp + imm;
							switch (p->forward_execution) {
							case EXEC_FORWARD:
								{
									for (i=0; i<2; i++) {
										unsigned int value;

										tsai_get_user_data_caution(p->mm, tmp_sp + (i<<2), 4, &value);
										ar->R[Rt+i] = value;
										ar->reg_extract_mask |= 1<< (Rt+i);
										if ((Rt+i)==ARM_LR_REGNUM || (Rt+i)==ARM_PC_REGNUM) {
											tsai_frame_details_return_retrieve(fde, ar, ic, Rt+i,tmp_sp + (i<<2) );
										}
										TSAI_UNWIND_LOG(" %s extra R%d %08x from %08x %08x %s sp %08x addr %08x @%d\n",
											exec_char[p->forward_execution], (Rt+i), ar->fp, ar->pc, insn, ic->mnemonic,
											ar->sp, (tmp_sp + (i<<2)), __LINE__ );
									}

									if (w) {
										ar->sp = tmp_sp;
									}
									//TSAI_UNWIND_LOG(" %s %08x %08x %s sp imm %d(%x) sp %08x\n",	exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, imm, imm, ar->sp);
								}
							break;
							}
						}

						/*  */
						ret = 1;
						goto Leave;

					}
					else if (op_6_5==0b11) {
						if ((insn & 0xff5f00f0) == 0xe14d00f0) {
							/* strd Rt, [sp, #imm]! , acts like push, storing something to stack
							 * E16D42F4 strd r4,r5,[r13,#0xFFFFFFDC]!
							 * E1CD60F8 strd    r6,r7,[r13,#0x8]
							 * E1CDA1F8 strd    r10,r11,[r13,#0x18]
							 * */
							int i;
							unsigned long imm = __BITS(insn, 8, 11) << 4;
							unsigned int w = (insn>>21) & 1;
							unsigned int tmp_sp;
							unsigned int Rt = (insn >> 12)& 0xF;

							ic->mnemonic = STR_STRD;
							imm |= insn & 0xf;

							tmp_sp = ar->sp + imm;

							for (i=0; i<2; i++) {
								unsigned int value;

								if ((Rt+i)==ARM_FP_REGNUM) {
									tsai_get_user_data_caution(p->mm, tmp_sp + (i<<2), 4, &value);
									ar->fp = value;
									TSAI_UNWIND_LOG("extra R%d %08x from %08x %08x %s sp %08x addr %08x @%d\n",
											(Rt+i), ar->fp, ar->pc, insn, ic->mnemonic, ar->sp, (tmp_sp + (i<<2)), __LINE__ );
								}
								else if ((Rt+i)==ARM_PC_REGNUM) {
									ar->pc = tsai_mark_early_out(ic, fde);
								}
							}

							if (w) {
								ar->sp = tmp_sp;
								fde->pc_most_recent_sp_sub = ar->pc;
								fde->ic_most_recent_sp_sub = ic;
							}

							TSAI_UNWIND_LOG("%08x %08x %s sp imm %d(%x) sp %08x @%d\n", ar->pc, insn, ic->mnemonic, imm, imm, ar->sp, __LINE__);
							/*  */
							ret = 1;
							goto Leave;
						}

					}

				}
			}





		}
		break;
	case 0B001:
		{
		/* Data-processing and miscellaneous instructions on page A5-196. */
			if ((insn & 0xfff00000) == 0xe2400000) {
				/* sub Rd,Rs, #size */
				unsigned long imm = insn & 0xff;
				unsigned long rot = (insn & 0xf00) >> 7;
				unsigned int regd = __BITS(insn, 12, 15);
				unsigned int regs = __BITS(insn, 16, 19);
				unsigned int interested = 0;
				ic->mnemonic = STR_SUB;
				ic->link_reg = regd;
				ic->link_reg_src = regs;

				imm = (imm >> rot) | (imm << (32 - rot));

				switch (p->forward_execution) {
				case EXEC_BACKWARD:
					{
						if (regd==ARM_SP_REGNUM) {

							IGNORE_COND_BLOCK;

							if (regs==ARM_SP_REGNUM ) {
								ar->sp += imm;
								fde->pc_most_recent_sp_sub = ar->pc;
								fde->ic_most_recent_sp_sub = ic;
							}
							else if (regs==ARM_FP_REGNUM) {
								//__asm("bkpt");
								if (!fde->pc_r13_tainted) {
									ar->fp = ar->sp + imm;
									interested = 1;
								}
							}
						}

						if (regd==ARM_SP_REGNUM || interested) {
							TSAI_UNWIND_LOG("%08x %08x %s R%d, R%d, imm %d(%x), sp %08x @%d\n", ar->pc, insn, ic->mnemonic,
									regd, regs, imm, imm, ar->sp, __LINE__);
						}
					}
					break;
				case EXEC_FORWARD:
					{
						if (regd==ARM_SP_REGNUM) {
							if (regs==ARM_SP_REGNUM) {
								ar->sp -= imm;
							}
							else if (regs==ARM_FP_REGNUM) {
								ar->sp = ar->fp - imm;
							}
							TSAI_UNWIND_LOG(" [fwe]%08x %08x %s R%d, R%d, imm %d(%x), sp %08x\n", ar->pc, insn, ic->mnemonic,
									regd, regs, imm, imm, ar->sp);
						}
					}
					break;
				}

				ret = 1;
				goto Leave;
			}
			else if ( ((insn>>21)&0b1111)==0b0100 ) {
				/* 2 possibility, ADR or ADD, if it's not ADR then it's ADD */
				unsigned int expand_imm;
				unsigned int rd = __BITS(insn, 12, 15);
				unsigned int imm = __BITS(insn, 0, 11);
				ic->link_reg = rd;
				expand_imm = tsai_ARMExpandImm(imm);
				ic->link_imm = expand_imm;
				if (__BITS(insn,16,20)==0b01111) {
					/* ADR eg B3F944D0 E28FC600 adr r12,0xB3F964D8*/
					ic->mnemonic = STR_ADR;

					ic->link_address = tsai_calculate_link_address(ar->pc, false, expand_imm);
					switch (p->forward_execution) {
					case EXEC_FORWARD:
						{
							ar->R[rd] = ic->link_address;

							TSAI_UNWIND_LOG("%08x %08x %s%s R[%d]=%08x \n",
									ar->pc, insn, ic->mnemonic, ic->condmnemonic, rd, ar->R[rd]);

						}
						break;

					}
					ret = 1;
					goto Leave;
				}
				else {

					/* add Rd, Rn, #n, A8.8.5 ADD (immediate, ARM)
					 * E28CCA42 add r12,r12,#0x42000 ; r12,r12,#270336
					 * E28DDF6E add r13,r13,#0x1B8, test the immediate value for this case!*/
					int regn = (insn & 0xf0000) >> 16;
					ic->mnemonic = STR_ADD;
					ic->link_reg_src = regn;
					switch(p->forward_execution) {
					case EXEC_BACKWARD:
						{

							if (rd==ARM_SP_REGNUM) {
								IGNORE_COND_BLOCK;
								ar->sp -= expand_imm;
								TSAI_UNWIND_LOG("%08x %08x %s sp imm %d(%x) sp %08x\n", ar->pc, insn, ic->mnemonic, expand_imm, expand_imm, ar->sp);
							}
							else if (rd==ARM_FP_REGNUM && regn==ARM_SP_REGNUM) {
								int sp_restored = 0;
								if (!fde->most_recent_r11_set) {
									if (fde->pc_r13_tainted) {
										/* R13 is tainted but R11 appears to be intact*/
										ar->sp = ar->fp - expand_imm;
										sp_restored = 1;
										TSAI_UNWIND_LOG("%08x %08x %s R11, R13 imm %d(%x) R13 %08x Restored based on R11 %08x\n",
											ar->pc, insn, ic->mnemonic, expand_imm, expand_imm, ar->sp, ar->fp);
									}
								}
								fde->most_recent_r11_set = ar->pc;
								if (!sp_restored) {
									ar->fp = ar->sp + expand_imm;
									TSAI_UNWIND_LOG("%08x %08x %s R11, R13 imm %d(%x) R11=%08x\n", ar->pc, insn, ic->mnemonic, expand_imm, expand_imm, ar->fp);
								}
							}
						}
						break;
					case EXEC_FORWARD:
						{
							unsigned int old_value = ar->R[regn];
							ar->R[rd] = old_value + expand_imm;
							TSAI_UNWIND_LOG(" [fwe]%08x %08x %s%s R[%d]=%08x imm %08x\n",
									ar->pc, insn, ic->mnemonic, ic->condmnemonic, rd, ar->R[rd], expand_imm);

						}
						break;
					}

					ret = 1;
					goto Leave;
				}
			}
		}
		break;
	case 0B010:
		{ /*Load/store word and unsigned byte on page A5-208.*/
			int interested = 0;
			unsigned int op_24_20 = (insn >> 20) & 0B11111;
			if ((op_24_20 & 0b00101 )==0b00001) {
				/*A8.8.63 LDR (immediate, ARM), including POP
				 * eg E5BCF390 ldr pc,[r12,#0x390]!
				 *    E49D7004 pop     {r7}
				 *    E59FC004 ldr r12,0xB1754F14   ; r12,=0xB294D005
				 * */
				int regnum = __BITS(insn, 12, 15);
				int regn = __BITS(insn, 16, 19);
				unsigned int imm = __BITS(insn, 0, 11);
				unsigned int pbit = __BITS(insn, 24, 24);
				unsigned int u = __BITS(insn, 23, 23);
				unsigned int w = __BITS(insn, 21, 21);
				unsigned int tmp_sp;

				if (!u) { /* u bit controls whether imm value is positive or negative */
					imm = -imm;
				}
				if ((pbit==0 || w==1)) {
					ic->wb = 1;
				}

				if ((insn & 0xffff0fff) == 0xE49D0004) {
					ic->mnemonic = STR_POP;
				}
				else {
					ic->mnemonic = STR_LDR;
				}

				ic->link_reg = regnum;
				ic->link_reg_src = regn;

				switch (p->forward_execution) {
				case EXEC_BACKWARD:
				{
					if (regnum == ARM_PC_REGNUM)
						ar->pc = tsai_mark_early_out(ic, fde);

						IGNORE_COND_BLOCK;

						if (regn==ARM_SP_REGNUM) {
							if (ic->wb)
								tmp_sp = ar->sp - imm;
							else
								tmp_sp = ar->sp + imm;
						}
						else if (regn==ARM_FP_REGNUM) {
							/* eg. E51B2078 ldr r2,[r11,#0xFFFFFF88] indicating R11 is used as frame pointer */
							fde->cnt_r11_use++;
						}

						if (regnum == ARM_FP_REGNUM ) {
						}
						else if (regnum == ARM_LR_REGNUM) {
						}
						else if (regnum == ARM_PC_REGNUM) {
							fde->pc_b = ic->PC;
							interested = 1;
						}

						if (regn==ARM_SP_REGNUM && ic->wb) {
								ar->sp = tmp_sp;
								interested = 1;
						}
						if (interested) {
							TSAI_UNWIND_LOG("%08x %08x %s%s R%d [R%d, #%d(%08x)]%s sp %08x LINE %d\n",
									ic->PC, insn, ic->mnemonic, ic->condmnemonic,
								ic->link_reg, ic->link_reg_src, imm, imm, ic->wb?"!":"", ar->sp, __LINE__);
						}
					}
					break;
				case EXEC_FORWARD:
					{
						unsigned int old_ptr, new_ptr;
						unsigned int ptr;
						if (regn==ARM_PC_REGNUM) {
							old_ptr = ar->pc + 8;
							new_ptr = tsai_calculate_link_address(ar->pc, false, imm );
						}
						else {
							old_ptr = ar->R[regn];
							new_ptr = old_ptr + imm;
						}

						if (pbit)
							ptr = new_ptr;
						else
							ptr = old_ptr;

						if (regn==ARM_SP_REGNUM && fde->pc_r13_tainted) {
							fde->cannot_continue = T_UNSPECIFIED;
							ret = 1;
							goto Leave;
						}

						/* cautious read because most register are likely of invalid value */
						tsai_callstack_copy_from_user_stack_caution(ptr, 4, &ar->R[regnum]);

						if (regnum==ARM_PC_REGNUM || regnum==ARM_LR_REGNUM) {
							tsai_frame_details_return_retrieve(fde, ar, ic, regnum, ptr);
						}

						if (ic->wb) {
							ar->R[regn] = new_ptr;
						}
						TSAI_UNWIND_LOG(" %s %08x %08x %s%s R[%d]=%08x @%d\n",
								exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, ic->condmnemonic, regnum, ar->R[regnum], __LINE__);
					}
					break;
				}
				ret = 1;
				goto Leave;

			}
			else if ((op_24_20 & 0b00101 )==0b00000) {
				/*A8.8.204 STR (immediate, ARM), including PUSH
				 * eg
				 * E50BD050 str r13,[r11,#0xFFFFFFB0]
				 * E58DE020 str r14,[r13,#0x20]
				 * E52D4008 str r4,[r13,#0xFFFFFFF8]!
				 * 0101 0010
				 * */
				int rt = __BITS(insn, 12, 15);
				int regn = __BITS(insn, 16, 19);
				unsigned int imm = __BITS(insn, 0, 11);
				unsigned int pbit = __BITS(insn, 24, 24);
				unsigned int u = __BITS(insn, 23, 23);
				unsigned int w = __BITS(insn, 21, 21);
				unsigned int is_push = 0;
				unsigned int tmp_sp;

				if (!u) { /* u bit controls whether imm value is positive or negative */
					imm = -imm;
				}
				if ((pbit==0 || w==1)) {
					ic->wb = 1;
				}

				if ((insn & 0x05ff0fff) == 0x052D0004) {
					is_push = 1;
					ic->mnemonic = STR_PUSH;
				}
				else {
					ic->mnemonic = STR_STR;
				}

				ic->link_reg = rt;
				ic->link_reg_src = regn;

				switch (p->forward_execution)
				{
				case EXEC_BACKWARD:
					if (regn==ARM_SP_REGNUM) {
						if (is_push || ic->wb) /* eg PUSH = STR R7,[R13,#imm]!  */
							tmp_sp = ar->sp - imm;
						else /* non-push */
							tmp_sp = ar->sp + imm;
					}
					else if (regn==ARM_FP_REGNUM) {
						/* eg. E50B803C str r8,[r11,#0xFFFFFFC4] indicating R11 is used as frame pointer */
						fde->cnt_r11_use++;
					}


					if (regn==ARM_SP_REGNUM) {
						if (is_push || ic->wb)
							tsai_check_set_register_value_from_stack(p, rt, ar->sp);
						else
							tsai_check_set_register_value_from_stack(p, rt, tmp_sp);

						ar->reg_extract_mask |= 1<<rt;
						TSAI_UNWIND_LOG(" extra R%d=%08x from %08x %s%s [stack addr=%08x] @%d\n",
								rt, ar->R[rt], ar->pc, ic->mnemonic, ic->condmnemonic, tmp_sp, __LINE__);

						if (rt == ARM_FP_REGNUM)
							interested = 1;

						if (rt == ARM_LR_REGNUM) {
							interested = 1;
						}
					}
					else if (rt == ARM_SP_REGNUM && regn==ARM_FP_REGNUM) {
						if (fde->pc_r13_tainted) {
							unsigned int tmp_ptr = ar->fp + imm;
							unsigned int tmp_value;
							//__asm("bkpt");
							tsai_get_user_data_caution(p->mm, tmp_ptr, 4, &tmp_value);
							if (tmp_value > ar->sp_saved && tmp_value < ar->sp_end) {
								fde->pc_r13_tainted = 0;
								ar->sp = tmp_value;
								TSAI_UNWIND_LOG("R13 %08x value RETRIEVED from %08x %08x %s%s R%d(%08x) R%d(%08x) #%d addr %08x\n",
									ar->sp, ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, ar->sp,regn, ar->fp, imm, tmp_ptr);
							}
							else {
								TSAI_UNWIND_LOG("IGNORE R13 %08x value RETRIEVED from %08x %08x %s%s R%d(%08x) R%d(%08x) #%d addr %08x\n",
									tmp_value, ar->pc, insn, ic->mnemonic, ic->condmnemonic,rt, ar->sp,regn, ar->fp, imm, tmp_ptr);
							}
							interested = 1;
						}
					}
					else if (rt == ARM_PC_REGNUM) {
					}

					if (regn==ARM_SP_REGNUM && ic->wb) {
						ar->sp = tmp_sp;
						interested = 1;
					}

					if (interested) {
						TSAI_UNWIND_LOG(" %08x %08x %s%s R%d [R%d, #%d(%08x)]%s sp %08x @%d\n", ar->pc, insn, ic->mnemonic, ic->condmnemonic,
							ic->link_reg, ic->link_reg_src, imm, imm, ic->wb?"!":"", ar->sp, __LINE__);

					}
					break;
				}
				ret = 1;
				goto Leave;
			}
		}
		break;
	case 0B011:
		/* Load/store word and unsigned byte on page A5-208.
		 * Media instructions on page A5-209. */
		{

		}
		break;
	case 0B100: /* PUSH and POP in this category */
		{
			unsigned int op_25_20 = (insn >> 20) & 0B111111;
			spshift = 0;
			switch (op_25_20) {
			case 0b001011: /* POP */
				//__asm("bkpt"); /* this clause verified */
				if ((insn & 0xff1f0000) == 0xe81d0000) {
						/*  pop { rlist }
						 * or
						 *  ldm{da,db,ia,ib} { rlist } {!} */
						int mask = insn & 0xffff;
						int rn = 0;
						ic->mnemonic = STR_POP;
						ic->link_reglist = mask;
						switch(p->forward_execution) {
						case EXEC_BACKWARD:
							{
								if ((mask & (1 << ARM_PC_REGNUM)) ||
										(mask & (1 << ARM_FP_REGNUM)))
								{
									ar->pc = tsai_mark_early_out(ic, fde);
								}
								else {
									/* ldmi instruction, if instrcution kept "lr" as register
									 * it will consider as the instrcution is not executed
									 * if so, branch will never return in current frame.
									 * skip sp adjustment in this case */
									if (mask & (1 << ARM_LR_REGNUM)) {
										goto Leave;
									}
									IGNORE_COND_BLOCK;

									for (; mask; rn++, mask >>=1) {
										if (mask & 1 ) {
											spshift += 4;
										}
									}
									ar->sp -= spshift;
									TSAI_UNWIND_LOG("%08x %08x %s sp shift %d(%x) sp %08x @%d\n", ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp, __LINE__);
								}
							}
							break;
						case EXEC_FORWARD:
							{
								for (; mask; rn++, mask >>=1) {
									if (mask & 1 ) {
										tsai_get_user_data_caution(p->mm, ar->sp+spshift, 4, &ar->R[rn]);
										ar->reg_extract_mask |= 1<<rn;
										TSAI_UNWIND_LOG(" R[%d]=%08x @%d\n", rn, ar->R[rn], __LINE__);
										if (rn == ARM_LR_REGNUM || rn == ARM_PC_REGNUM) {
											tsai_frame_details_return_retrieve(fde, ar,ic, rn, ar->sp+spshift);
										}

										spshift += 4;
									}
								}
								ar->sp += spshift;
								TSAI_UNWIND_LOG("%s @%08x %08x %s sp shift %d(%x) sp %08x @%d\n",
										exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp, __LINE__);
							}
							break;
						}
						ret = 1;
						goto Leave;
				}
				break;
			case 0B010010: /* PUSH , register list */
				{ /* if ((insn & 0xffff0000) == 0xe92d0000) */
					/*  stmfd sp!, {..., fp, ip, lr, pc}
					 * or
					 *  stmfd sp!, {a1, a2, a3, a4}
					 * or
					 *  push {...fp,ip,lr,pc} */
					int mask = insn & 0xffff;
					int rn = 0;
					ic->mnemonic = STR_PUSH;
					switch (p->forward_execution) {
					case EXEC_BACKWARD:
						/* Calculate offsets of saved registers.  */
						for (; mask; rn++, mask>>=1) {
							if (mask & 1) {
								/* lr is pushed on stack so read lr */
								if (rn == ARM_LR_REGNUM) {
									tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->lr);
									tsai_frame_details_return_retrieve(fde,ar,ic, ARM_LR_REGNUM, ar->sp);
								}
								else {
									tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->R[rn]);
									ar->reg_extract_mask |= 1<<rn;
									TSAI_UNWIND_LOG(" R%d=%08x from sp %08x @%d\n", rn, ar->R[rn], ar->sp, __LINE__);
								}

								ar->sp += 4;
								spshift += 4;
							}
						}
						TSAI_UNWIND_LOG("%08x %08x %s sp shift %d(%x) sp %08x @%d\n", ar->pc, insn, ic->mnemonic, spshift, spshift, ar->sp, __LINE__);
						break;
					}
					ret = 1;
					goto Leave;
				}
				break;
			case 0b011000: /* stmib , no write back*/
			case 0b011010: /* stmib, write back */
				{/*STMIB can be used to write LR to stack */
					/* eg E98D4800            stmib   r13,{r11,r14} , A=0, op24_20=11000, A8.8.202 STMIB (STMFA)*/
					int reg = (insn & 0xf0000) >> 16;
					int wb = (insn >> 21) & 0x1;
					int mask = insn & 0xffff; /* low 16bit is reg list */
					int rn = 0;
					int tmp_sp = ar->sp;

					ic->mnemonic = "stmib";
					ic->link_reg = reg;

					switch(p->forward_execution) {
					case EXEC_BACKWARD:
						{
							if (reg==ARM_SP_REGNUM) {
								for (; mask; rn++, mask>>=1 ) {
									if (mask & 1) {
										tmp_sp += 4;
										tsai_get_user_data_caution(p->mm, tmp_sp, 4, &ar->R[rn]);
										ar->reg_extract_mask |= 1 << rn;
										if (rn == ARM_LR_REGNUM) {
											tsai_frame_details_return_retrieve(fde,ar,ic, ARM_LR_REGNUM, tmp_sp);
										}
										TSAI_UNWIND_LOG(" %s @%08x %08x %s extra r%d=%08x from %08x \n",
												exec_char[p->forward_execution], ar->pc, insn, ic->mnemonic, rn, ar->R[rn], tmp_sp);
									}
								}
								if (wb) {
									ar->sp = tmp_sp;
								}
								TSAI_UNWIND_LOG("%08x %08x %s sp %08x \n", ar->pc, insn, ic->mnemonic, ar->sp);
							}

						}
						break;
					}

					ret = 1;
					goto Leave;
				}
				break;
			} /* end of switch */
		}
		break;
	case 0b101:
		{
			if (0x01000000 & insn) { /* if bit 24 is set, it's BL */
				unsigned int pc = ic->PC;
				unsigned int imm24 = (insn & 0xFFFFFF);
				unsigned int imm = imm24 << 2;
				unsigned int negative = insn & 0x800000;
				ic->mnemonic = STR_BL;
				fde->pc_functioncall = ar->pc;
				fde->cnt_functioncall++;
				if (negative) {
					/* as of now, target is not calculated correctly! */
					imm |= 0xFC000000; /* make bit 31..26 all 1, to become 32bit negative value */
					//imm = (1 << 26) - imm;
				}
				else {
				}
				ic->link_address = tsai_calculate_link_address(pc, false, imm);
				goto Leave;
			}
			else { /* bit 24=0, B */
				unsigned int pc = ic->PC;
				unsigned int imm24 = (insn & 0xFFFFFF);
				unsigned int imm = imm24 << 2;
				unsigned int negative = insn & 0x800000;
				ic->mnemonic = STR_B;
				if (negative) {
					/* as of now, target is not calculated correctly! */
					imm |= 0xFC000000; /* make bit 31..26 all 1, to become 32bit negative value */
					//imm = (1 << 26) - imm;
				}
				else {
				}
				ic->link_address = tsai_calculate_link_address(pc, false, imm);
				goto Leave;
			}
		}
		break;
	case 0B110:
		if ((insn & 0xefbf0f00) == 0xed2d0b00) {
				/* vpush {rlist} */
				ar->sp += 8 * __BITS(insn, 0, 7) >> 1;
				goto Leave;
		}
		if ((insn & 0x0cbd0b00) == 0x0cbd0b00) {
			/* vpop {rlist}
			 * ECBD8B02 vpop.64 {d8} */
			unsigned int vd = __BITS(insn, 12, 15);
			unsigned int imm32 = __BITS(insn, 0, 7) << 2;
			ic->mnemonic = "vpop.64";
			ic->link_reg = vd;

			switch(p->forward_execution) {
			case EXEC_BACKWARD:
				{
					IGNORE_COND_BLOCK;
					ar->sp -= imm32;
				}
				break;
			case EXEC_FORWARD:
				{
					ar->sp += imm32;
				}
				break;
			}
			TSAI_UNWIND_LOG(" %s @%08x %s v%d sp=%d @%d\n",
				exec_char[p->forward_execution], ar->pc, ic->mnemonic, ic->link_reg, ar->sp, __LINE__);
			ret = 1;
			goto Leave;
		}
		if ((insn & 0xec3d0f00) == 0xec2d0b00) {
				/* vstm{ia,db} sp!, { rlist } */
				/* we probably should care about BIT:23 */
				ar->sp += 8 * __BITS(insn, 0, 7);
				goto Leave;
		}
		if ((insn & 0xec3f0f00) == 0xec3d0b00 ||
					(insn & 0xec3f0f00) == 0x8c3d0b00) {
				/* vldm{ia,db} sp!, { rlist }*/
				fde->flags |= KUBT_FLAG_FUNC_EPILOGUE;
				if (fde->flags) {
					goto Leave;
				}
				/* we probably should care about BIT:23 */
				ar->sp -= 8 * __BITS(insn, 0, 7);
				goto Leave;
		}
		break;
	}

Leave:
	return ret;
}

/* data_bytes: how many bytes identified to be data*/
static void tsai_handle_data_insn(struct tsai_handle_insn_param* p, int data_bytes) {
	struct tsai_instruction_cache* ic = p->ic;
	ic->mnemonic = STR_DCD;
	TSAI_UNWIND_LOG("the content at %08x appears to be data %08x @%d\n",
			PC_NO_THUMB(p->ar->pc), ic->hex_code, __LINE__);
}

/*
 * purpose:
 * 1: scan forward to find jump target at the end of block, result will be stored in *bb
 * 2: scan forward and execute to find LR
 *
 * return:
 * 1: when finding LR from early out block, it means everything check out and should use the information
 * 0: scanned
 * -1: error, eg. not valid memory yet
 * */
static int tsai_scan_basic_block(struct tsai_handle_insn_param* pa, unsigned int block_begin, struct tsai_bb* bb, int purpose)
{
	int ret = 0;
	unsigned int extracted_jump_target = 0;
	int i;
	struct tsai_handle_insn_param* p;
	struct tsai_frame_details* fde;
	struct tsai_instruction_cache_mgr* im;
	struct tsai_intermediate_regs* ar;
	struct tsai_instruction_cache* ic;
	unsigned int insn;
	int flags = 0;
	const char* purpose_str[] = {"unknown", "find jump target", "find lr" };

	struct TMP_PARSE_USER_CALLSTACK {
		struct tsai_intermediate_regs ar_stack;
		struct tsai_handle_insn_param param;
		struct tsai_frame_details f;
		struct tsai_instruction_cache_mgr im;
		char full_path[256];
		const char* func_name;
	};
	struct TSAI_FAKE_STACK_TICKET ticket;
	struct TMP_PARSE_USER_CALLSTACK* ts =
			(struct TMP_PARSE_USER_CALLSTACK*)tsai_fake_stack_get(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);

	if (tsai_get_user_data_caution(pa->mm, block_begin, 4, &insn)) {
		ret = -1;
		goto Leave;
	}

	TSAI_UNWIND_LOG(" Scan BB @ pc %08x--%08x %s\n", block_begin, bb->pc_end, purpose_str[purpose]);
	p = &ts->param;
	tsai_handle_insn_param_clear(p);
	*p = *pa;

	if (purpose == 1)
		p->forward_execution = EXEC_FORWARD_EMPTY;
	else if (purpose == 2)
		p->forward_execution = EXEC_FORWARD;

	fde = &ts->f;
	ar = &ts->ar_stack;
	*ar = *pa->ar;
	im = &ts->im;

	ar->pc = block_begin;
	ar->pc_saved = ar->pc;

	ar->frame_is_thumb = pa->ar->frame_is_thumb;

	p->ar = ar; p->fde = fde; p->start = 0;

	tsai_frame_details_clear(fde);
	tsai_instruction_cache_init(im);

	if (purpose == 1)
		bb->pc_begin = block_begin;

	for (;;) {
		unsigned int pc = ar->pc & ~1;
		if (ar->frame_is_thumb) {
			unsigned t32_sig;

			if (tsai_get_user_data_caution(pa->mm, PC_NO_THUMB(ar->pc), 4, &insn))
				break;
			insn = (insn & 0x0000FFFF) << 16 | (insn & 0xFFFF0000) >> 16;
			t32_sig = (insn) >> 27;
			if (t32_sig == 0b11101 || t32_sig == 0b11110 || t32_sig == 0b11111) {
				p->armthumb = 2;
			}
			else {
				p->armthumb = 1;
				if (p->forward_execution==EXEC_BACKWARD)
					insn &= 0x0000FFFF;
				else
					insn = insn >> 16;
			}

		} else {
			p->armthumb = 0;
			if (tsai_get_user_data_caution(pa->mm, ar->pc, 4, &insn))
				break;
		}

		ic = tsai_instruction_cache_obtain(im); ic->hex_code = insn; ic->PC = ar->pc; ic->armthumb = p->armthumb;
		p->ic = ic;

		if (ar->frame_is_thumb)
			tsai_handle_thumb_insn(p);
		else
			tsai_handle_arm_insn(p);

		if (purpose == 1) {
			if ( tsai_end_of_bb_pattern_match(ic) ) {
				bb->pc_end = ic->PC & ~1;
				bb->ic_end = *ic;
				bb->ic_end.pm = 0;
				TSAI_UNWIND_LOG(" BB @ pc %08x jump to %08x\n", block_begin, bb->ic_end.link_address);
				break;
			}
		}
		else if (purpose == 2) {
			if (fde->f_pc_set) {
				break;
			}
			else if (fde->cannot_continue) {
				break;
			}
			else if ( pc >= (bb->pc_end&~1) ) {
				break;
			}

		}

		ar->pc += tsai_instruction_cache_hex_len(ic);
		if (bb->pc_end && (ar->pc&~1) > (bb->pc_end&~1) )
			break;
	}

	if (purpose==2 && (fde->f_pc_set || fde->pc_r14_retrieve)) {
		int lrok;
		int acceptable = 0;
		int match_perfect = 0;
		int execusable = 0; /* start address not match, but belong to known case */

		if (fde->f_pc_set) { /* for cases R15 retrieved instead of R14*/
			if (ar->lr != ar->pc)
				ar->lr = ar->pc;
		}

		lrok = tsai_examine_lr_valid(p, 1, 1);
		if (lrok) {
			if (p->call_depth==0) {
				tsai_examine_extracted_function_start(p);
			}
			if (p->f_start_found && p->start_found) {

				if (pa->start) {
					if (tsai_compare_address_ignore_thumbbit(pa->start,p->start_found)) {
						TSAI_UNWIND_LOG(" EARLY OUT BLOCK @%08x LR %08x appears valid, start address match \n",
								block_begin, ar->lr	);
						match_perfect = 1;
						acceptable = 1;
					}
					else {
#if defined(DEBUG)
						p->vw = tsai_find_vma_wrapper_by_addr(p->vma_mgr, p->start_found, p->mm, ts->full_path);
						ts->func_name = 0;
						if (p->vw && p->vw->symbol_key) {
							p->start = tsai_lookup_symbol(p->vw->symbol_key, p->start_found, p->vw->vma->vm_start,
									&ts->func_name, &p->start_len);
						}

						TSAI_UNWIND_LOG(" found start %08x %s is different than known start %08x %s \n",
								p->start_found, ts->func_name, pa->start, pa->func_name);
#endif
						acceptable = 1;
						execusable = 1;
					}
				}
				else
					acceptable = 1;
			}
			else
				acceptable = 1;
		}

		if (acceptable) {
			/* there is no function call address extracted from return address, most likely due to blx register
			 * if the return address is not directly from register from first frame, treate it as trustworthy */
			if (fde->pc_r14_retrieve || match_perfect || execusable) {
				*pa->ar = *ar;
				pa->ar->pc = ic->PC;
				pa->fde->f_r14_examined = 1;
				pa->fde->f_r14_valid = 1;
				pa->fde->st_r14_retrieve = fde->st_r14_retrieve;
				pa->fde->pc_r14_retrieve = fde->pc_r14_retrieve;

				ret = 1;
				if (match_perfect) {
					TSAI_UNWIND_LOG(" EARLY OUT BLOCK @%08x LR %08x likely to be valid (perfect match)\n",
							block_begin, ar->lr);
				}
				else if (execusable) {
					TSAI_UNWIND_LOG(" EARLY OUT BLOCK @%08x LR %08x likely to be valid (excusable)\n",
							block_begin, ar->lr);
				}
				else
					TSAI_UNWIND_LOG(" EARLY OUT BLOCK @%08x LR %08x likely to be valid as it was from stack addr %08x\n",
						block_begin, ar->lr	, fde->st_r14_retrieve);

				ASSERT(pa->ar->pc);
				goto Leave;
			}
		}
		TSAI_UNWIND_LOG(" EARLY OUT BLOCK @%08x LR %08x NOT OK! \n",
				block_begin, ar->lr	);

		if (tsai_bkpt_disasm) {
			__asm("bkpt");
		}
	}
	else {
		TSAI_UNWIND_LOG(" BASIC BLOCK no useful information! @%d\n",
				__LINE__ );
	}

Leave:
	tsai_fake_stack_put(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	return ret;

}

void tsai_detect_cond_basic_block(struct tsai_handle_insn_param* p) {
	int ok;
	struct tsai_intermediate_regs *ar = p->ar;
	struct tsai_instruction_cache* ic = p->ic;
	//unsigned int insn = p->ic->hex_code;
	//unsigned long start = p->start;
	struct tsai_frame_details* fde = p->fde;

	/* deal with outstanding early out bb first */
	if (fde->f_early_out_bb) {
		int can_unwind;

		can_unwind = tsai_scan_basic_block(p, fde->early_out_bb.pc_begin, &fde->early_out_bb, 2);
		if (can_unwind==1) {
			fde->can_unwind_now = 1;
		}
		fde->f_early_out_bb = 0;
	}

	if (!fde->can_unwind_now) {
		if ((ic->mnemonic==STR_B && (!ic->condmnemonic || ic->condmnemonic==STR_AL)) || /* B unconditional */
			(ic->mnemonic==STR_ADD && ic->link_reg==ARM_PC_REGNUM) /* example: jumping to clause, add pc,pc,r12 */
				)
		{
			int is_conditional_bb = 1;
			if (ic->link_address > ic->PC && p->armthumb==0 ) { /* right now thumb decoding engine is not robust */
				/* if it's jumping to later code, see if the destination will jump back soon
				 * it's very common for while/for loop
				 * for that case, it's not a conditional early out block
				 * */
				struct tsai_bb bb;
				ok = tsai_scan_basic_block(p, ic->link_address, &bb, 1);
				if ( ok>=0 && (bb.ic_end.link_address == (ic->PC & ~1) + (ic->armthumb==1?2:4)) ) {
					is_conditional_bb = 0;
					TSAI_UNWIND_LOG(" pc %08x %s%s %08x jump forward and back, not conditional bb\n",
							ar->pc, ic->mnemonic, ic->condmnemonic, ic->link_address);
				}
			}

			if (is_conditional_bb) {
				if (fde->pc_b) {
					TSAI_UNWIND_LOG(" pc %08x likely begin of conditional basic block @%d\n", ar->pc, __LINE__);
					if (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) {
						fde->flags &= ~KUBT_FLAG_FUNC_EPILOGUE;
						fde->early_out_bb.pc_begin = ar->pc + tsai_instruction_cache_hex_len(ic);
						fde->early_out_bb.pc_end = fde->pc_b;
						fde->f_early_out_bb = 1;
					}
					fde->pc_b = 0;

					/* scan this early out bb and see if it can find LR information! */
					if (fde->f_early_out_bb) {
						int can_unwind;
	#if 0 && defined(DEBUG)
						if (p->armthumb)
							__asm("bkpt");
	#endif
						can_unwind = tsai_scan_basic_block(p, fde->early_out_bb.pc_begin, &fde->early_out_bb, 2);
						if (can_unwind==1) {
							fde->can_unwind_now = 1;
						}
						fde->f_early_out_bb = 0;
					}
				}

				fde->pc_b = ic->PC;
				TSAI_UNWIND_LOG(" pc %08x %s%s %08xlikely end of conditional basic block @%d\n",
						ar->pc, ic->mnemonic, ic->condmnemonic, ic->link_address, __LINE__);

			}
		}
		else if (ic->mnemonic==STR_B || ic->mnemonic==STR_CBZ || ic->mnemonic==STR_CBNZ) { /* B with condition, CBZ,CBNZ */
			if (fde->pc_b) {
				TSAI_UNWIND_LOG(" pc %08x likely begin of conditional basic block @%d\n", ar->pc, __LINE__);
				if (fde->flags & KUBT_FLAG_FUNC_EPILOGUE) {
					fde->flags &= ~KUBT_FLAG_FUNC_EPILOGUE;
					fde->early_out_bb.pc_begin = ar->pc + tsai_instruction_cache_hex_len(ic);
					fde->early_out_bb.pc_end = fde->pc_b;
					fde->f_early_out_bb = 1;
				}
				fde->pc_b = 0;

				/* scan this early out bb and see if it can find LR information! */
				if (fde->f_early_out_bb) {
					int can_unwind;
#if 0 && defined(DEBUG)
					if (p->armthumb)
						__asm("bkpt");
#endif
					can_unwind = tsai_scan_basic_block(p, fde->early_out_bb.pc_begin, &fde->early_out_bb, 2);
					if (can_unwind==1) {
						fde->can_unwind_now = 1;
					}
					fde->f_early_out_bb = 0;
				}
			}
		}
	}
}

int tsai_special_case_by_function_name(struct tsai_handle_insn_param* p) {
	int ret = 0;
	/* special case handling, such as big jump table which will take a long time to parse */
	if (p->func_name) {
		if (strcmp(p->func_name, "coregl_initialize")==0) {
			p->ar->pc = p->start + 0x10;
			if (p->ar->frame_is_thumb) {
				p->ar->pc |= 1;
			}
			ret = 1;
		}
		else if (strcmp(p->func_name, "coregl_initialize")==0) {

		}
	}

	return ret;
}


int tsai_examine_lr_at_first_frame(struct tsai_handle_insn_param* p) {
	int ret = 0;
	/* when profiling interrupt directly happen on top of user stack, LR(R14) might still be valid?
	 * if that happens, it can offer unwind information directly
	 * Also note, the top frame may have already done another function call
	 * so even if the LR register value appears to be valid, it could be from those additional function call and not for this frame
	 * if LR can be extracted from stack, the LR extracted from stack is more trustworthy
	 * */
	int lrok;
	ASSERT( p->call_depth==0 );
	lrok = tsai_examine_lr_valid(p, 1, 1);
	if (lrok) {
		if (p->f_start_found && p->start_found) {
			int startok;
			unsigned int start_found_clean = p->start_found & ~1;
			startok = tsai_examine_extracted_function_start(p);
			if (startok) {
				p->fde->f_start_suspicious = 1;
				ret = 1;
			}
			else {
				p->fde->f_r14_examined = 1;
				p->fde->f_r14_valid = 0;
				TSAI_UNWIND_LOG(" LR %08x at first frame the jump target start address not valid %08x LR invalidated %d\n",
						p->ar->lr, start_found_clean, __LINE__);
			}
		}
		else {
			/* inconclusive because the LR cannot be used to get a jump target address */
			ret = 1;
		}
	}

	return ret;
}

/* detect data embedded along with code
 * return: how many bytes are judged to be data */
static int tsai_detect_data_in_code(struct tsai_handle_insn_param* p, unsigned int addr, unsigned int insn) {
	int ret = 0;
	int data_encountered;
	int nop_encountered;
	unsigned int addr_in;
	if (addr & 0x2)  /* if addr is not aligned to boundary of 4, don't check, ignoring thumb bit */
		goto Leave;

	addr_in = addr;
	data_encountered = 0;
	nop_encountered = 0;
	do {
		int is_data = 0;
		if ( (insn&0xFFFF0000)==0xFFFF0000 ||
				( (data_encountered || p->fde->pc_r14_retrieve )&& (insn&0xFFE00000)==0 )) {
			is_data++;
		}

		if ( (insn & 0xFE000000)==0) { /* if these 4 bytes begin with 0x00 or 0x01 */
			is_data++;
		}

		if (is_data)
			data_encountered++;
		else {
			if (p->armthumb) {
				if ((insn & 0xFFFF0000)==0xBF000000) { /* nop */
					nop_encountered++;
				}
			}

			break;
		}

		addr = PC_NO_THUMB(addr - 4) ;
		tsai_get_user_data_caution(p->mm, addr, 4, &insn);
	} while(1);

	if (data_encountered ) {
		/* if only one word look like data and not accompanied by NOP, could it be just coincidence?? */
		if (data_encountered==1 && nop_encountered==0) {
			//__asm("bkpt");
		}
		else {
			TSAI_UNWIND_LOG(" addr %08x--%08x appears to be data @%d\n", addr+4, addr_in, __LINE__ );
			ret = data_encountered * 4;
		}
	}
Leave:
	return ret;
}

static int tsai_lookup_arm_exidx(struct tsai_handle_insn_param* p);
static int tsai_apply_exidx(struct tsai_handle_insn_param* pa);

#ifdef DEBUG
unsigned int tsai_callstack_break_at_pc = 0x0;
unsigned int tsai_callstack_break_at_insn = 0x0;

#endif

/* This function uses 2598 bytes on stack!
 *
 * dbg_seq: caller-provided debug sequence number
 *
 * return 1: perfect termination
 * 2: early out (including reaching requested level) and perfect
 * 0: unexpected result, but carry on next task
 * -1: forced stop profiling
 * */
int tsai_parse_user_callstack(struct TSAI_PARSE_USER_CALLSTACK* param, unsigned int dbg_seq)
{
	unsigned long flags;
	struct tsai_intermediate_regs* ar;
	unsigned int insn = 0;
	unsigned long last_sp = 0;
	int ret, th_mode;
	int ret_trace;
	unsigned int to_handle_pabort = 0;
	unsigned int data_encountered = 0;
	int limit = 64;
	struct tsai_handle_insn_param* p;
	struct tsai_frame_details* fde;
	struct tsai_instruction_cache_mgr* im;
	char* path;
	char* filename;

	struct TMP_PARSE_USER_CALLSTACK {
		struct tsai_intermediate_regs ar_stack;
		struct tsai_handle_insn_param param;
		struct tsai_frame_details f;
		struct tsai_instruction_cache_mgr im;
		struct TSAI_EXIDX_UNWIND exidx;
		const char* func_name;
	};
	struct TSAI_FAKE_STACK_TICKET ticket;
	struct TMP_PARSE_USER_CALLSTACK* ts;

	TSAI_UNWIND_LOG("tsai_parse_user_callstack dbg_seq %d @%d\n", dbg_seq, __LINE__);

	local_irq_save(flags);
	preempt_disable();

	ts = (struct TMP_PARSE_USER_CALLSTACK*)tsai_fake_stack_get(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	p = &ts->param;
	tsai_handle_insn_param_clear(p);
	p->cpu_core = tsai_cpu_core_id();
	p->call_depth = 0;
	p->func_name = ts->func_name;
	fde = &ts->f;
	ar = &ts->ar_stack;
	im = &ts->im;
	ts->ar_stack = *param->regs;

	ar->pc_saved = ar->pc;
	ar->sp_saved = ar->sp;

	p->ar = ar;
	p->fde = fde;
	p->exidx = &ts->exidx;
	p->mm = param->tsk_mm;
	p->vma_mgr = param->vma_mgr;

	to_handle_pabort = param->regs->on_pabort;
	if (!to_handle_pabort && !param->regs->voluntary) {
		/* if profiling interrupt happen right before pre-fetch handler, we won't see pabort on kernel stack but still possible */
		int err;
		err = tsai_callstack_copy_from_user_stack_caution(ar->pc, 4, NULL);
		if (err) {
			TSAI_UNWIND_LOG("PABORT suspected! not accessible @%08x\n", ar->pc);
			to_handle_pabort = 1;
		}
	}

	ar->reg_extract_mask = 0xFFFF;

ParseFrame:
	ar->reg_extract_mask_prv = ar->reg_extract_mask;
	ar->reg_extract_mask = 0;

	if (param->max_depth && p->call_depth >= param->max_depth) {
		ret = 2;
		goto Leave;
	}
	/* if first frame is PABORT, then this can check thumb mode again */
	ar->frame_is_thumb |= (ar->pc & 0x01);
	{
		char* path_buf;
		struct vm_area_struct* vma;
		path_buf = tsai_full_path_buffer[p->cpu_core].path_buffer;
		p->vw = tsai_find_vma_wrapper_by_addr(param->vma_mgr, ar->pc, param->tsk_mm, path_buf);
		vma = p->vw->vma;
		p->start = 0;
		if (vma && vma->vm_file) {
			path = tsai_get_full_path(&(vma->vm_file->f_path),path_buf, 256, &filename );
			if (IS_ERR(path)) {
				__asm("bkpt");
				ret = 0;
				goto Leave;
			}
			else {
				ts->func_name = 0;
				if (p->vw->symbol_key) {
					p->start = tsai_lookup_symbol(p->vw->symbol_key, ar->pc, vma->vm_start, &ts->func_name, &p->start_len);
				}
				TSAI_UNWIND_LOG("Frame #%d PC %08x SP %08x LR %08x R11 %08x R7 %08x %s %s @ %08x SP_Base %08x start %08x %s len 0x%x\n",
						p->call_depth, ar->pc, ar->sp, ar->lr, ar->fp, ar->r7, ar->frame_is_thumb?"Thumb":"ARM", path, vma->vm_start,
						ar->sp_end, p->start, p->start? ts->func_name : "", p->start_len);
				TSAI_UNWIND_LOG("reg mask = %08x\n", ar->reg_extract_mask_prv);

				if (0 && strcmp("/usr/lib/libCOREGL.so.4.0", path)==0) {
					__asm("bkpt");
				}
			}
		}
		else {
			ret = 0;
			__asm("bkpt");
			goto Leave;
		}
	}

	if (param->user_trace_simple) {
		struct TSAI_USER_TRACE_SIMPLE simple;
		simple.pc = ar->pc;
		simple.sp = ar->sp;
		simple.reg = ar;
		simple.data = param->data;
		ret_trace = (*param->user_trace_simple)(&simple);
		if (ret_trace > 0) {
			ret = 2;
			TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
			goto Leave;
		}
	}

	tsai_frame_details_clear(fde);
	tsai_instruction_cache_init(im);

#if 0 /* test particular case*/
	if (!to_handle_pabort && p->start && strcmp(p->func_name, "init_export")==0) {
		__asm("bkpt");
	}
#endif


	tsai_lookup_arm_exidx(p);

	if (to_handle_pabort) {
		/* there are several possible scenario
		 * 1. pc is at begin of a function, in this case, R14 is expected to be valid
		 * 2. the function is extremely big and it has just moved across page boundary, in this case, LR likely not valid
		 * */
		if (p->start && !fde->f_start_suspicious) {
			/* if start address is known, and it's not right at start, then it's a long function*/
			if (!tsai_compare_address_ignore_thumbbit(p->start, ar->pc)) {
				/* it is likely a long function, there is no information on where previous valid execution code is
				 * see if special known function handler can solve this?
				 * */
				ret_trace = tsai_special_case_by_function_name(p);
				if (ret_trace) {
					TSAI_UNWIND_LOG(" PREFETCH ABORT HANDLED by special function handling %s\n", p->func_name);
					to_handle_pabort = 0;
					goto FinishHandlePAbort;
				}
			}

		}

		ret_trace = tsai_examine_lr_at_first_frame(p);
		if (!ret_trace) {
			/* give up and try to recover as much as possible */
			int ret_recover = 0;
			if (param->user_recover)
				ret_recover = (param->user_recover)(ar, param->data);
			if (ret_trace) {
				ret = 0;
				TSAI_UNWIND_LOG("recover and move on, ret_recover=%d @%d\n", ret_recover, __LINE__);
				goto Leave;
			}
			else {
				TSAI_UNWIND_LOG("FAILED AND CANNOT RECOVER! ret_recover=%d @%d\n", ret_recover, __LINE__);
				ret = 0;
				goto Leave;
			}
		}
		else if (param->user_trace) {
			struct TSAI_USER_TRACE tt;
			memset(&tt, 0, sizeof(tt));
			tt.pc = ar->pc_saved;
			tt.sp_func_start = ar->sp;
			tt.sp_unwind = ar->sp_saved;
			tt.lr_st_addr = 0;
			tt.data = param->data;

			ret_trace = (*param->user_trace)(&tt);
			TSAI_UNWIND_LOG(" PREFETCH ABORT HANDLED\n", 0);
			if (ret_trace > 0) {
				ret = 2;
				TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
				goto Leave;
			}

			ar->pc = ar->lr;
			ar->pc_saved = ar->pc;
			ar->frame_is_thumb = (ar->pc & 1);

			p->call_depth++;
			to_handle_pabort = 0;
			goto ParseFrame;
		}
FinishHandlePAbort:
		;
	}

	if (p->start && ts->func_name && ts->func_name[0]) {
		if (tsai_check_termination_sym_name(ts->func_name)) {
			if (param->user_trace) {
				struct TSAI_USER_TRACE tt;
				memset(&tt, 0, sizeof(tt));
				tt.pc = ar->pc_saved;
				tt.sp_func_start = ar->sp;
				tt.sp_unwind = ar->sp_saved;
				tt.lr_st_addr = fde->st_r14_retrieve;
				tt.data = param->data;

				ret_trace = (*param->user_trace)(&tt);
				if (ret_trace > 0) {
					ret = 2;
					TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
					goto Leave;
				}
			}
			TSAI_UNWIND_LOG("callstack reconstruction successful due to reach %s\n", ts->func_name);
			ret = 1;
			goto Leave;
		}
		/* special case handling, such as big jump table which will take a long time to parse */
		tsai_special_case_by_function_name(p);
	}

	if (tsai_apply_exidx(p) ) {

		if (param->user_trace) {
			struct TSAI_USER_TRACE tt;
			memset(&tt, 0, sizeof(tt));
			tt.pc = ar->pc_saved;
			tt.sp_func_start = ar->sp;
			tt.sp_unwind = ar->sp_saved;
			tt.lr_st_addr = fde->st_r14_retrieve;
			tt.data = param->data;
			ret_trace = (*param->user_trace)(&tt);
			if (ret_trace > 0) {
				ret = 2;
				TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
				goto Leave;
			}
		}

		ar->pc = ar->lr;
		ar->pc_saved = ar->pc;
		ar->frame_is_thumb = (ar->pc & 1);

		p->call_depth++;
		TSAI_UNWIND_LOG(" EXIDX applied succesfully @%d\n", __LINE__);
		goto ParseFrame;
	}

	if (p->call_depth==0) { /* before parsing any instructions */
		unsigned int jump_target;
		TSAI_UNWIND_LOG("First Frame, checking... ARM/Thumb mode=%d @%d\n",
				ar->frame_is_thumb , __LINE__);

		/* there are some observed cases when in thumb mode, the PC point to
		 * 4778 bx pc
		 * ignore this frame and use the LR to find caller frame
		 * */
		if (ar->frame_is_thumb) {
			int ok;
			ok = tsai_get_user_data_caution(p->mm, ar->pc, 2, &insn);
			TSAI_UNWIND_LOG("First Frame pc %08x insn %08x @%d\n",
					ar->pc, insn , __LINE__);

			if (insn==0x4778) {
				TSAI_UNWIND_LOG("%08x %08x BX PC, directly use R14 %08x to unwind @%d\n",
						ar->pc, insn, ar->lr, __LINE__);
				fde->can_unwind_now = 1;
				goto UnwindNow;
			}
		}

		/* it may be just about to (but not yet) enter a jump table, so before parsing any instructions, examine whether we are in a jump table
           NSR:00B7:B0C6EBC8|018E9B99            strexeq r9,r9,[r14]
==========>NSR:00B7:B0C6EBCC|E59FC004            ldr     r12,0xB0C6EBD8   ; r12,=0xB2039AC5
           NSR:00B7:B0C6EBD0|E08FC00C            add     r12,pc,r12
           NSR:00B7:B0C6EBD4|E12FFF1C            bx      r12
           NSR:00B7:B0C6EBD8|013CAEED            teqeq   r12,r13,ror #0x1D
		 */
		if (tsai_is_PLT_table(p, ar->pc, ar, ar->frame_is_thumb, 1, &jump_target)) {
			TSAI_UNWIND_LOG("%08x is PLT table, target %08x, can unwind @%d\n", ar->pc, jump_target, __LINE__);
			{
				char* path_buf;
				char* filename_target;
				struct vm_area_struct* vma;
				struct TSAI_VMA_WRAPPER* vw_target;
				path_buf = tsai_full_path_buffer[p->cpu_core].path_buffer;
				vw_target = tsai_find_vma_wrapper_by_addr(param->vma_mgr, jump_target, param->tsk_mm, path_buf);
				vma = vw_target->vma;
				if (vma && vma->vm_file) {
					path = tsai_get_full_path(&(vma->vm_file->f_path),path_buf, 256, &filename_target );
					if (IS_ERR(path)) {
					}
					else {
						if (vw_target->symbol_key) {
							const char* func_name_target;
							unsigned int code_len_target;
							unsigned int start_target;
							start_target = tsai_lookup_symbol(vw_target->symbol_key, jump_target, vma->vm_start, &func_name_target, &code_len_target);
							TSAI_UNWIND_LOG("Target %08x %s %s @%d\n", start_target, func_name_target, filename_target, __LINE__);
						}
						else
							TSAI_UNWIND_LOG("Target %s @%d\n", filename_target, __LINE__);
					}
				}
			}
			fde->plt_target = jump_target;
			fde->can_unwind_now = 1;
			goto UnwindNow;
		}

		tsai_examine_lr_at_first_frame(p);

	}

	while (1) {
		int ok;
		struct tsai_instruction_cache* ic;
		th_mode = ar->frame_is_thumb;

		/* if the function start address is known, don't parse beyond the entry point,
		 * when it's frame frame PC may point right at function entry point
		 * */
		if (p->start && (PC_NO_THUMB(ar->pc) <= p->start) ) {
			goto UnwindNow;
		}

		/* THUMB addresses have 0 bit set, which is identical to
		 * `pc + 1'. In order to read correct `pc' we need to adjust
		 * pc address. */
		/* we read 4 bytes for ARM mode and 2 bytes for THUMB.
		 * Take special care of THUMB16/THUMB32 mode instructions */
		if (th_mode) {
			unsigned int first_two_byte;
			unsigned pc_tmp;
			unsigned t32_sig;
			ar->pc -= 2;
			pc_tmp = PC_NO_THUMB(ar->pc - 2);

			ok = tsai_get_user_data_caution(p->mm, pc_tmp, 4, &insn);
			while (ok) {
				ar->pc = ( (ar->pc - 4096) | (4096-1)) - 4 ; /* the last 4 bytes of a page*/
				pc_tmp = PC_NO_THUMB(ar->pc - 2);
				ok = tsai_get_user_data_caution(p->mm, pc_tmp, 4, &insn);
			}

			/* TSAI: note, Thumb32 bit should be consider as 2 x 16bit,
			 * eg.
			 * F7DFEF86            blx     0x424D901C
			 * in the memory F7DF will appear first, followed by 0xEF86
			 * if loading 4 bytes togethr, because of endian, F7DF might end up in the lo byte
			 * */
			/* detect possible data embedded alone with instructions
			 * eg:
			 * 0017B5BA               dcd     0x17B5BA
			 * E92D47F0  coregl_init.:push    {r4-r10,r14}
			 * */
			if ( (data_encountered = tsai_detect_data_in_code(p, pc_tmp, insn )) ) {
				ar->pc = (pc_tmp - data_encountered ) + 4;
				ok = tsai_get_user_data_caution(p->mm, ar->pc, 4, &insn);
				goto PrepareParam;
			}

			insn = (insn & 0x0000FFFF) << 16 | (insn & 0xFFFF0000) >> 16;

			t32_sig = (insn) >> 27;
			if (t32_sig == 0b11101 || t32_sig == 0b11110 || t32_sig == 0b11111) {
				p->armthumb = 2;
				ar->pc -= 2;
			}
			else {
				p->armthumb = 1;
				insn &= 0x0000FFFF;
			}

		} else {
			ar->pc -= 4;
			p->armthumb = 0;
			ok = tsai_get_user_data_caution(p->mm, ar->pc, 4, &insn);
			while (ok) {
				ar->pc -= 4096;
				ok = tsai_get_user_data_caution(p->mm, ar->pc, 4, &insn);
			}

			if ( (data_encountered = tsai_detect_data_in_code(p, ar->pc, insn )) ) {
				ar->pc = (ar->pc - data_encountered ) + 4;
				ok = tsai_get_user_data_caution(p->mm, ar->pc, 4, &insn);
			}
		}
PrepareParam:
		ic = tsai_instruction_cache_obtain(im); ic->hex_code = insn; ic->PC = ar->pc; ic->armthumb = p->armthumb;
		p->ic = ic;
#ifdef DEBUG
		if (tsai_callstack_break_at_pc && ( PC_NO_THUMB(ar->pc)== PC_NO_THUMB(tsai_callstack_break_at_pc) )) {
			__asm("bkpt");
		}
		if (tsai_callstack_break_at_insn && insn==tsai_callstack_break_at_insn) {
			__asm("bkpt");
		}
#endif
		if (data_encountered)
			tsai_handle_data_insn(p, data_encountered);
		else if (th_mode)
			tsai_handle_thumb_insn(p);
		else
			tsai_handle_arm_insn(p);

		ASSERT(ar->pc < (p->mm->task_size) );
		ic->SP = ar->sp;
		if (!p->start || fde->f_start_suspicious) {

			ret_trace = tsai_detect_begin_function(p);
			if (ret_trace < 0) {

				if (param->user_trace) {
					struct TSAI_USER_TRACE tt;
					memset(&tt, 0, sizeof(tt));
					tt.pc = ar->pc_saved;
					tt.sp_func_start = ar->sp;
					tt.sp_unwind = ar->sp_saved;
					tt.lr_st_addr = 0; /* LR is invalid if return code < 0*/
					tt.data = param->data;

					ret_trace = (param->user_trace)(&tt);
					TSAI_UNWIND_LOG("user_trace return %d \n", ret_trace);
					if (ret_trace > 0) { /* there are copied frame, no need to recover again */
						ret = 0;
						TSAI_UNWIND_LOG("Frame %d Detect function begin fail, copied previous valid frames \n", p->call_depth);
						goto Leave;
					}

					if (param->user_recover)
						ret_trace = (param->user_recover)(ar, param->data);
					else
						ret_trace = 0;

					if (ret_trace) {
						ret = 0;
						TSAI_UNWIND_LOG("Frame %d recover and move on @%d\n", p->call_depth, __LINE__);
						goto Leave;
					}
				}

				TSAI_UNWIND_LOG("FAILED AND CANNOT RECOVER! @%d\n", __LINE__);
				if (tsai_bkpt_disasm)
					__asm("bkpt");
				ret = 0;
				goto Leave;
			}


		}
		/* detect conditional basic block */
		tsai_detect_cond_basic_block(p);

		if (!ar->pc) {
			ret = 0;
			__asm("bkpt");
			goto Leave;
		}

		if (fde->cannot_continue) {
			if (fde->cannot_continue==T_INFINITE_LOOP) {
				ret = 0;
				goto Leave;
			}
			else { /* unclear, check what is going on */
				__asm("bkpt");
				ret = -1;
				goto Leave;
			}
		}

UnwindNow:
		if ( (p->start && ( PC_NO_THUMB(ar->pc) <= p->start) ) || fde->can_unwind_now)
		{
			/* special case handling, in ld.so _dl_runtime_resolve didn't push R14 to stack but its caller did, so we can get educated guess */
			if (p->start) {
				int lrok;
				if (ts->func_name && strcmp(ts->func_name, "_dl_runtime_resolve")==0)
				{
					tsai_get_user_data_caution(p->mm, ar->sp, 4, &ar->lr);
					tsai_frame_details_return_retrieve(fde, ar, ic, ARM_LR_REGNUM, ar->sp);
					lrok = tsai_examine_lr_valid(p, 0, 0);
					if (lrok) {
						ar->sp += 0x4; /* the caller of _dl_runtime_resolve appears to use these bytes? */
						TSAI_UNWIND_LOG("ld.so _dl_runtime_resolve guess LR=%08x SP %08x OK\n", ar->lr, ar->sp);
					}
					else {
						__asm("bkpt");
						TSAI_UNWIND_LOG("ld.so _dl_runtime_resolve guess LR=%08x NOT OK, give up\n", ar->lr);
						ret = -1;
						goto Leave;
					}
				}
				else {
					/* even if with symbol help, still better check if LR address make sense! */
					if (fde->f_r14_examined)
						lrok = fde->f_r14_valid;
					else
						lrok = tsai_examine_lr_valid(p, 0, 0);
					if (!lrok) {
#ifdef DEBUG
						if (tsai_bkpt_disasm)
						__asm("bkpt");
#endif

						TSAI_UNWIND_LOG("Even with symbol LR %08x not OK @%d\n", ar->lr, __LINE__);
						if (param->user_trace) {
							struct TSAI_USER_TRACE tt;
							memset(&tt, 0, sizeof(tt));
							tt.pc = ar->pc_saved;
							tt.sp_func_start = ar->sp;
							tt.sp_unwind = ar->sp_saved;
							tt.lr_st_addr = 0; /* since LR is invalid no point of providing stack address for it*/
							tt.data = param->data;

							ret_trace = (param->user_trace)(&tt);
							if (ret_trace > 0) {
								ret = 2;
								TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
								goto Leave;
							}
						}

						if (ret_trace > 0) {
							ret = 0;
							goto Leave;
						}

						if (param->user_recover)
							ret_trace = (param->user_recover)(ar, param->data);
						else
							ret_trace = 0;

						if (ret_trace) {
							TSAI_UNWIND_LOG("recover and move on @%d\n", __LINE__);
							ret = 0;
							goto Leave;
						}
						else {
							ret = 0;
							goto Leave;
						}
					}
				}
			}

			if (ar->lr == INSN_ERR) {
				__asm("bkpt");
				goto Leave;
			}

			if (param->user_trace) {
				struct TSAI_USER_TRACE tt;
				memset(&tt, 0, sizeof(tt));
				tt.pc = ar->pc_saved;
				tt.sp_func_start = ar->sp;
				tt.sp_unwind = ar->sp_saved;
				tt.lr_st_addr = fde->st_r14_retrieve;
				tt.data = param->data;
				tt.plt_target = fde->plt_target;

				ret_trace = (*param->user_trace)(&tt);
				if (ret_trace > 0) {
					ret = 2;
					TSAI_UNWIND_LOG("user_trace return > 0, early out ret_trace %d @%d\n", ret_trace, __LINE__);
					goto Leave;
				}
			}

			ar->pc = ar->lr;
			ar->lr = 0;
			ar->pc_saved = ar->pc;
			ar->sp_saved = ar->sp;
			ar->frame_is_thumb = (ar->pc & 0x01);

			fde->flags &= ~KUBT_FLAG_FUNC_EPILOGUE;

			if (last_sp >= ar->sp) {
				pr_err("KUBT: abort backtracing at SP: %x\n",
						ar->sp);
				__asm("bkpt");
				goto Leave;
			}
			last_sp = ar->sp;
			limit--;
			if (unlikely(limit < 1)) {
				pr_err("KUBT: abort backtracing at SP: %x\n",
						(unsigned int)ar->sp);
				__asm("bkpt");
				goto Leave;
			}

			p->call_depth++;
			goto ParseFrame;
		}
	}
Leave:
	tsai_mmu_pfn_reset();
	tsai_fake_stack_put(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	preempt_enable();
	local_irq_restore(flags);
	return ret;
}

#include <linux/highmem.h> /* flush_cache_range */

/* apply the unwind information from exidx,
 * return 1: if exidx info is useful and tentative unwind is successful */
int tsai_apply_exidx(struct tsai_handle_insn_param* pa) {
	int i;
	int j;
	int ret = 0;
	int r;
	struct tsai_intermediate_regs* ar;
	unsigned int insn = 0;
	int lrpop = 0;
	int lrok = 0;
	struct tsai_handle_insn_param* p;
	struct tsai_frame_details* fde;
	struct tsai_instruction_cache_mgr* im;

	struct TMP_PARSE_USER_CALLSTACK {
		struct tsai_intermediate_regs ar_stack;
		struct tsai_handle_insn_param param;
		struct tsai_frame_details f;
		struct tsai_instruction_cache_mgr im;
	};
	struct TSAI_FAKE_STACK_TICKET ticket;
	struct TMP_PARSE_USER_CALLSTACK* ts =
			(struct TMP_PARSE_USER_CALLSTACK*)tsai_fake_stack_get(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);

	if (!pa->exidx->count)
		goto Leave;

	pa->f_start_found = 0;
	p = &ts->param;
	*p = *pa;
	fde = &ts->f;
	ar = &ts->ar_stack;
	im = &ts->im;

	*ar = *(pa->ar);

	ar->pc_saved = ar->pc;
	ar->frame_is_thumb = (ar->pc & 0x01);

	p->ar = ar; p->fde = fde; p->start = pa->start;

	tsai_frame_details_clear(fde);
	tsai_instruction_cache_init(im);

	TSAI_UNWIND_LOG("ApplyExidx record function entry %08x, pc %08x @%d\n", p->exidx->function_entry_point, ar->pc, __LINE__);
	if (p->call_depth==0) {
		/* first frame could be right point to entry point, or early out block, epilogue, and has higher risk of not able to apply EXIDX */
		unsigned int threshold;
		unsigned int distance;
		if (p->ar->frame_is_thumb)
			threshold = 0x10;
		else
			threshold = 0x20;

		if (p->start)
			distance = (ar->pc - p->start);
		else
			distance = (ar->pc - p->exidx->function_entry_point);

		if (threshold >= distance ) {
			TSAI_UNWIND_LOG("ApplyExidx first frame and distance %08x to function entry is too close, not applying @%d\n",
					distance, __LINE__);
			goto Leave;
		}
	}

	for (i=0; i< p->exidx->count ; i++) {
		switch (p->exidx->inst[i].mnemonic) {
		case ARM_EXIDX_CMD_REG_POP:
			{
				unsigned int reg_list = p->exidx->inst[i].reg_list;
				TSAI_UNWIND_LOG("ApplyExidx %s reglist %08x @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic], reg_list, __LINE__);
				for (j=0; reg_list; j++, reg_list >>= 1) {
					if (reg_list & 0x1) {
						r = tsai_get_user_data_caution(pa->mm, ar->sp, 4, &(ar->R[j]) );
						if (r) {
							/* it could be SP is an insane value, or genuinely the stack memory has been swapped out */
							if (tsai_check_register_value(p, ARM_SP_REGNUM, ar->sp)) {
								__asm("bkpt");
							}
							goto Leave;
						}
						ar->reg_extract_mask |= 1<<j;
						if (j==ARM_LR_REGNUM) {
							tsai_frame_details_return_retrieve(fde, ar, 0, ARM_LR_REGNUM, ar->sp);
							lrpop = 1;
						}
						TSAI_UNWIND_LOG("R%d=%08x loaded from stack %08x @%d\n", j, ar->R[j], ar->sp, __LINE__);
						ar->sp += 4;
					}
				}
			}
			break;
		case ARM_EXIDX_CMD_REG_TO_SP:
			{
				int rn = p->exidx->inst[i].reg_num;
				if (ar->reg_extract_mask & (1<<rn) ) {
					ar->sp = ar->R[rn];

					TSAI_UNWIND_LOG("ApplyExidx %s sp=R[%d]=%08x @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic],
						p->exidx->inst[i].reg_num, ar->sp ,__LINE__);

					if (tsai_check_register_value(p, ARM_SP_REGNUM, ar->sp)) {
						TSAI_UNWIND_LOG("ApplyExidx SP value %08x invalid, abort @%d\n", ar->sp ,__LINE__);
						goto Leave;
					}
				}
				else {
					TSAI_UNWIND_LOG("ApplyExidx %s sp=R[%d] but R[%d]=%08x value not sure @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic],
						rn, rn, ar->R[rn], __LINE__);

					if (tsai_check_register_value(p, ARM_SP_REGNUM, ar->R[rn])==0) {
						/* This register contains a sensible value, give it a second try */
						ar->sp = ar->R[rn];
						TSAI_UNWIND_LOG("ApplyExidx %s sp=R[%d]=%08x TENTATIVE TRY @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic],
							p->exidx->inst[i].reg_num, ar->sp ,__LINE__);
					}
					else {
						goto Leave;
					}
				}
			}
			break;
		case ARM_EXIDX_CMD_DATA_PUSH:
		case ARM_EXIDX_CMD_DATA_POP:
			ar->sp += p->exidx->inst[i].vsp_offset;
			TSAI_UNWIND_LOG("ApplyExidx %s sp +[%d]=%08x @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic],
					p->exidx->inst[i].vsp_offset, ar->sp ,__LINE__);
			break;
		case ARM_EXIDX_CMD_VFP_POP:
			{
				unsigned int reg_list = p->exidx->inst[i].reg_list;
				TSAI_UNWIND_LOG("ApplyExidx %s reglist %08x @%d\n", STR_ARM_EXIDX_CMD[p->exidx->inst[i].mnemonic], reg_list, __LINE__);

				for (j=0; reg_list; j++, reg_list >>= 1) {
					if (reg_list & 0x1) {
						ar->sp += 8;
					}
				}
			}
			break;
		case ARM_EXIDX_CMD_FINISH:
			goto ExamineLR;
			break;
		default:
			__asm("bkpt");
		}
	}
ExamineLR:
	lrok = tsai_examine_lr_valid(p, 1, lrpop==0);
	if (lrok) {
		if (p->call_depth==0 && lrpop==0) {
			TSAI_UNWIND_LOG("ApplyExidx first frame and not get valid LR from stack, not applying EXIDX @%d\n", __LINE__);
		}
		else {
			*pa->ar = *ar;
			pa->fde->st_r14_retrieve = p->fde->st_r14_retrieve;
			pa->fde->pc_r14_retrieve = p->fde->pc_r14_retrieve;

			ret = 1;
		}
	}
Leave:
	tsai_fake_stack_put(sizeof(struct TMP_PARSE_USER_CALLSTACK), &ticket);
	return ret;
}

/* make a 32bit signed value from pre-31 value */
#define SIGNED_31(x) (( ((x)<<1) & 0x80000000) | (x))
#define FUNC_ADDR(tbl,offset) (void*)( (char*)(tbl) + (offset) )

void tsai_force_load_address(struct tsai_handle_insn_param* p, unsigned int addr) {
	int ret;
	int is_atomic;
	is_atomic = preempt_count();
	if (!is_atomic)
		down_write(&p->mm->mmap_sem);
	flush_cache_range(p->vw->vma, p->vw->vma->vm_start, p->vw->vma->vm_end); /* Invalidating all cache entries for vma range */
	ret = handle_mm_fault(p->mm, p->vw->vma, addr & PAGE_MASK, FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE | FAULT_FLAG_USER);
	flush_tlb_range(p->vw->vma, p->vw->vma->vm_start, p->vw->vma->vm_end); /* Ensuring MMU/TLB doesn't contain stale translation */
	if (!is_atomic)
		up_write(&p->mm->mmap_sem);
}

unsigned int tsai_get_exidx_ins(unsigned int* tbl_entry, int offset) {
	int word_offset = offset >> 2;
	int byte_offset = offset & 0x3;
	int bits = 24 - (byte_offset << 3);

	return (tbl_entry[word_offset] >> bits) & 0xFF;
}

/* offset: between 0..3 */
int tsai_decode_exidx(unsigned int* tbl_entry, int offset, struct TSAI_EXIDX_UNWIND* exidx) {
	int i;
	int offset_end = offset + exidx->count;
	int j;
	for (i=0; offset<offset_end; i++, offset++) {
		unsigned int ins1 = tsai_get_exidx_ins(tbl_entry, offset);
		unsigned int ins2 = tsai_get_exidx_ins(tbl_entry, offset+1);

		if (__BIT(ins1, 7)==0) {
			if (__BIT(ins1, 6)==0) { /* pop */
				exidx->inst[i].mnemonic = ARM_EXIDX_CMD_DATA_POP;
				exidx->inst[i].vsp_offset = (__BITS(ins1, 0, 5) << 2) + 4;
			}
			else {
				exidx->inst[i].mnemonic = ARM_EXIDX_CMD_DATA_PUSH;
				exidx->inst[i].vsp_offset = -((__BITS(ins1, 0, 5) << 2) + 4);
			}
		}
		else {
			if (__BIT(ins1, 6)==0) {
				if (__BIT(ins1, 5)==0) { /* 100.....*/
					if (ins1==0x80 && ins2==0)
						exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REFUSED;
					else if (__BIT(ins1, 4)==0) { /* 1000....*/
						exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REG_POP;
						exidx->inst[i].reg_list = ( (ins1 & 0b1111)<< 8 | ins2) << 4;
						offset++;
					}
					else { /* 1001....*/
						exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REG_TO_SP;
						exidx->inst[i].reg_num = (ins1 & 0b1111);
					}
				}
				else { /* 101.....*/
					if (__BIT(ins1, 4)==0) { /* 1010....*/
						if (__BIT(ins1, 3)==0) { /* 10100...*/
							unsigned int reg = __BITS(ins1, 0,2);
							exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REG_POP;
							exidx->inst[i].reg_list = 0;
							for (j=0; j<=reg; j++)
								exidx->inst[i].reg_list |= 1 << (j+4);
						}
						else { /* 10101...*/
							unsigned int reg = __BITS(ins1, 0,2);
							exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REG_POP;
							exidx->inst[i].reg_list = 1 << 14;
							for (j=0; j<=reg; j++)
								exidx->inst[i].reg_list |= 1 << (j+4);
						}
					}
					else { /* 1011*/
						if (__BIT(ins1, 3)==0) { /* 10110...*/
							if (ins1==0xB0)
								exidx->inst[i].mnemonic = ARM_EXIDX_CMD_FINISH;
							else if (__BIT(ins1, 1)==0 ) { /* 1011000.*/
								/* 10110001 */
								exidx->inst[i].mnemonic = ARM_EXIDX_CMD_REG_POP;
								exidx->inst[i].reg_list = ins2 & 0b1111;
								offset++;
							}
							else { /* 1011001.*/
								if (__BIT(ins1, 0)==0 ) { /* 10110010 */
									exidx->inst[i].mnemonic = ARM_EXIDX_CMD_DATA_POP;
									exidx->inst[i].vsp_offset = 0x204 + (ins2<<2);
									offset++;
								}
								else
									__asm("bkpt");
							}
						}
						else { /* 10111*/
							unsigned int reg = __BITS(ins1, 0,2);
							exidx->inst[i].mnemonic = ARM_EXIDX_CMD_VFP_POP;
							exidx->inst[i].reg_list = 0;
							for (j=0; j<=reg; j++)
								exidx->inst[i].reg_list |= 1 << (j+8);
						}
					}
				}
			}
			else { /* 11 */
				if (__BIT(ins1, 5)==0) { /* 110 */
					if (__BIT(ins1, 4)==0) { /* 1100 */
						if (__BIT(ins1, 3)==0) { /* 11000 */
							__asm("bkpt");
						}
						else { /* 11001 */
							unsigned int ssss;
							unsigned int cccc;
							if (__BITS(ins1, 0,2)==0) { /*11001000 sssscccc Pop VFP double precision registers
							D[16+ssss]-D[16+ssss+cccc] saved (as if) by VPUSH (see remarks d,e)*/
								ssss = __BITS(ins2, 4, 7);
								cccc = __BITS(ins2, 0, 3);
								for (j=0; j<=cccc; j++)
									exidx->inst[i].reg_list |= 1 << (16+ssss+j);

								offset++;
								__asm("bkpt");
							}
							else if (__BITS(ins1, 0,2)==1){ /*11001001 sssscccc Pop VFP double precision registers D[ssss]-D[ssss+cccc] saved (as if) by VPUSH
								(see remark d)*/
								ssss = __BITS(ins2, 4, 7);
								cccc = __BITS(ins2, 0, 3);
								exidx->inst[i].mnemonic = ARM_EXIDX_CMD_VFP_POP;
								exidx->inst[i].reg_list = 0;
								for (j=0; j<=cccc; j++)
									exidx->inst[i].reg_list |= 1 << (ssss+j);

								offset++;
							}
							else
								__asm("bkpt");
						}
					}
					else { /* 1101 */
						unsigned int reg = __BITS(ins1, 0, 2);
						exidx->inst[i].mnemonic = ARM_EXIDX_CMD_VFP_POP;
						exidx->inst[i].reg_list = 0;
						for (j=0; j<=reg; j++)
							exidx->inst[i].reg_list |= 1 << (j+8);
					}
				}
				else { /* 111 */
					__asm("bkpt");
				}
			}
		}

	}

	exidx->inst[i].mnemonic = 0;
	exidx->count = i;

	return 1;
}

#include <linux/elf.h>
#include <linux/mmu_context.h>
#include <linux/vmalloc.h>


unsigned int tsai_force_read_user(struct tsai_handle_insn_param* p, unsigned int addr) {
	long ret = 0;
	unsigned int insn = 0;
	do {
		ret = __copy_from_user(&insn, (void *)addr, 4);
		if (ret) {
			tsai_force_load_address(p, addr);
			ret = __copy_from_user(&insn, (void *)addr, 4);
		}
	}while(0);
	return insn;
}

/* try to find PLT section if possible
 * return:
 * 0=OK
 * otherwise = error code
 * */
int tsai_vma_walk_section_header(struct TSAI_VMA_WRAPPER* vw) {
	int idx;
	int ret;
	unsigned int insn;
	struct mm_struct *mm = vw->vma->vm_mm;
	struct mm_struct* saved_mm;
	int save_mm = 0;
	int atomic_context = preempt_count();

	Elf32_Phdr* pPhdr;
	Elf32_Ehdr*	pEhdr;
	Elf32_Shdr* pShdr;
	Elf32_Shdr* lShdr;
	tsai_backup_mm(&save_mm, &saved_mm, mm);

	ret = tsai_get_user_data_caution(mm, vw->vm_start, 4, &insn);
	if (ret) {
		goto Leave;
	}

	/* verify ELF magic, C# binaries would not be in ELF format */
	if (memcmp(&insn, (void*)ELFMAG, 4)) {
		vw->f_non_elf = 1;
		goto Leave;
	}

	pEhdr = (Elf32_Ehdr*)vw->vm_start;
	pPhdr = (Elf32_Phdr*)(vw->vm_start + pEhdr->e_phoff);

	/* walk through program header */
	for (idx=0; idx < pEhdr->e_phnum; idx++ ) {
		if (pPhdr[idx].p_type == PT_LOAD && (pPhdr[idx].p_flags & PF_X)==PF_X ) {
			vw->vaddr = pPhdr[idx].p_vaddr;
		}
		else if (pPhdr[idx].p_type == 0x70000001) { /* PT_ARM_EXIDX = 0x70000001*/
			if (!vw->arm_exidx) {
				unsigned int addr = vw->vm_start + pPhdr[idx].p_offset;
				vw->arm_exidx = (void*)addr;
				vw->arm_exidx_size = pPhdr[idx].p_memsz;
				vw->arm_exidx_offset = pPhdr[idx].p_offset;
			}
		}
	}

	if (!atomic_context) {
		/* EXIDX content may have not been read from filesystem into memory yet */
		if (vw->arm_exidx) {
			unsigned int p = (unsigned int)vw->arm_exidx;
			unsigned int p_end = p + vw->arm_exidx_size;
			p &= ~(4096-1);
			for (;p<p_end; p += 4096) {
				ret = tsai_get_user_data_caution(mm, p, 4, &insn);
				if (ret) {
					goto Leave;
				}
			}
		}
	}

	/* walk through section header, note section headers are not loaded into memory so it has to be read from the filesystem
	 * access to filesystem is not allowed during atomic context */
	if (!atomic_context) {
		Elf32_Shdr* sh;
		void* pMem;
		loff_t file_cursor;
		unsigned int bytesTotal = pEhdr->e_shnum * sizeof(Elf32_Shdr);
		pMem = kmalloc(bytesTotal, GFP_KERNEL);
		file_cursor = pEhdr->e_shoff;
		__vfs_read(vw->vma->vm_file, pMem, bytesTotal, &file_cursor);
		sh = (Elf32_Shdr*)pMem;
		for (idx=0; idx < pEhdr->e_shnum; idx++, sh++) {
			//const char* sh_name = sh_str + sh[i].sh_name;

			if (sh->sh_type==SHT_PROGBITS && ( (sh->sh_flags & (SHF_EXECINSTR|SHF_ALLOC))==(SHF_EXECINSTR|SHF_ALLOC) ) &&
					sh->sh_entsize )
			{
				if (!vw->plt)
					vw->plt = (void*)(sh->sh_offset + vw->vm_start);
			}
			else if (vw->arm_exidx && sh->sh_type==SHT_PROGBITS && ( (sh->sh_flags & (SHF_EXECINSTR|SHF_ALLOC))==(SHF_ALLOC) ) &&
					sh->sh_entsize==0 && (sh->sh_offset < vw->arm_exidx_offset) && sh->sh_addralign==4)
			{
				/* this is .ARM.extab */
				if (!vw->arm_extab) {
					vw->arm_extab = (void*)(sh->sh_offset + vw->vm_start);
					vw->arm_extab_size = sh->sh_size;
				}
			}
		}

		if (vw->arm_extab) {
			unsigned int p = (unsigned int)vw->arm_extab;
			unsigned int p_end = p + vw->arm_extab_size;
			p &= ~(4096-1);
			for (;p<p_end; p += 4096) {
				ret = tsai_get_user_data_caution(mm, p, 4, &insn);
				if (ret) {
					goto Leave;
				}
			}
		}

		kfree(pMem);
	}

	ret = 0;
Leave:
	tsai_restore_mm(&save_mm, &saved_mm);
	return ret;
}

/* return:
 * 0=OK, otherwise error code
 * */
int tsai_lookup_arm_exidx(struct tsai_handle_insn_param* p) {
	int ret = 0;
	int exidx_ok = 0;
	unsigned int insn;
	p->exidx->count = 0;
	if (!p->vw->arm_exidx) {
		tsai_vma_walk_section_header(p->vw);
	}

	if (p->vw->arm_exidx) {
		struct T {
			unsigned int key;
			unsigned int value;
		};
		int iterations = 0;
		struct T *lo, *hi, *mid, *found = 0;
		void *lo_off, *hi_off, *mid_off, *found_func = 0;
		unsigned int lo_key, hi_key, mid_key;
		void *func = (void*)(p->ar->pc);
		lo = (struct T*)p->vw->arm_exidx;
		hi = lo + (p->vw->arm_exidx_size / 8) - 1;
		ret = tsai_get_user_data_caution(p->mm, (unsigned int)&lo->key, sizeof(lo->key), &lo_key);
		if (ret)
			goto Leave;
		lo_off = FUNC_ADDR(lo, SIGNED_31(lo_key));

		ret = tsai_get_user_data_caution(p->mm, (unsigned int)&hi->key, sizeof(hi->key), &hi_key);
		if (ret)
			goto Leave;
		hi_off = FUNC_ADDR(hi, SIGNED_31(hi_key));

		for (; (func >= lo_off) && (func <= hi_off) ;iterations++) {
			mid = (hi-lo)/2 + lo;
			ret = tsai_get_user_data_caution(p->mm, (unsigned int)&mid->key, sizeof(mid->key), &mid_key);
			if (ret)
				goto Leave;

			mid_off = FUNC_ADDR(mid, SIGNED_31( mid_key));

			if (func < mid_off) {
				hi = mid;
				hi_off = mid_off;
			}
			else if (func > mid_off) { /* this could be a hit! */
				if (lo==mid) {
					found = lo;
					found_func = mid_off;
					break;
				}
				lo = mid;
				lo_off = mid_off;
			}
			else {
				found = mid;
				found_func = mid_off;
				break;
			}
		}

		exidx_ok = 1;
		TSAI_UNWIND_LOG("EXIDX lookup iterations %d entry addr %08x key %08x value %08x @%d\n",
				iterations, (unsigned int)found, (unsigned int)(found?found->key:0), (unsigned int)(found?found->value:0) ,__LINE__);
		if (found) {
			int i;
			unsigned int* tbl_entry = 0;
			unsigned int entry_value;
			int inst_offset = 0;

			p->exidx->function_entry_point = (unsigned int)found_func;
			if (!p->start) {
				p->start = (unsigned int)found_func;
				p->fde->f_start_suspicious = 1;
				TSAI_UNWIND_LOG("EXIDX likely function start %08x @%d\n", p->start, __LINE__);
			}
			tsai_force_read_user(p, (unsigned int)found);
			if (found->value==1) { /* cannot unwind, just use the start address */
				goto Leave;
			}
			else if (found->value & 0x80000000) { /* key itself is an entry */
				tbl_entry = &found->value;
			}
			else {
				int off;
				off = SIGNED_31(found->value);
				tbl_entry = (unsigned int*)((char*)&found->value + off);
			}

			/* decode the table entry */
			ret = tsai_get_user_data_caution(p->mm, (unsigned int)&tbl_entry[0], sizeof(entry_value), &entry_value);
			if (ret) {
				TSAI_UNWIND_LOG(" tbl_entry %08x Not readable @%d \n", tbl_entry, __LINE__);
				goto Leave;
			}

			if (entry_value & 0x80000000) { /* compact */
				unsigned int index;
				index = __BITS(entry_value, 24, 27);
				if (index==0) {
					p->exidx->count = 3;
					inst_offset = 1;
				}
				else {
					p->exidx->count = 2 + (__BITS(entry_value, 16, 23))*4;
					inst_offset = 2;
				}
			}
			else { /* generic model */
				unsigned int entry_value_1;
				unsigned int index;
				int prs_offset;
				char* prs;
				prs_offset = SIGNED_31(entry_value );
				prs = (char*)&tbl_entry[0] + prs_offset;
				TSAI_UNWIND_LOG(" prs_offset %d prs=%08x @%d \n", prs_offset, prs);

				/* not sure what to do when there is personality func offset? */
				tbl_entry = &tbl_entry[1];
				ret = tsai_get_user_data_caution(p->mm, (unsigned int)&tbl_entry[0], sizeof(entry_value_1), &entry_value_1);
				if (ret)
					goto Leave;

				p->exidx->count = 3 + (__BITS(entry_value_1, 24, 27))*4;
				inst_offset = 1;
			}

			tsai_decode_exidx(tbl_entry, inst_offset, p->exidx);
		}
	}
Leave:
	if (!exidx_ok && p->vw->f_non_elf==0) {
		tsai_vma_mgr_add_defer_read(p->vma_mgr, p->vw);
	}
	return ret;
}


#include "../kernel/kdebugd/elf/kdbg_elf_sym_api.h"

static void kdbg_elf_find_func_name (kdbg_elf_usb_elf_list_item *plist,
		unsigned int idx, char *elf_sym_buff, unsigned int sym_len);


/* if plist->sym_buff is NULL, load to memory
 *
 * return: 1: success 0: nothing happen
 * */
static int tsai_elf_sym_string_reload(kdbg_elf_usb_elf_list_item *plist) {
	int ret = 0;
	if (plist->sym_str_offset && plist->sym_str_size) {
		struct file *elf_filp = NULL; /* File pointer to access file for ELF parsing*/
		char* elf_sym_buff = vmalloc(plist->sym_str_size);
		if (elf_sym_buff) {
			elf_filp = filp_open(plist->elf_name_actual_path, O_RDONLY | O_LARGEFILE, 0);
			if (elf_filp) {
				ssize_t bytesread;
				elf_filp->f_pos = plist->sym_str_offset;
				bytesread = vfs_read(elf_filp, elf_sym_buff, plist->sym_str_size, &elf_filp->f_pos);
				if (bytesread == plist->sym_str_size) {
					plist->sym_buff = (char*)elf_sym_buff;
					ret = 1;
				}
				else
					vfree(elf_sym_buff);
			}
		}
		if (elf_filp) {
			filp_close(elf_filp, NULL);
		}
	}
	return ret;
}


/* unsigned int address: please use calibrated address (adjusted by shifting plist->virtual_address)
 * original kdbg_elf_sym_find has bug, so I make my own version
 * fix the bug of PC is at begin of thumb function, but symbol value is (thumb function + 1)
 * start_addr:[out] the stated address of this symbol
 * start_len:[out] the stated size for this symbol in bytes. eg. how many hex byte does main() cotain
 * */
int tsai_elf_sym_find(unsigned int address,
		kdbg_elf_usb_elf_list_item *plist, const char** out_symbol_string,
		unsigned int *start_addr, unsigned int* start_len)
{
	kdbg_elf_kernel_symbol_item *beg = NULL, *end = NULL, *mid = NULL;
	kdbg_elf_kernel_symbol_item *temp_item = NULL;
	int ret = 1;
	int found = 0;
	const char* symbol_string;

	address &= ~1; /* clear thumb bit to avoid confusion */

	if (!plist) {
		printk("List is not availble\n");
		return -EINVAL;
	}

	if (!plist->sym_str_size) {
		printk("No DynSym and Sym Info present\n");
		return -EINVAL;
	}

	/* Array is sorted, Implement Binary Search alogorithm */
	/* Search for the address, if address not match exactly take the previouse
	 * value */

	/* Sanity check for existence*/
	beg = plist->kdbg_elf_sym_head;

	if (plist->elf_symbol_count > 0 && beg && (beg->st_value & ~1) <= address) {

		/* every thing store in array no need to verify pointer for existence*/
		end = plist->kdbg_elf_sym_head + (plist->elf_symbol_count - 1);

		while (beg <= end) {
			mid = beg + (end - beg)/2;
			/* is the address in lower or upper half? */
			if (address < (mid->st_value & ~1)  )
				end = mid - 1;     /* new end */
			else if (address == (mid->st_value & ~1) ) {
				found = 1;
				temp_item = mid;
				break;
			} else
				beg = mid + 1;     /* new beginning */
		}

		if (!found) {
			/* the position less than the address */
			temp_item = end;
		}

		/* checks */
		BUG_ON(temp_item < plist->kdbg_elf_sym_head);
		if ((temp_item >= plist->kdbg_elf_sym_head + plist->elf_symbol_count)) {
			printk("---------------- BUG BUG -------------\n");
			printk("temp_item [%p]  plist->kdbg_elf_sym_head [%p] last= [%p] count [%d]\n",
					temp_item, plist->kdbg_elf_sym_head, plist->kdbg_elf_sym_head + plist->elf_symbol_count,
					plist->elf_symbol_count);
		}

		BUG_ON(temp_item >= plist->kdbg_elf_sym_head + plist->elf_symbol_count);
		BUG_ON(temp_item > plist->kdbg_elf_sym_head
				&& temp_item->st_value < temp_item[-1].st_value);
		BUG_ON((temp_item < plist->kdbg_elf_sym_head + plist->elf_symbol_count - 1)
				&& temp_item->st_value > temp_item[1].st_value);

		/* more checks */
		if (temp_item < plist->kdbg_elf_sym_head + plist->elf_symbol_count - 1) {
			if ( (temp_item->st_value & ~1) != (temp_item[1].st_value&~1)) {
				BUG_ON(address < (temp_item->st_value & ~1) );
				BUG_ON(address >= (temp_item[1].st_value & ~1) );
			} else {
				BUG_ON(address < (temp_item->st_value & ~1));
			}
		} else {
			BUG_ON(temp_item != plist->kdbg_elf_sym_head + plist->elf_symbol_count - 1);
			BUG_ON(address < temp_item->st_value);
		}
	}

	/* item found, now check if it lies within function size. */
	if (temp_item && (address < (temp_item->st_size + (temp_item->st_value&~1)))) {
#if defined(KDBG_ELF_DEBUG_ON) && (KDBG_ELF_DEBUG_ON != 0)
		kdbg_elf_print_vma (temp_item->st_value, LONG_HEX);
#endif

SymbolBufRetry:
		if (plist->sym_buff) {
			symbol_string = (const char*)plist->sym_buff + temp_item->st_name;
		} else {
			/* there is symbol but the string table has not been loaded into memory yet*/
			__asm("bkpt");
			if (tsai_elf_sym_string_reload(plist)) {
				goto SymbolBufRetry;
			}
			symbol_string = 0;
		}

		if (out_symbol_string)
			*out_symbol_string = symbol_string;

		if (start_addr)
			*start_addr = (temp_item->st_value & ~1);
		if (start_len)
			*start_len = temp_item->st_size;

		//printk("[pfunc_name]  :: %s\n", pfunc_name);
		ret = 0;
	} else{
		if (start_addr)
			*start_addr = 0;
		if (start_len)
			*start_len = 0;

		ret = -ENOMEM;
	}

	return ret;
}

/* return: stated address of this symbol */
static unsigned int tsai_lookup_symbol(void* symbol_key, unsigned int addr, unsigned int vma_start, const char** out_symbol_string,
		unsigned int* out_start_len)
{
	unsigned int start = 0;
	unsigned int start_len = 0;
	kdbg_elf_usb_elf_list_item* l = (kdbg_elf_usb_elf_list_item*)symbol_key;
	int shift;
	int ret;
	shift = vma_start - l->virtual_addr;

	addr -= shift;
	ret = tsai_elf_sym_find(addr, (kdbg_elf_usb_elf_list_item*)l, out_symbol_string, &start, &start_len);
	if (ret==0) {
		start += shift;
	}

	if (out_start_len)
		*out_start_len = start_len;

	return start;
}

/* do_not_open: if in interrupt context where opening file is prohibited, specify this flag */
static void* tsai_callstack_load_symbol_file(const char* fname, int do_not_open) {
	char tmp[256];
	kdbg_elf_usb_elf_list_item *plist;
#if 0
	if (in_interrupt()) { /* if in interrupt, cannot even grab mutex lock!*/
		return 0;
	}
#endif
	//FIXME: for now assuming there is no other user of this db, so don't lock
	//get_elf_db_lock();
	strcpy(tmp, fname);
	plist = lookup_elf_file_in_db((char*)tmp);
	if (!plist && !do_not_open) {
		plist = load_elf_db_by_elf_file((char*)fname, 1, 0);
		if (!plist) {
			__asm("bkpt");
			goto Leave;
		}
	}
Leave:
	//put_elf_db_lock();
	return (void*)plist;
}

extern char *cplus_demangle(const char *mangled, int options);

static unsigned int tsai_callstack_preload_symbol_done;

/* load most frequently used symbols to increase success rate */
void tsai_callstack_preload_symbol(void) {
	char func[256];
	if (!tsai_callstack_preload_symbol_done) {

#if 1
		strcpy(func, "/usr/lib/driver/libmali.so");
		//__asm("bkpt");
		tsai_callstack_load_symbol_file(func , 0);
#endif

		strcpy(func, "/usr/lib/libc-2.24.so");
		tsai_callstack_load_symbol_file(func , 0);
		//TSAI_VMA_WRAPPER* tsai_find_vma_wrapper(struct TSAI_VMA_MGR* mgr, struct vm_area_struct* vma, const char* fullpath)

		strcpy(func, "/usr/lib/libstdc++.so.6.0.22");
		tsai_callstack_load_symbol_file(func , 0);

		strcpy(func, "/usr/lib/ld-2.24.so");
		tsai_callstack_load_symbol_file(func, 0);

		strcpy(func, "/usr/lib/libpthread-2.24.so");
		tsai_callstack_load_symbol_file(func , 0);

		strcpy(func, "/usr/lib/libCOREGL.so.4.0");
		tsai_callstack_load_symbol_file(func , 0);

		tsai_callstack_preload_symbol_done = 1;
	}

	/* check bug ld-2.24.so, address 4101aef0, but symbol records 4101AEF1 because of thumb, filter out this case */
#if 0
	{
		kdbg_elf_usb_elf_list_item *plist;

		__asm("bkpt");
		strcpy(func, "/usr/lib/ld-2.24.so");
		plist = lookup_elf_file_in_db(func);

		tsai_lookup_symbol(plist, 0x4101AEF0, func, 256);
	}
#endif
}

#define MAX_TO_FREE_SYMBOL (256)
int to_free_symbol_count;
struct TSAI_VMA_WRAPPER* to_free_symbol[MAX_TO_FREE_SYMBOL];

void tsai_callstack_print_bin_symbol_free(void) {
	int i;
	for (i=0; i<to_free_symbol_count; i++) {
		struct TSAI_VMA_WRAPPER* vw;
		vw = to_free_symbol[i];
		if (vw->symbol_key) {
			vw->symbol_key = 0;
		}
		to_free_symbol[i] = 0;
	}
	to_free_symbol_count = 0;
}

/* print to memory, and use T32 to extract the report */
void tsai_callstack_print_bin_symbol(int level, struct TSAI_VMA_MGR* mgr, struct mm_struct *tsk_mm, void* addr) {
	int cpu = smp_processor_id();
	char* full_path = tsai_full_path_buffer[cpu].path_buffer;
	const char* func_name = 0;
	struct TSAI_VMA_WRAPPER* vw;
	int symbol_len;
	char* p = 0;

	vw = tsai_find_vma_wrapper_by_addr(mgr, (unsigned int)addr, tsk_mm, full_path);

	if (vw->vma->vm_file) {
		p = tsai_get_full_path(&(vw->vma->vm_file->f_path),full_path, 256, NULL );
	}

	if (!vw->symbol_key) {
		vw->symbol_key = tsai_callstack_load_symbol_file(p, 0);
		to_free_symbol[to_free_symbol_count] = vw;
		to_free_symbol_count++;

		if (vw->vma->vm_file) {
			p = tsai_get_full_path(&(vw->vma->vm_file->f_path),full_path, 256, NULL );
		}
	}


	tsai_lookup_symbol(vw->symbol_key, (unsigned int)addr, vw->vma->vm_start,
			&func_name, &symbol_len);

	TSAI_UNWIND_LOG("#%d %08x %s %s\n", level, (unsigned int)addr, func_name, p);

}

/* caller provide address and this function will look up bin / symbol and fill into relevant buffer
 * return: address of this symbol (0 if symbol not found)
 * */
unsigned int tsai_callstack_format_bin_symbol(struct TSAI_VMA_MGR* mgr, struct task_struct* task, void* addr,
		char* in_full_path, int len_full_path, char** out_full_path, const char** out_symbol_string)
{
	int cpu = smp_processor_id();
	struct mm_struct *mm;
	struct TSAI_VMA_WRAPPER* vw;
	int ret_symbol_len;
	unsigned int symbol_address;
	char* p = 0;

	mm = tsai_get_task_mm_no_irq(task);
	vw = tsai_find_vma_wrapper_by_addr(mgr, (unsigned int)addr, mm, in_full_path);
	mmput(mm);

	if (vw->vma->vm_file) {
		p = d_path(&(vw->vma->vm_file->f_path), in_full_path, len_full_path);
	}

	if (!vw->symbol_key) {
		//__asm("bkpt");
		vw->symbol_key = tsai_callstack_load_symbol_file(p, 0);
		to_free_symbol[to_free_symbol_count] = vw;
		to_free_symbol_count++;

		if (vw->vma->vm_file) {
			p = tsai_get_full_path(&(vw->vma->vm_file->f_path),in_full_path, len_full_path, NULL );
		}
	}


	symbol_address = tsai_lookup_symbol(vw->symbol_key, (unsigned int)addr, vw->vma->vm_start,
			out_symbol_string, &ret_symbol_len);

	*out_full_path = p;
	return symbol_address;
}

/* caller provide address and this function will look up bin / symbol and fill into relevant buffer
 * return: address of this symbol (0 if symbol not found)
 * */
unsigned int tsai_callstack_demangle_bin_symbol(struct TSAI_VMA_MGR* mgr, struct task_struct* task, void* addr,
		char* in_full_path, int len_full_path, char** out_full_path, const char** out_symbol_string)
{
	int cpu = smp_processor_id();
	struct mm_struct *mm;
	struct TSAI_VMA_WRAPPER* vw;
	int ret_symbol_len;
	unsigned int symbol_address;
	char* p = 0;
	const char* sym_str = 0;

	mm = tsai_get_task_mm_no_irq(task);
	vw = tsai_find_vma_wrapper_by_addr(mgr, (unsigned int)addr, mm, in_full_path);
	mmput(mm);

	if (vw->vma->vm_file) {
		p = d_path(&(vw->vma->vm_file->f_path), in_full_path, len_full_path);
	}

	if (!vw->symbol_key) {
		//__asm("bkpt");
		vw->symbol_key = tsai_callstack_load_symbol_file(p, 0);
		to_free_symbol[to_free_symbol_count] = vw;
		to_free_symbol_count++;

		if (vw->vma->vm_file) {
			p = tsai_get_full_path(&(vw->vma->vm_file->f_path),in_full_path, len_full_path, NULL );
		}
	}


	symbol_address = tsai_lookup_symbol(vw->symbol_key, (unsigned int)addr, vw->vma->vm_start,
			&sym_str, &ret_symbol_len);

	if (symbol_address) {
		if (sym_str[0]=='_' && sym_str[1]=='Z') { /* likely C++ mangled name */
			struct ts_binary_node* binnode = tsai_vw_get_binnode(vw);
			sym_str = ts_binary_node_find_demangle(binnode, sym_str);
		}
	}
	*out_symbol_string = sym_str;
	*out_full_path = p;
	return symbol_address;
}
#define sym_printk(...)
#define sym_errk(...)

/* TSAI: Read symbol string for specific symbol, this is low efficiency and should be avoided
 *   Find the Symbol name form ELF
 */
static void kdbg_elf_find_func_name (kdbg_elf_usb_elf_list_item *plist,
		unsigned int idx, char *elf_sym_buff, unsigned int sym_len)
{
	struct file *elf_filp = NULL; /* File pointer to access file for ELF parsing*/
	ssize_t bytesread = 0;
	unsigned int total_bytes = 0;
	uint32_t symstr_offset = 0;
	uint32_t symstr_size = 0;
	mm_segment_t oldfs = get_fs();

	sym_printk("enter\n");
	BUG_ON(sym_len > AOP_MAX_SYM_NAME_LENGTH);

	sym_printk("Index = %u\n", idx);
	sym_printk("[%s file loading....\n",  plist->elf_name_actual_path);

	/*
	 * Kernel segment override to datasegment and write it
	 * to the accounting file.
	 */
	set_fs(KERNEL_DS);

	/* File Open */
	elf_filp = filp_open(plist->elf_name_actual_path, O_RDONLY | O_LARGEFILE, 0);

	if (IS_ERR(elf_filp) || (elf_filp == NULL)) {
		elf_filp = NULL;
		sym_errk("file open error\n\n");
		strncpy(elf_sym_buff, "<none>", sizeof("<none>"));
		sym_errk("<none>\n");
		bytesread = sizeof("<none>");
		goto DONE;
	}

	elf_filp->f_pos = 0;

	sym_printk("sym_str_size = %d \n", plist->sym_str_size);

	symstr_offset = plist->sym_str_offset;
	symstr_size =  plist->sym_str_size;

	elf_filp->f_pos = (loff_t)(symstr_offset + idx);
	if (elf_filp->f_pos <= 0) {
		strncpy(elf_sym_buff, "<no-name>", sizeof("<no-name>"));
		sym_errk("----<no-name>");
		bytesread = sizeof("<no-name>");
		goto DONE;
	}


	sym_printk("symstr_offset = %d :: symstr_size = %d\n",
			symstr_offset, symstr_size);
	if (idx >=  symstr_size) {
		strncpy(elf_sym_buff, "<corrupt>", sizeof("<corrupt>"));
		sym_errk("----<corrupt>\n");
		bytesread = sizeof("<corrupt>");
		goto DONE;
	}

	total_bytes = (symstr_size - idx);
	sym_printk("total_bytes = %d\n", total_bytes);

	if (total_bytes > sym_len) {
		total_bytes = sym_len;
	}

	bytesread = vfs_read
		(elf_filp, elf_sym_buff, total_bytes, &elf_filp->f_pos);
	if (bytesread < (ssize_t)total_bytes) {
		sym_errk("Bytes Read: %d read bytes out of required %u\n", bytesread, sym_len);
		strncpy (elf_sym_buff, "<none>", sizeof("<none>"));
		bytesread = sizeof("<none>");
	}

DONE:
	BUG_ON(bytesread <= 0 || bytesread > sym_len);
	elf_sym_buff[bytesread-1] = '\0';
	sym_printk("\nSym_len = %d :: Bytes read = %d :: [%s]\n", sym_len, bytesread,
			elf_sym_buff);
	if (elf_filp) {
		filp_close(elf_filp, NULL);
	}
	set_fs(oldfs);
}
