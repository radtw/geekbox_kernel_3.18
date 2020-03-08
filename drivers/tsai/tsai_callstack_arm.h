/*
 * tsai_callstack_arm.h
 *
 *  Created on: 7 Feb 2018
 *      Author: cheng.tsai
 */

#ifndef TSAI_CALLSTACK_ARM_H_
#define TSAI_CALLSTACK_ARM_H_

#include <linux/spinlock.h>

struct TSAI_VMA_WRAPPER;

/* for the process being profiled */
struct TSAI_VMA_MGR {
	struct rb_root root;
	spinlock_t lock;

	/* if PLT/ARMEIDX cannot be read due to atomic context, record the pointer here and do the reading from work thread */
	struct TSAI_VMA_WRAPPER* vw_to_read[16];
	int vw_to_read_count;
};

void tsai_vma_mgr_init(struct TSAI_VMA_MGR* vm);
void tsai_vma_mgr_add_defer_read(struct TSAI_VMA_MGR* vm, struct TSAI_VMA_WRAPPER* vw);
void tsai_vma_mgr_process_defer_read(struct TSAI_VMA_MGR* vm);
int tsai_vma_walk_section_header(struct TSAI_VMA_WRAPPER* vw);

struct tsai_intermediate_regs {
	union {
		unsigned int R[16];
		struct {
		unsigned int r0;
		unsigned int r1;
		unsigned int r2;
		unsigned int r3;
		unsigned int r4;
		unsigned int r5;
		unsigned int r6;
		unsigned int r7;
		unsigned int r8;
		unsigned int r9;
		unsigned int r10;
		unsigned int fp;	/* current frame pointer */
		unsigned int r12;
		unsigned int sp;	/* current stack pointer */
		unsigned int lr;	/* current return address */
		unsigned int pc;	/* current instruction pointer */
		};
	};

	unsigned int sp_end;	/* The limit of stack address */

	unsigned int pc_saved;
	unsigned int sp_saved;
	unsigned short reg_extract_mask; /* when register value extracted from stack, mark this field */
	unsigned short reg_extract_mask_prv;
	unsigned int voluntary; /* user side use ioctl to quest unwind stack, in this case, PC is guaranteed not to be in prologue/epilogue */
	unsigned int frame_is_thumb:1; /* if this frame is thumb */
	unsigned int on_pabort:1;
	unsigned int interrupt_on_user:1; /* the timer interrupt happens on top of user mode code, so first frame may be just in begin of function */
};


struct TSAI_USER_TRACE_SIMPLE {
	unsigned int pc;
	unsigned int sp;
	struct tsai_intermediate_regs* reg;
	void *data;
};

struct TSAI_USER_TRACE {
	unsigned int pc;
	unsigned int sp_func_start;
	unsigned int sp_unwind;
	unsigned int lr_st_addr;
	unsigned int plt_target; /* if this frame is PLT, provide the jump destination here */
	void *data;
};

typedef int (*PFN_user_trace_simple)(struct TSAI_USER_TRACE_SIMPLE* p);
typedef int (*PFN_user_trace)(struct TSAI_USER_TRACE* p);
typedef int (*PFN_user_recover)(struct tsai_intermediate_regs *regs, void *data);

int tsai_cpu_core_id(void);

unsigned long tsai_callstack_copy_from_user_stack(unsigned long pc, long sz);

struct TSAI_PARSE_USER_CALLSTACK {
	struct mm_struct *tsk_mm;
	struct TSAI_VMA_MGR* vma_mgr;
	struct tsai_intermediate_regs *regs;
	int max_depth; /* if not 0, only parse specified level and then stop */
	PFN_user_trace_simple user_trace_simple;
	PFN_user_trace user_trace;
	PFN_user_recover user_recover;
	void* data;
};

int tsai_parse_user_callstack(struct TSAI_PARSE_USER_CALLSTACK* param, unsigned int dbg_seq);

void tsai_callstack_preload_symbol(void);

void tsai_callstack_print_bin_symbol(int level, struct TSAI_VMA_MGR* mgr, struct mm_struct *tsk_mm, void* addr);
unsigned int tsai_callstack_format_bin_symbol(struct TSAI_VMA_MGR* mgr, struct task_struct* task, void* addr,
		char* in_full_path, int len_full_path, char** out_full_path, const char** out_symbol_string);
unsigned int tsai_callstack_demangle_bin_symbol(struct TSAI_VMA_MGR* mgr, struct task_struct* task, void* addr,
		char* in_full_path, int len_full_path, char** out_full_path, const char** out_symbol_string);

void tsai_callstack_print_bin_symbol_free(void);

#endif /* TSAI_CALLSTACK_ARM_H_ */
