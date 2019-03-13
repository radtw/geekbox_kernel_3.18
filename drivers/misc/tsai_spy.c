/*
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>

//#include <linux/kds.h>

#include <linux/dma-buf.h>

#include <drm/drmP.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 92)
	#include <drm/drm_gem.h>
	#include <linux/reservation.h>
#endif

#include <linux/rbtree.h>
#include <linux/list.h>

#include "tsai_spy_user.h"
#include <linux/tracepoint.h>
#include <linux/atomic.h>

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>


#define DEBUG
#include "tsai_macro.h"

#if TSAI_DS5
	#include "streamline_annotate.h"
	ANNOTATE_DEFINE_KERNEL;
#endif

#include "tsai_callstack_arm.h"
#include "tsai_callstack_cache.h"
#include "tsai_mem.h"

enum {
	TP_UNSPECIFIED = 0,
	TP_RESTART_TIMER = 1,
	TP_PROCESS_TRACE_BUF = 2, /* there is samples in the trace buffer, process it */
	TP_AUTO_STOP = 3, /* if a max duration is set and reached, auto stop profiling */
};

struct TSAI_PROFILER_WORK {
	struct work_struct work;
	struct TSAI_PROFILER_DATA* pr;
	int cmd;
	struct task_struct* task;
	spinlock_t lock;
};

struct tsai_spy_profiling_ipi_info {
	//struct TSAI_PROFILER_DATA* pr;
	unsigned int shed_mask_core; /* record the task which is currently on core */
	atomic_t expected_core_reply; /* it's a bit mask */

};

struct TSAI_PROFILER_DATA {
	struct rb_root profiling_proc_root; /* this will be used even when timer-profiler is not run, eg. one off backtrace */
	/* profiler specific */
	char output_filename[256];

	struct tsai_spy_mem_log mem_log;
	struct tsai_spy_mem_log unwind_log;

	struct TSpy_Profiler user_request;
	struct timespec timestamp_trace_begin;

	struct task_struct* profiling_task;
	int profiler_collecting;
	struct list_head list_deferred_task;
	struct hrtimer profiling_timer;
	ktime_t profiling_interval;
	ktime_t slower_interval;
	ktime_t profiling_hrtimer_expire;
	unsigned int interrupts_cnt; /* how many profiling timer interrupts have been executed*/
	struct timespec timestamp;
	struct rb_root profiling_taskroot;
	int profiling_task_cnt;

	struct file* filetrace; /* to hold trace binary file*/
	struct file* fileunwind; /* storing unwind log to file system  */

	/* trace buffer to hold samples before flushing to file system =============*/
	char* profiling_trace_buf;
	int   profiling_trace_buf_size; /* 512KB for now */
	int   profiling_trace_buf_curtail; /* when there are some bytes ignored in the end due to contiguous data requirement  */
	int   profiling_trace_buf_cur_w; /* write cursor */
	int	  profiling_trace_buf_cur_r; /* read cursor */
	spinlock_t profiling_trace_buf_lock;
	int   profiling_trace_event_lost;

	/* ====trace writer specific===============================================================*/
	struct timespec timestamp_lastwrite;

	struct timespec timestamp_lastread;
	unsigned int seqno_lastread;

	/* ==========================================================================*/

	struct TSAI_PROFILER_WORK profiler_work;
	atomic_t profiler_work_pending;
	struct task_struct* profiler_work_task; /* last known task which process work queue */
	struct TSAI_VMA_MGR vma_mgr;

	struct tsai_spy_profiling_ipi_info ipi;
	struct call_single_data csd_stack[8]; /* for smp ipi*/

	/* use this mask to see which tasks of interests have been scheduled, bit 24-31 (core mask) */
	unsigned int sche_mask;
	unsigned int task_freeze_cnt; /* lifetime in tsai_spy_capture_sample() */
	unsigned int task_nonsleeping_cnt; /* lifetime in tsai_spy_capture_sample() */

	atomic_t timer_status; /* timer started */
	atomic_t engine_pending_smp; /* at least one cpu core is still processing, that core is responsibile to restart the timer */

	/* ======== worker thread ========== */
	struct task_struct *worker_thread;
	atomic_t	worker_go; /* when set to 1, tsai_profile_thread_fn_wake should wake the engine thread */
	/* ================================= */
	unsigned int opt_task_state_trace: 1; /* change task state to trace if it's not on a CPU core */
	unsigned int opt_task_on_rq_backup: 1;
	unsigned int opt_engine_timer:1;
};


/* a data structure to hold common frequently used data, and kernel modules can access it too */
struct TSAI_SPY_DATA {
	unsigned int last_gpu_schedule_pid;
	/* log buffer */
	void* log_msg;
	unsigned int log_msg_max;
	unsigned int log_msg_cur;

	struct TSAI_PROFILER_DATA pr;
	struct ts_callstack_binary_cache bincache;

	struct {
		unsigned int addr;
		unsigned int size;
	} pabort_symbol;

	struct tracepoint *tracepoint_sched;
	struct tracepoint *tracepoint_sched_wakeup;
	struct tracepoint *tracepoint_sched_try_wakeup;
	struct tracepoint *tracepoint_irq_entry;
	struct tracepoint *tracepoint_irq_exit;

	struct task_struct** ptr_tsai_debug_wake_up_task;

	int debug_flag;
} tsai_spy_data;

EXPORT_SYMBOL(tsai_spy_data);

///////////////////////////////////////////////////////////

TSAI_STATIC void tsai_spy_walk_through_modules(void) {
	struct module *mod;
	struct list_head* p;
	struct list_head* mod_begin;
	void* addr;
	void* low_addr;
#if defined(__aarch64__)
#else
	low_addr = (void*)0xc0000000;
#endif
	//note, modules is not exported by default, I modified and make it exported
	mod_begin = (struct list_head*)__symbol_get("modules");
	if (mod_begin) {
		for (p = mod_begin->next; p != mod_begin; p=p->next) {
			mod = container_of(p, struct module, list);
			addr = mod->module_core;
			if (addr < low_addr)
				low_addr = addr;
		}
	}
	__symbol_put("modules");
}


/* given a name, walk through the tasks and find by name
 * return -1 if not found
 * */
struct task_struct* tsai_find_process_by_name(const char* name) {
	struct task_struct* ret;
	struct task_struct* pt = &init_task;

	while(pt) {
		//printk("%d %s \n", pt->pid, pt->comm);

		if (pt->pid==pt->tgid && pt->mm) {
			if (strcmp(pt->comm, name)==0) {
				ret = pt;
				goto Leave;
			}
		}

		pt = container_of(pt->tasks.next, struct task_struct, tasks);
		if (pt == &init_task) {
			ret = NULL;
			break;
		}
	}
Leave:
	return ret;
}

struct task_struct* tsai_find_process_thread_by_name(const char* proc_name, const char* thre_name) {
	struct task_struct* ret = NULL;
	struct task_struct* proc;
	struct task_struct* thre;
	proc = tsai_find_process_by_name(proc_name);

	thre = proc;

	for (;thre;) {
		if (strcmp(thre->comm, thre_name)==0) {
			ret = thre;
			goto Leave;
		}
		thre = container_of(thre->thread_group.next, struct task_struct, thread_group);
		if (thre == proc) {
			ret = NULL;
			break;
		}
	}
Leave:
	return ret;
}

///////////////////////////////////////////////////////////

extern unsigned int tsai_annotate_handle_prefetch;
extern struct task_struct* tsai_annotate_handle_prefetch_task;


TSAI_STATIC struct miscdevice tsai_spy_dev = { 0, };

TSAI_STATIC const char tsai_spy_dev_name[] = "tsai_spy";


unsigned int tsai_spy_user_var_01;
EXPORT_SYMBOL(tsai_spy_user_var_01);

TSAI_STATIC int fd_to_gem_name(int fd) {
	int gem = -1;
	struct dma_buf* dma_buf;

	dma_buf = dma_buf_get(fd);
	if (dma_buf) {
		struct drm_gem_object* obj;
		obj = (dma_buf->priv)? (struct drm_gem_object*)dma_buf->priv: NULL;

		if (obj) {
			gem = obj->name;
		}

		dma_buf_put(dma_buf);
		dma_buf = NULL;
	}
//Leave:
	return gem;
}



TSAI_STATIC unsigned long tsai_last_gpu_sched_pid(void) {
	return tsai_spy_data.last_gpu_schedule_pid;
}

TSAI_STATIC unsigned int tsai_annotate_current_task(struct TSpy_Task* user_task) {
	struct task_struct* t = current;
#if TSAI_DS5
	SRUK_ANNOTATE_CHANNEL_COLOR(999, ANNOTATE_WHITE, "task %p tgid %d pid %d %s", t, t->tgid, t->pid, t->comm);
	ANNOTATE_CHANNEL_END(999);
#endif

	if (user_task) {
#if defined(__aarch64__)
		user_task->ptr_task = (uint64_t)t;
#else
		user_task->ptr_task = (unsigned int)t;
#endif
		user_task->tgid = t->tgid;
		user_task->pid = t->pid;
		memcpy(user_task->comm, t->comm, sizeof(t->comm) );
	}

	return 0;
}

extern int tsai_install_watchpoint(u64 address, unsigned int access, const char* label);
extern void tsai_remove_watchpoint(u64 address);

TSAI_STATIC int tsai_spy_install_watch_point(struct TSpy_Watchpoint* w) {

	int ret;
	if (w->on_off) {
		ret = tsai_install_watchpoint(w->address, w->access, w->label);
	}
	else {
		tsai_remove_watchpoint(w->address);
		ret = 1;
	}

	return ret;
}

/* set a watchpoint and break when MMU entry for virtual address has changed
 * mm: if NULL, use current->mm */
int tsai_spy_monitor_mmu_change(void* virtual_addr, struct mm_struct* mm) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	pte_t* pte;
	if (!mm)
		mm = current->active_mm;
	pte = tsai_address_is_on_mmu(mm, (uint64_t)virtual_addr, NULL);
#endif
	return 0;
}

EXPORT_SYMBOL(tsai_spy_monitor_mmu_change);

/* ================ PROFILER SPECIFIC CODE =================================================================== */
#if defined(DEBUG)
	#define TSAI_PROFILER_LOG(fmt,...) 	tsai_spy_mem_log(&tsai_spy_data.pr.unwind_log, fmt, __VA_ARGS__);
	#define TSAI_PROTRACE_LOG(fmt,...) tsai_spy_mem_log(&tsai_spy_data.pr.mem_log, fmt, __VA_ARGS__)
#else
	#define TSAI_PROFILER_LOG(...)
	#define TSAI_PROTRACE_LOG(fmt,...)
#endif


#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/rbtree.h>
#include <linux/mmu_context.h>
#include <asm/stacktrace.h>
#include <linux/kallsyms.h>


#define TSAI_MAX_PROFILING_FRAME 256

struct tsai_profiling_frame {
	unsigned int pc;
	unsigned int sp_saved; /* sp when newly unwinding a frame */
	unsigned short sp_offset; /* sp value on begin of function */
	unsigned int f_entrypoint:1; /* this frame is the entry point main or thread_start */
	unsigned int lr_from_addr; /* LR was retrieved from which address */
};

struct tsai_profiling_sample {
	unsigned int task_state;
	unsigned int ts_sec;
	unsigned int ts_usec;
	unsigned int plt_target; /* if known, the first user frame is in PLT*/
	unsigned int frame_cursor:8;
	unsigned int kern_frames:8;
	unsigned int full_frames:8; /* including fast copy from previous sample! */
	unsigned int copied_start_idx:8; /* frames not parsed, but compare/copied from previous frame */
	struct tsai_profiling_frame frame[TSAI_MAX_PROFILING_FRAME]; /* for both kernel and user */
};

void tsai_profiling_sample_clear(struct tsai_profiling_sample* s) {
	s->task_state = 0;
	s->plt_target = 0;
	s->frame_cursor = 0;
	s->kern_frames = 0;
	s->full_frames = 0;
	s->copied_start_idx = 0;
}

struct tsai_profiling_task_node {
	struct rb_node rb; /* has to be first one */
	struct list_head list_deferred; /* when state=running but not on any cpu core, check again after all cores have done IPI */
	unsigned int pid;
	struct task_struct* task;
	struct task_struct* wake_by_task; /* when being waken up, record who woke it up */
	/* record the irq which affects this task */
	struct irqaction* irq_on_task;
	struct timespec irq_timestamp_en;
	struct timespec irq_timestamp_ex;
	struct timespec sched_on_timestamp; /* timestamp when sched on */
	struct timespec sched_off_timestamp; /* timestamp when falling into sleep */

	atomic_t is_in_process; /* set to 1 if being processed in tsai_spy_parse_stack */

	unsigned int handled_in_this_interrupt:1;
	unsigned int new_sample:1; /* set to 1 when there are actually some new sample written, if no samples, skip this node */
	unsigned int sched_away: 1; /* when scheduled off core, set to 1, otherwise 0 */
	unsigned int unchanged_kern:1; /* kern PC/SP is unchanged */
	unsigned int unchanged_user:1; /* user PC/SP unchanged */
	unsigned int active_sample:1;
	unsigned int comp_cursor;

	spinlock_t save_state_lock; /* to keep consistency of the following variables */
	atomic_t save_state_flag;
	int saved_state; /* copy of task->state */
	int prev_saved_state;
	int saved_on_rq; /* saved task->on_rq */

	struct tsai_profiling_sample sample[2];

};

/* this structure stands for one process */
struct ts_prof_proc_node {
	struct ts_rb_node rb; /* has to be first one */
	struct TSAI_VMA_MGR* vma_mgr;
};

TSAI_STATIC void tsai_spy_profiler_defer_free(struct TSAI_PROFILER_DATA* pr);
TSAI_STATIC void tsai_spy_profiler_process_trace(struct TSAI_PROFILER_DATA* pr);
int tsai_spy_profiler(struct TSpy_Profiler* p);

TSAI_STATIC void tsai_handle_profiler_work(struct work_struct *work)
{
	struct TSAI_PROFILER_DATA* pr;
	struct TSAI_PROFILER_WORK* pw = (struct TSAI_PROFILER_WORK*)work;
	pr = pw->pr;

	TSAI_PROFILER_LOG("===tsai_handle_profiler_work cmd=%d task %p=====@%d\n", pw->cmd, current, __LINE__);
	pr->profiler_work_task = current;
	switch(pw->cmd) {
	case TP_PROCESS_TRACE_BUF:
		tsai_spy_profiler_process_trace(pr);
		break;
	case TP_AUTO_STOP:
		{
			struct TSpy_Profiler p;
			p.on_off = 0;
			tsai_spy_profiler(&p);
			kfree(work);
		}
		break;
#if 0
	case TP_RESTART_TIMER:
		{
			if (atomic_read(&pr->timer_status)== 0) {
			#ifdef DEBUG
				TSAI_PROFILER_LOG("===DEFERRED TIMER RESTART=====@%d\n", __LINE__);
			#endif
				atomic_set(&pr->timer_status, 1);
				hrtimer_restart(&pr->profiling_timer);
			}
		}
		break;
#endif
	default:
		BKPT;
		tsai_print_user_callstack(pw->task, NULL);
	}
}

/* return a value between 0~23 */
TSAI_STATIC inline unsigned int tsai_24bit_value(unsigned int key) {
	return (key & 15) + ((key & 0x70)>>8);
}


#ifdef DEBUG

struct tsai_profiling_task_node* tsai_debug_task_nodes[16];

#endif

TSAI_STATIC struct ts_prof_proc_node* ts_get_proc_node(pid_t tgid) {
	struct ts_prof_proc_node* n = (struct ts_prof_proc_node*)ts_rb_find(&tsai_spy_data.pr.profiling_proc_root, (unsigned int) tgid );
	if (!n) {
		n = kzalloc(sizeof(struct ts_prof_proc_node), GFP_KERNEL);
		n->rb.key = (unsigned int) tgid;
		n->vma_mgr = kzalloc(sizeof(struct TSAI_VMA_MGR), GFP_KERNEL);
		ts_rb_insert(&tsai_spy_data.pr.profiling_proc_root, &n->rb);
	}
	return n;
}

TSAI_STATIC struct tsai_profiling_task_node* tsai_spy_profiling_find_task(struct TSAI_PROFILER_DATA* pr, unsigned int pid) {
	struct tsai_profiling_task_node* ret = 0;
	struct tsai_profiling_task_node* n = (struct tsai_profiling_task_node*)pr->profiling_taskroot.rb_node;

	while (n) {
		u32 key = n->pid;

		if (pid > key) {
			n = (struct tsai_profiling_task_node*)n->rb.rb_right;
		}
		else if (pid < key) {
			n = (struct tsai_profiling_task_node*)n->rb.rb_left;
		}
		else {
			ret = n;
			break;
		}
	}

	return ret;
}

TSAI_STATIC void tsai_spy_profiling_insert_task(struct TSAI_PROFILER_DATA* pr, struct tsai_profiling_task_node* tnode) {
	struct rb_node **pnew = &pr->profiling_taskroot.rb_node;
	struct tsai_profiling_task_node* parent = NULL;
	u32 key = tnode->pid;

	while (*pnew) {
		parent = (struct tsai_profiling_task_node*)*pnew;
		if (key < parent->pid)
			pnew = &parent->rb.rb_left;
		else
			pnew = &parent->rb.rb_right;
	}

	pr->profiling_task_cnt++;
	rb_link_node(&tnode->rb, &parent->rb, pnew);

	//print_tree(root->rb_node, 0);

	rb_insert_color(&tnode->rb, &pr->profiling_taskroot); /* insert is already done, change color, or rotate if necessary */

	//print_tree(root->rb_node, 0);
}

TSAI_STATIC struct tsai_profiling_task_node* tsai_spy_profiling_create_tnode(struct TSAI_PROFILER_DATA* pr, unsigned int pid, struct task_struct* t) {
	struct tsai_profiling_task_node* tnode;

	tnode = kzalloc(sizeof(struct tsai_profiling_task_node), GFP_KERNEL );
	tnode->pid = t->pid;
	tnode->task = t;
	spin_lock_init(&tnode->save_state_lock);
	tsai_spy_profiling_insert_task(pr, tnode);
	return tnode;
}

void tsai_vma_mgr_init(struct TSAI_VMA_MGR* vm) {
	vm->root.rb_node = 0;
	spin_lock_init(&vm->lock);
	vm->vw_to_read_count = 0;
	vm->vw_to_read[0] = 0;
}

void tsai_vma_mgr_add_defer_read(struct TSAI_VMA_MGR* vm, struct TSAI_VMA_WRAPPER* vw) {
	unsigned long irqflags;
	spin_lock_irqsave(&vm->lock, irqflags);
	if (vm->vw_to_read_count < 16 ) {
		vm->vw_to_read[vm->vw_to_read_count] = vw;
		vm->vw_to_read_count++;
	}
	spin_unlock_irqrestore(&vm->lock, irqflags);
}

void tsai_vma_mgr_process_defer_read(struct TSAI_VMA_MGR* vm) {
	unsigned long irqflags;
	while(1) {
		struct TSAI_VMA_WRAPPER* vw = 0;
		spin_lock_irqsave(&vm->lock, irqflags);
		if (vm->vw_to_read_count) {
			vw = vm->vw_to_read[vm->vw_to_read_count-1];
			vm->vw_to_read_count--;
		}
		spin_unlock_irqrestore(&vm->lock, irqflags);

		if (!vw)
			break;

		/* defer read if needed, walk through the table */
			//__asm("bkpt");
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
			tsai_vma_walk_section_header(vw);
#else
			BKPT;
#endif
	}
}

/* this is a callback function */

struct TSAI_TRACE_CALLBACK_DATA {
	struct tsai_profiling_task_node* tnode;
	unsigned int on_pabort;
};

TSAI_STATIC  int tsai_spy_profiling_kernel_trace(struct stackframe *fr, void *data)
{
	struct TSAI_TRACE_CALLBACK_DATA* d = (struct TSAI_TRACE_CALLBACK_DATA*)data;
	struct tsai_profiling_task_node* tnode = d->tnode;
	struct tsai_profiling_sample* s = &tnode->sample[tnode->active_sample];

	if (s->frame_cursor < TSAI_MAX_PROFILING_FRAME) {
		struct tsai_profiling_frame* f = &s->frame[s->frame_cursor];
		f->pc = fr->pc;
		f->sp_saved = fr->fp;
		s->frame_cursor++;

		if (f->pc >= tsai_spy_data.pabort_symbol.addr && f->pc < (tsai_spy_data.pabort_symbol.addr+tsai_spy_data.pabort_symbol.size) ) {
			d->on_pabort = 1;
		}
	}
	else {
		BKPT; /* not enough place to store the callstack information */
	}

	return 0;
}

/* a callback function,
 * sp: the sp when entering that function, not when PC==pc */
TSAI_STATIC int tsai_spy_profiling_user_trace(struct TSAI_USER_TRACE* p)
{
	//unsigned int pc, unsigned int sp_func_start, unsigned int sp_unwind, unsigned int lr_st_addr, void *data

	struct tsai_profiling_task_node* tnode = (struct tsai_profiling_task_node*)p->data;
	struct tsai_profiling_sample* s = &tnode->sample[tnode->active_sample];
	struct tsai_profiling_sample* prevs = &tnode->sample[(tnode->active_sample+1) & 1];

#ifdef DEBUG
	ASSERT( tnode->active_sample < 2);
	ASSERT( s->frame_cursor < 256);
#endif
	if (p->plt_target)
		s->plt_target = p->plt_target;

	if (s->frame_cursor < TSAI_MAX_PROFILING_FRAME) {
		struct tsai_profiling_frame* f = &s->frame[s->frame_cursor];
		f->pc = p->pc;
		f->sp_saved = p->sp_unwind;
		f->sp_offset = (p->sp_func_start - p->sp_unwind);
		f->lr_from_addr = p->lr_st_addr;
		f->f_entrypoint = 0;
		TSAI_PROFILER_LOG(" Sample Frame %d PC %08x SP %08x @%d\n", s->frame_cursor, f->pc, f->sp_saved, __LINE__);
#ifdef DEBUG
		if (s->frame_cursor) {
			struct tsai_profiling_frame* f_minusone = &s->frame[s->frame_cursor - 1];
			struct thread_info *tsk_ti = task_thread_info(tnode->task);
			/* only assert by comparing user mode address*/
			ASSERT((tsk_ti->addr_limit && (f_minusone->pc >= tsk_ti->addr_limit) ) || (f->sp_saved >= f_minusone->sp_saved) );
		}
#endif
		s->frame_cursor++;

		/* compare with previous sample buffer, find early out possibility*/
		if (prevs->full_frames) {
			struct tsai_profiling_frame* pf;
			int i = tnode->comp_cursor;
			for (;i<prevs->full_frames; i++) {
				pf = &prevs->frame[i];
				if (pf->sp_saved > f->sp_saved)
					break;

				if (pf->sp_saved==f->sp_saved && pf->pc==f->pc && pf->sp_offset==f->sp_offset) {
					/* find identical, copying the remaining */
					int frame_copied = 0;
					int last_sp = p->sp_unwind;
					i++;
					s->copied_start_idx = s->frame_cursor;
					while (i<prevs->full_frames) {
						struct tsai_profiling_frame* f2 = &s->frame[s->frame_cursor];
						pf = &prevs->frame[i];
						*f2 = *pf;
						TSAI_PROFILER_LOG(" Sample Frame [Copied] %d PC %08x SP %08x %s prv full %d i %d @%d\n",
								s->frame_cursor, f2->pc, f2->sp_saved, f2->f_entrypoint?"E":"", prevs->full_frames, i, __LINE__);
#ifdef DEBUG
						if (f2->sp_saved < last_sp)
							BKPT;
						last_sp = f2->sp_saved;
#endif

						frame_copied++;
						s->frame_cursor++;
						if (f2->f_entrypoint)
							break;

						i++;
					}

					return 1;
				}
				tnode->comp_cursor = i;
			}
		}

	}
	else {
		BKPT; /* not enough place to store the callstack information */
	}

	return 0;
}

/* when encountering some excetions, before completely giving up, try to compare with previous sample and recover as much as possible */
int tsai_spy_profiling_user_recover(struct tsai_intermediate_regs *regs, void *data) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct tsai_profiling_task_node* tnode = (struct tsai_profiling_task_node*)data;
	struct tsai_profiling_sample* s = &tnode->sample[tnode->active_sample];
	struct tsai_profiling_sample* prevs = &tnode->sample[(tnode->active_sample+1) & 1];

	if (s->frame_cursor < TSAI_MAX_PROFILING_FRAME) {
		//struct tsai_profiling_frame* f = &s->frame[s->frame_cursor];
		//f->pc = pc;
		//f->sp_saved = sp_unwind;
		//f->sp_offset = (sp_func_start - sp_unwind);
		//s->frame_cursor++;

		/* compare with previous sample buffer, find early out possibility*/
		if (prevs->full_frames) {
			struct tsai_profiling_frame* pf;
			int i = tnode->comp_cursor;
			for (;i<prevs->full_frames; i++) {
				pf = &prevs->frame[i];
				if (pf->sp_saved < regs->sp_saved)
					continue;

				/* examine the LR address on the stack */
				{
					unsigned int lr;
					unsigned int next_pc;
					lr = tsai_callstack_copy_from_user_stack(pf->lr_from_addr, 4);
					next_pc = prevs->frame[i+1].pc;
					if (lr==next_pc) {
						int frame_copied = 0;
						int last_sp = pf->sp_saved;

						TSAI_PROFILER_LOG("LR from prev sample still valid #%d pc %08x sp %08x lr %08x lr_staddr %08x \n",
								i, pf->pc, pf->sp_saved, lr, pf->lr_from_addr);

						/* copied the remaining frames over */
						i = i+1;
						s->copied_start_idx = s->frame_cursor;
						for (;i<prevs->full_frames; i++) {
							struct tsai_profiling_frame* f2 = &s->frame[s->frame_cursor];
							*f2 = prevs->frame[i];
							TSAI_PROFILER_LOG(" Sample Frame [Recov] %d PC %08x SP %08x %s prv full %d i %d\n",
									s->frame_cursor, f2->pc, f2->sp_saved, f2->f_entrypoint?"E":"", prevs->full_frames, i);
#ifdef DEBUG
							if (f2->sp_saved < last_sp)
								BKPT;

							last_sp = f2->sp_saved;
#endif

							s->frame_cursor++;
							frame_copied++;
							if (f2->f_entrypoint)
								break;
						}

						return 1;
					}
				}

				tnode->comp_cursor = i;
			}
		}

	}
	else {
		BKPT; /* not enough place to store the callstack information */
	}
#endif
	return 0;
}

TSAI_STATIC inline unsigned int tsai_tnode_task_state(struct tsai_profiling_task_node* tnode) {
	int saved_state_flag = atomic_read(&tnode->save_state_flag);
	if (saved_state_flag) {
		return tnode->saved_state;
	}
 	return tnode->task->state;
}

TSAI_STATIC int tsai_diff_microsec(struct timeval* first, struct timeval* second)
 {
 	 int retval;
 	 int sec;
 	   /* Perform the carry for the later subtraction by updating y. */
 	 //first->tv_sec;
 	 //first->tv_nsec;

 	 retval = second->tv_usec - first->tv_usec;	//retval might be negative at this point
 	 for (sec = (second->tv_sec - first->tv_sec); sec>0; sec-- ) {
 		 retval += 1000000 ;
 	 }

 	 return retval;
}

TSAI_STATIC int tsai_diff_microsec64(struct timespec* first, struct timespec* second)
{
	unsigned long long retval;
 	int sec;
 	retval = second->tv_nsec - first->tv_nsec;	//retval might be negative at this point
 	for (sec = (second->tv_sec - first->tv_sec); sec>0; sec-- ) {
 	 retval += 1000000000 ;
 	}

 	retval = div_u64(retval, 1000); /* make it microsec*/
 	return (int)retval;
}

/*
 * defined the following
 * SMPL: it's a sample
 * BEGN: begin of trace, time stamp will be recorded
 * ENDT: end of trace, time stamp will be recorded
 *
 * */
#define CONSTR_SMPL  ('S' | 'M'<<8 | 'P' << 16 | 'L' <<24)
#define CONSTR_BEGN  ('B' | 'E'<<8 | 'G' << 16 | 'N' <<24)
#define CONSTR_ENDT  ('E' | 'N'<<8 | 'D' << 16 | 'T' <<24)
#define CONSTR_SLEP  ('S' | 'L'<<8 | 'E' << 16 | 'P' <<24)
#define CONSTR_SHON  ('S' | 'H'<<8 | 'O' << 16 | 'N' <<24) /* Schedule On to core */
#define CONSTR_SHOF  ('S' | 'H'<<8 | 'O' << 16 | 'F' <<24) /* Schedule Off core */
#define CONSTR_IRQC  ('I' | 'R'<<8 | 'Q' << 16 | 'C' <<24) /* IRQ on core affect the task being profiled */
#define CONSTR_WAKE  ('W' | 'A'<<8 | 'K' << 16 | 'E' <<24) /* wake up on core */

enum TM {
	M_BEGN = 0,
	M_ENDT = 1,
	M_SLEP = 2,
	M_SHON = 3,
	M_SHOF = 4,
	M_IRQC = 5,
	M_WAKE = 6,
};


struct tsai_trace_marker_param {
	uint64_t p1;
	uint64_t p2;
	uint64_t p3;
	uint64_t p4;
};

struct tsai_context_switch_info {
	pid_t pid1;
	pid_t tgid1;
	unsigned int state1;
	pid_t pid2;
	pid_t tgid2;
	unsigned int state2;

	unsigned int cpu_core: 4;
	unsigned int in_iowait1:1;
	unsigned int in_iowait2:1;

	char comm1[16];
	char comm2[16];

	unsigned int sleep_us; /* sleep duration in us*/
};

struct tsai_irq_core_info {
	struct irqaction *action;
	unsigned int duration_us; /* duration in microsecond */
	unsigned int pid;
};

int tsai_log_profiler_buffer_dyn = 1;
int tsai_log_profiler_buffer = 0;

/* reserve bytes in the trace buffer, increase the write cursor, and return a pointer for caller to write to */
TSAI_STATIC unsigned char* tsai_spy_profiler_reserve_trace_buffer(struct TSAI_PROFILER_DATA* pr, int bytes_needed) {
	unsigned char* ret = 0;
	int retry = 0;
	int bytes_max;
	unsigned long irqflags;
	spin_lock_irqsave(&pr->profiling_trace_buf_lock, irqflags);

Retry:
	ASSERT (pr->profiling_trace_buf_cur_w <= pr->profiling_trace_buf_size);
	if (!retry) {
		if (pr->profiling_trace_buf_cur_w >= pr->profiling_trace_buf_cur_r ) {
			if (pr->profiling_trace_buf_curtail)
				bytes_max = pr->profiling_trace_buf_cur_r - pr->profiling_trace_buf_cur_w;
			else
				bytes_max = pr->profiling_trace_buf_size - pr->profiling_trace_buf_cur_w;

			if ( (bytes_needed > bytes_max) && !pr->profiling_trace_buf_curtail ) {
				pr->profiling_trace_buf_curtail = pr->profiling_trace_buf_cur_w;

#ifdef DEBUG
				if (bytes_max > 1024) {
					/* when curtail is too far away from buffer size, check what is going on? */
					tsai_spy_mem_log(&pr->mem_log, "write smpl r=%d w=%d curtail=%d bneed %d bmax %d @%d\n",
						pr->profiling_trace_buf_cur_r, pr->profiling_trace_buf_cur_w, pr->profiling_trace_buf_curtail,
						bytes_needed, bytes_max , __LINE__);
					BKPT;
				}
#endif

				pr->profiling_trace_buf_cur_w = 0;
				retry++;
				goto Retry;
			}
		}
		else
			bytes_max = pr->profiling_trace_buf_cur_r - pr->profiling_trace_buf_cur_w;

	}

#ifdef DEBUG
	if (tsai_log_profiler_buffer_dyn) {
		if (bytes_max > 1024)
			tsai_log_profiler_buffer = 0;
		else if (bytes_max < 512)
			tsai_log_profiler_buffer = 1;
	}
#endif

	if (tsai_log_profiler_buffer)
		tsai_spy_mem_log(&pr->mem_log, "write smpl r=%d w=%d curtail=%d bneed %d bmax %d @%d\n",
			pr->profiling_trace_buf_cur_r, pr->profiling_trace_buf_cur_w, pr->profiling_trace_buf_curtail,
			bytes_needed, bytes_max , __LINE__);

	if (bytes_needed > bytes_max) {
		/* produce samples quicker than processing them, some samples need to be throw away from source side */
		pr->profiling_trace_event_lost++;
	}
	else {
		ret = ( (unsigned char*)pr->profiling_trace_buf + pr->profiling_trace_buf_cur_w);
		pr->profiling_trace_buf_cur_w += bytes_needed;

		ASSERT(pr->profiling_trace_buf_cur_w <= pr->profiling_trace_buf_size);
	}

	spin_unlock_irqrestore(&pr->profiling_trace_buf_lock, irqflags);

	return ret;
}

TSAI_STATIC void tsai_spy_wake_work_queue(struct TSAI_PROFILER_DATA* pr, int command) {
	unsigned long irqflags;
	int pending;
	spin_lock_irqsave(&pr->profiler_work.lock, irqflags);
	pending = atomic_read(&pr->profiler_work_pending);
	if (!pending) {
		pr->profiler_work.pr = pr;
		pr->profiler_work.cmd = command;
		INIT_WORK(&pr->profiler_work.work, tsai_handle_profiler_work);
		schedule_work(&pr->profiler_work.work);

		atomic_set(&pr->profiler_work_pending, 1);
	}
	spin_unlock_irqrestore(&pr->profiler_work.lock, irqflags);
}

/* write begin/end marker
 * marker: 0=begin 1=end, 2=all sleep 3=sche on 4=sched off
 * M_WAKE: wakeup
 * */
TSAI_STATIC void tsai_spy_profiler_write_trace_marker(struct TSAI_PROFILER_DATA* pr, int marker, struct timespec* timestamp,
		struct tsai_trace_marker_param* p)
{
	int bytes_needed;
	unsigned char* ptr;

	/* determine how many bytes needed */
	bytes_needed = 4 * 5;
	switch(marker) {
	case M_SHON:
		bytes_needed += sizeof(struct tsai_context_switch_info);
		break;
	case M_SHOF:
		bytes_needed += sizeof(struct tsai_context_switch_info);;
		break;
	case M_IRQC:
		bytes_needed += sizeof(struct tsai_irq_core_info);;
		break;
	case M_WAKE:
		bytes_needed += sizeof(struct tsai_context_switch_info);;
		break;
	default:
		;
	}
	ptr = (unsigned char*)tsai_spy_profiler_reserve_trace_buffer(pr, bytes_needed);

	if (ptr) {
		/* write an identifier 'BEGN' */
		switch(marker) {
		case M_BEGN:
			*(unsigned int*)ptr = CONSTR_BEGN;
			break;
		case M_ENDT:
			*(unsigned int*)ptr = CONSTR_ENDT;
			break;
		case M_SLEP:
			*(unsigned int*)ptr = CONSTR_SLEP;
			break;
		case M_SHON:
			*(unsigned int*)ptr = CONSTR_SHON;
			break;
		case M_SHOF:
			*(unsigned int*)ptr = CONSTR_SHOF;
			break;
		case M_IRQC:
			*(unsigned int*)ptr = CONSTR_IRQC;
			break;
		case M_WAKE:
			*(unsigned int*)ptr = CONSTR_WAKE;
			break;
		default:
			BKPT;
		}

		ptr += 4;
		*(unsigned int*)ptr = bytes_needed; 						ptr += 4;
		*(unsigned int*)ptr = 0;				 					ptr += 4;
		*(unsigned int*)ptr = timestamp->tv_sec; 				ptr += 4;
		*(unsigned int*)ptr = timestamp->tv_nsec; 				ptr += 4;

		switch(marker) {
		case M_SHON:
		case M_SHOF:
			{
			struct task_struct* t1 = (struct task_struct*)p->p1;
			struct task_struct* t2 = (struct task_struct*)p->p2;

			struct tsai_context_switch_info inf;
			inf.sleep_us = p->p4;
			inf.cpu_core = p->p3;
			inf.pid1 = t1->pid;
			inf.tgid1 = t1->tgid;
			inf.state1 = t1->state;
			inf.in_iowait1 = t1->in_iowait;
			memcpy(inf.comm1, t1->comm, sizeof(inf.comm1));

			inf.pid2 = t2->pid;
			inf.tgid2 = t2->tgid;
			inf.state2 = t2->state;
			inf.in_iowait2 = t2->in_iowait;
			memcpy(inf.comm2, t2->comm, sizeof(inf.comm2));

			memcpy(ptr, &inf, sizeof(inf));		ptr += sizeof(inf);
			}
			break;
		case M_WAKE:
			{
				struct task_struct* t1 = (struct task_struct*)p->p1;
				struct task_struct* t2 = (struct task_struct*)p->p2;

				struct tsai_context_switch_info inf;
				inf.sleep_us = p->p4;
				inf.cpu_core = p->p3;
				inf.pid1 = t1->pid;
				inf.tgid1 = t1->tgid;
				inf.state1 = t1->state;
				inf.in_iowait1 = t1->in_iowait;
				memcpy(inf.comm1, t1->comm, sizeof(inf.comm1));

				inf.pid2 = t2->pid;
				inf.tgid2 = t2->tgid;
				inf.state2 = t2->state;
				inf.in_iowait2 = t2->in_iowait;
				memcpy(inf.comm2, t2->comm, sizeof(inf.comm2));

				memcpy(ptr, &inf, sizeof(inf));		ptr += sizeof(inf);
			} break;
		case M_IRQC:
			{
				struct tsai_irq_core_info inf;
				inf.action = (struct irqaction*) p->p1;
				inf.duration_us = (unsigned int) p->p2;
				inf.pid = (unsigned int) p->p3;
				memcpy(ptr, &inf, sizeof(inf));		ptr += sizeof(inf);
			}
			break;
		}
	}

	/* notifying worker to process the data */
	if (!(marker==M_SHON || marker==M_SHOF || marker==M_WAKE))
		tsai_spy_wake_work_queue(pr, TP_PROCESS_TRACE_BUF);

}

TSAI_STATIC void tsai_profile_thread_fn_sleep(struct TSAI_PROFILER_DATA* pr) {
	atomic_set(&pr->worker_go, 1);
	__set_current_state(TASK_UNINTERRUPTIBLE);
	schedule();
}
#include <linux/cpumask.h>

/* when called from tracepoint sched_switch, prev is previous task, otherwise NULL */
TSAI_STATIC void tsai_profile_thread_fn_wake(struct TSAI_PROFILER_DATA* pr, struct task_struct *prev) {
	int cur_cpu;
	//int wakee_cpu;
	struct task_struct* wakee;
	struct timespec timestamp;
	struct cpumask new_mask;

	TSAI_PROFILER_LOG("tsai_profile_thread_fn_wake[enter] pr->worker_go=%d wrk state %d @%d\n",
			atomic_read(&pr->worker_go), pr->worker_thread->state, __LINE__);

	/* used to judge by atomic_dec_and_test(&pr->worker_go), remove worker_go variable if not needed */
	if (pr->worker_thread->state==TASK_UNINTERRUPTIBLE )
	{
		/* this function is called within tsai_probe_sched_switch()
		 * cannot call wake_up_process if it's on the same core, it will fall into deadlock due to rq->lock already locked */
		wakee = pr->worker_thread;
		if (wakee==prev && wakee) {
			TSAI_PROFILER_LOG("tsai_profile_thread_fn_wake wakee==prev UNABLE TO WAKE UP @%d\n", __LINE__);
			atomic_set(&pr->worker_go, 1);
			return;
		}
		cur_cpu = smp_processor_id();
		cpumask_setall(&new_mask);
		cpumask_clear_cpu(cur_cpu, &new_mask);
		/* do not use set_cpus_allowed_ptr(), cause deadlock */
		/*set_cpus_allowed_ptr(wakee, &new_mask);*/
		wakee->cpus_allowed.bits[0] = new_mask.bits[0];

		TSAI_PROFILER_LOG("tsai_profile_thread_fn_wake wakee cpu mask %08x @%d\n", new_mask.bits[0], __LINE__);
		getrawmonotonic(&timestamp);
		TSAI_PROFILER_LOG("tsai_profile_thread_fn_wake ts %d.%09d @%d\n", timestamp.tv_sec, timestamp.tv_nsec, __LINE__);

		/* there is a chance that wakee is about to sleep but has not falled into sleep yet,
		 * so cannot wake it up if it has not actually been sleeping,
		 * 20180919: if wakee is in middle of schedule, but that schedule is going waiting on a spinlock 'prev' task currently owned,
		 * then it comes deadlock, so in that case, give up the wake up attempt
		 *  */
		while (wakee->on_cpu) {
			if (wakee->state==TASK_UNINTERRUPTIBLE) {
				TSAI_PROFILER_LOG("tsai_profile_thread_fn_wake UNABLE to wake, wakee in middle of schedule waiting for spinlock own by this cpu @%d\n", __LINE__);
				atomic_set(&pr->worker_go, 1);
				return;
			}
			cpu_relax();
		}

		wake_up_process(wakee);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
		smp_send_reschedule(wakee->wake_cpu); /* make the CPU wakee is on to reschedule */
#else
		(void)wakee;
		BKPT;
#endif
	}
}

TSAI_STATIC unsigned int tsai_spy_capture_sample(struct TSAI_PROFILER_DATA* pr);

TSAI_STATIC int tsai_profile_thread_fn(void *arg)
{
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)arg;
	struct timespec timestamp;
	struct mm_struct* saved_mm;
	int save_mm = 0;
	unsigned int running = 0;
	unsigned int wake_from_sleep = 0;
	unsigned int interval_us;


	struct sched_param param = {.sched_priority = 1};
	sched_setscheduler(current, SCHED_RR, &param);

	interval_us = 1000000 / pr->user_request.timer_frequency;

	tsai_backup_mm(&save_mm, &saved_mm, pr->profiling_task->mm);

	while(1) {
		getrawmonotonic(&timestamp);
		TSAI_PROFILER_LOG("tsai_profile_thread_fn looping ts %d.%09d @%d\n", timestamp.tv_sec, timestamp.tv_nsec, __LINE__);

		if (!pr->opt_engine_timer) {
			running = tsai_spy_capture_sample(pr);
		}
		tsai_vma_mgr_process_defer_read(&pr->vma_mgr);

		if (!running) {
			atomic_set(&pr->worker_go, 1);
			tsai_profile_thread_fn_sleep(pr); /* force sleep to be woken up */
			wake_from_sleep = 1;
		}

		/* sleep to make up the desired interval before going on to next */
		if (pr->opt_engine_timer==0 && !wake_from_sleep) {
			struct timespec ts2;
			int delta;
			int sleep_us;
			getrawmonotonic(&ts2);
			delta = tsai_diff_microsec64(&timestamp, &ts2);

			if (delta > interval_us)
				sleep_us = 0;
			else
				sleep_us = interval_us - delta;

			if (sleep_us > 0) {
				TSAI_PROFILER_LOG("tsai_profile_thread_fn wait %d us then carrying on @%d\n", sleep_us, __LINE__);
				usleep_range(sleep_us, sleep_us + 20);
			}
			wake_from_sleep = 0;
		}

		if (!(pr->profiling_task && pr->profiler_collecting)) {
			while(atomic_read(&pr->engine_pending_smp))
				cpu_relax();

			getrawmonotonic(&timestamp);
			break;
		}
	}

	TSAI_PROFILER_LOG("tsai_profile_thread_fn QUIT ts %d.%09d @%d\n", timestamp.tv_sec, timestamp.tv_nsec, __LINE__);
	tsai_restore_mm(&save_mm, &saved_mm);

	return 0;
}


TSAI_STATIC int tsai_trigger_hrtimer_asap(struct hrtimer *timer) {
	int ret;
	ktime_t time;
	time.tv64 = 0;
	ret = __hrtimer_start_range_ns(timer, time, 0, HRTIMER_MODE_ABS, 0);
	return ret;
}

TSAI_STATIC void tsai_probe_irq_entry(void* data, PARAMS(TP_PROTO(int irq, struct irqaction *action))) {
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)data;
	if ((pr->profiling_task) && current->tgid == pr->profiling_task->tgid) {
		if (pr->user_request.f_current_thread_only==0 ||
				(pr->user_request.f_current_thread_only && pr->profiling_task==current) )
		{
			struct tsai_profiling_task_node* tnode;
			tnode = tsai_spy_profiling_find_task(pr, current->pid);

			if (tnode->irq_on_task) {
				TSAI_PROFILER_LOG("WARNING: probe_irq_entry double entry? prev %d %s ts %d.%09d @%d\n", tnode->irq_on_task->irq,
						tnode->irq_on_task->name, tnode->irq_timestamp_en.tv_sec, tnode->irq_timestamp_en.tv_nsec, __LINE__);
			}
			tnode->irq_on_task = action;
			getrawmonotonic(&tnode->irq_timestamp_en);
			TSAI_PROFILER_LOG("probe_irq_entry %d ts %d.%09d @%d\n", action->irq,
					tnode->irq_timestamp_en.tv_sec, tnode->irq_timestamp_en.tv_nsec, __LINE__);
		}
	}
}

/* return 1: interested in this task
 * 0: not interested in this task
 * */
TSAI_STATIC inline int tsai_interested_in_task(struct TSAI_PROFILER_DATA* pr, struct task_struct *t) {
	if ((pr->profiling_task) && t->tgid == pr->profiling_task->tgid) {
		if (pr->user_request.f_current_thread_only==0 ||
				(pr->user_request.f_current_thread_only && pr->profiling_task==t) )
		{
			return 1;
		}
	}

	return 0;
}

TSAI_STATIC  void tsai_probe_irq_exit(void* data, PARAMS(TP_PROTO(int irq, struct irqaction *action, int ret)) ) {
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)data;
	struct tsai_trace_marker_param p;
	if ((pr->profiling_task) && current->tgid == pr->profiling_task->tgid) {
		if (pr->user_request.f_current_thread_only==0 ||
				(pr->user_request.f_current_thread_only && pr->profiling_task==current) )
		{
			struct tsai_profiling_task_node* tnode;
			int delta;
			tnode = tsai_spy_profiling_find_task(pr, current->pid);
			if (tnode) {
				getrawmonotonic(&tnode->irq_timestamp_ex);
				delta = tsai_diff_microsec64(&tnode->irq_timestamp_en, &tnode->irq_timestamp_ex);

				ASSERT(tnode->irq_on_task == action);
				TSAI_PROFILER_LOG("probe_irq_exit %d ts %d.%09d @%d\n", action->irq,
						tnode->irq_timestamp_ex.tv_sec, tnode->irq_timestamp_ex.tv_nsec, __LINE__);

				p.p1 = (uint64_t)tnode->irq_on_task;
				p.p2 = (uint64_t)delta;
				p.p3 = (uint64_t)tnode->pid;

				tsai_spy_profiler_write_trace_marker(pr, M_IRQC, &tnode->irq_timestamp_en, &p);

				tnode->irq_on_task = NULL;
			}
		}
	}
}

/* when sche happens, it will go to this function, inside this function interrupt should have been disabled
 * do not use kmalloc etc, it will enable interrupt and fall into complication siutation
 *  */
TSAI_STATIC  void tsai_probe_sched_switch(void *data, PARAMS(TP_PROTO(struct task_struct *prev, struct task_struct *next))) {
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)data;
			/* restart a timer may require waking up some other process, which requires scheduler to do something,
			 * since this is the tracepoint of scheduler, it becomes deadlock
			 * deferred work queue also have the same problem!
			 * */
	struct tsai_profiling_task_node* tnode;
	struct timespec timestamp;
	struct tsai_trace_marker_param p;
	//unsigned long flags;
	int delta;
	tsai_spy_mem_log_mark_rq_lock(1);
	if ((pr->profiling_task) && next->tgid == pr->profiling_task->tgid) {
		if (pr->user_request.f_current_thread_only==0 ||
				(pr->user_request.f_current_thread_only && pr->profiling_task==next) )
		{
			int timer_status;
			int timer_pending;
			int cpu = tsai_cpu_core_id();
			unsigned int value = 1<<(tsai_24bit_value(next->pid)) | 1 << (24 + cpu);
			pr->sche_mask |= value;
			tnode = tsai_spy_profiling_find_task(pr, next->pid);
			tnode->sched_away = 0;
			getrawmonotonic(&tnode->sched_on_timestamp);
			delta = tsai_diff_microsec64(&tnode->sched_off_timestamp, &tnode->sched_on_timestamp);
			p.p1 = (uint64_t)next;
			p.p2 = (uint64_t)prev;
			p.p3 = (uint64_t)cpu;
			p.p4 = (uint64_t)delta;
			tsai_spy_profiler_write_trace_marker(pr, M_SHON, &tnode->sched_on_timestamp, &p);

			if (pr->opt_engine_timer) {
				timer_status = atomic_read(&pr->timer_status);
				timer_pending = atomic_read(&pr->engine_pending_smp);
				if (timer_status==1 && timer_pending==0) {
					int timer_in_callback = pr->profiling_timer.state & HRTIMER_STATE_CALLBACK;
					if (timer_in_callback) {
						TSAI_PROFILER_LOG("waking up, but timer callback is not done @%d\n", __LINE__);
					}
					else {
						TSAI_PROFILER_LOG("waking up, trigger timer asap @%d\n", __LINE__);
						tsai_trigger_hrtimer_asap(&pr->profiling_timer);
					}
				}
			}

			TSAI_PROFILER_LOG("sched_switch pid %d ON core %d ts %d.%09d @%d\n",
					next->pid, cpu, timestamp.tv_sec, timestamp.tv_nsec, __LINE__);

			tsai_profile_thread_fn_wake(pr, prev);
		}
	}
	if ((pr->profiling_task) && prev->tgid == pr->profiling_task->tgid) {
		if (pr->user_request.f_current_thread_only==0 ||
				(pr->user_request.f_current_thread_only && pr->profiling_task==prev) )
		{
			int cpu = tsai_cpu_core_id();
			tnode = tsai_spy_profiling_find_task(pr, prev->pid);
			tnode->sched_away = 1;

			getrawmonotonic(&tnode->sched_off_timestamp);
			delta = tsai_diff_microsec64(&tnode->sched_on_timestamp, &tnode->sched_off_timestamp);

			p.p1 = (uint64_t)prev;
			p.p2 = (uint64_t)next;
			p.p3 = (uint64_t)cpu;
			p.p4 = (uint64_t)delta;
			tsai_spy_profiler_write_trace_marker(pr, M_SHOF, &tnode->sched_off_timestamp, &p);
#if 0	/* temp, to check io schedule wait */
			if (prev->in_iowait) {
				BKPT;
			}
#endif
			TSAI_PROFILER_LOG("sched_switch pid %d %s io_wait %d OFF core %d st %d on_rq %d, ts %d.%09d @%d\n",
					prev->pid, prev->comm, prev->in_iowait, cpu, prev->state, prev->on_rq,
					tnode->sched_off_timestamp.tv_sec, tnode->sched_off_timestamp.tv_nsec, __LINE__);
		}
	}
	tsai_spy_mem_log_mark_rq_lock(0);
}

/* inside this probe, rq lock has been obtained, so do not try to acquire the same lock again (dead lock)
 *
 * */
TSAI_STATIC void tsai_probe_sched_wakeup(void *data, struct task_struct *wakee, int success)
{
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)data;
	struct timespec timestamp;
	int delta;
	tsai_spy_mem_log_mark_rq_lock(1);
	if (tsai_interested_in_task(pr, wakee)) {
		struct tsai_profiling_task_node* tnode;
		getrawmonotonic(&timestamp);
		TSAI_PROFILER_LOG("sched_wakeup RAW pid %d %s WAKE UP st %d on_rq %d by task %p ts %d.%09d @%d\n",
				wakee->pid, wakee->comm, wakee->state, wakee->on_rq, current, timestamp.tv_sec, timestamp.tv_nsec, __LINE__);
		tnode = tsai_spy_profiling_find_task(pr, wakee->pid);
		{ /* write a trace marker */
			struct tsai_trace_marker_param p;
			delta = tsai_diff_microsec64(&tnode->sched_off_timestamp, &timestamp);
			p.p1 = (uint64_t)tnode->wake_by_task;
			p.p2 = (uint64_t)tnode->task;
			p.p3 = (uint64_t)0;
			p.p4 = (uint64_t)delta;
			tsai_spy_profiler_write_trace_marker(pr, M_WAKE, &timestamp, &p);
		}
		{
			unsigned long irqflags;
			spin_lock_irqsave(&tnode->save_state_lock, irqflags);
			if (atomic_read(&tnode->save_state_flag)) {
				int old_state;
				int old_on_rq;
				int old_cpu;

#if 0 && defined(DEBUG)
				if (!pr->opt_engine_timer) {
					/* usually this will lead to deadlock when this wakee being sched on a cpu core!
					 * investigate to see what did I miss?
					 * */
					BKPT;
				}
#endif

				tsai_task_prevent_run(wakee, 1, NULL, &old_state, &old_on_rq, &old_cpu);

				tnode->saved_state = TASK_RUNNING; /* once going out probe_sched_wakeup, task->state will become 0 (TASK_RUNNING)*/
				tnode->saved_on_rq = old_on_rq;
				ASSERT(old_on_rq); /* since this function is wake up, on_rq must be 1 on entering */
				TSAI_PROFILER_LOG("sched_wakeup pid %d %s WAKE UP s_st %d s_on_rq %d ts %d.%09d @%d\n",
						wakee->pid, wakee->comm, tnode->saved_state, tnode->saved_on_rq,
						timestamp.tv_sec, timestamp.tv_nsec, __LINE__);
			}
			spin_unlock_irqrestore(&tnode->save_state_lock, irqflags);
		}
	}
	tsai_spy_mem_log_mark_rq_lock(0);
}

TSAI_STATIC void tsai_probe_sched_try_wakeup(void *data, struct task_struct *wakee, int success)
{
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)data;
	struct timespec timestamp;
	//int delta;
	if (tsai_interested_in_task(pr, wakee)) {
		struct tsai_profiling_task_node* tnode;
		getrawmonotonic(&timestamp);
		TSAI_PROFILER_LOG("sched_try_wakeup RAW pid %d %s WAKE UP st %d on_rq %d by task %p ts %d.%09d @%d\n",
				wakee->pid, wakee->comm, wakee->state, wakee->on_rq, current, timestamp.tv_sec, timestamp.tv_nsec, __LINE__);
		tnode = tsai_spy_profiling_find_task(pr, wakee->pid);
		tnode->wake_by_task = current;
	}
}
struct tsai_task_frame_information {
	union {
		unsigned int dummy_value;
		struct {
			unsigned int frame_full:8;
			unsigned int frame_kern:8;
			unsigned int task_state:2; /* last 2 bit of task->state */
			unsigned int task_on_cpu:1;
			unsigned int task_on_core:4;
		};
	};
	unsigned int plt_target;
};


TSAI_STATIC  void tsai_spy_profiler_write_trace_sample(struct TSAI_PROFILER_DATA* pr, struct tsai_profiling_task_node* tnode,
		struct tsai_profiling_sample* s)
{
	struct tsai_task_frame_information tfi;
	int bytes_needed;
	int bytes_needed_sample;
	unsigned char* ptr;

	tfi.frame_full = s->full_frames;
	tfi.frame_kern = s->kern_frames;
	tfi.task_state = tnode->task->state & 0x3;
	tfi.task_on_cpu = tnode->task->on_cpu;
	tfi.plt_target = s->plt_target;

	if (tfi.task_on_cpu) {
		if (tnode->task==current) {
			tfi.task_on_core = smp_processor_id();
		}
	}

	bytes_needed_sample = (s->full_frames) * sizeof(unsigned int);
	bytes_needed = 4 * 5 + sizeof(struct tsai_task_frame_information) + bytes_needed_sample;
	ptr = (unsigned char*)tsai_spy_profiler_reserve_trace_buffer(pr, bytes_needed);

	if (ptr) {
		int i;
		/* write an identifier 'SMPL' */
		*(unsigned int*)ptr = CONSTR_SMPL; 	ptr += 4;
		*(unsigned int*)ptr = bytes_needed; 						ptr += 4;
		*(unsigned int*)ptr = (unsigned int)(NATIVE_UINT)tnode; 					ptr += 4;
		*(unsigned int*)ptr = pr->timestamp.tv_sec; 				ptr += 4;
		*(unsigned int*)ptr = pr->timestamp.tv_nsec; 				ptr += 4;
		memcpy(ptr,&tfi, sizeof(tfi)); ptr += sizeof(tfi);
#ifdef DEBUG
		{
			int delta = tsai_diff_microsec64(&pr->timestamp_lastwrite, &pr->timestamp);
			ASSERT(delta >= 0);
		}
#endif
		pr->timestamp_lastwrite = pr->timestamp;

		for (i=0; i<s->full_frames; i++) {
			*(unsigned int*)ptr = s->frame[i].pc;
			ptr += 4;
		}
	}

	/* notifying worker to process the data,
	 * when reaching here, if ptr, then new data need to be processed,
	 * if (!ptr) means buffer has no space so worker need to wake up and process
	 *  */
	{
		tsai_spy_wake_work_queue(pr, TP_PROCESS_TRACE_BUF);
	}

}

TSAI_STATIC int tsai_spy_profiler_trace_identifier_valid(unsigned int identifier) {
	int ret = 0;
	switch (identifier) {
	case CONSTR_BEGN:
	case CONSTR_ENDT:
	case CONSTR_SLEP:
	case CONSTR_SHON:
	case CONSTR_SHOF:
	case CONSTR_SMPL:
	case CONSTR_IRQC:
	case CONSTR_WAKE:
		ret = 1;
		break;
	default:
		;
	}
	return ret;
}


/* read one sample, process and return, caller will maintain the loop
 * return:
 * 0: encounter end of trace, caller should quit the loop
 * -1: error encountered, caller should handle it!
 * */
TSAI_STATIC int tsai_spy_profiler_read_trace(struct TSAI_PROFILER_DATA* pr, unsigned char* ptr_in)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct tsai_task_frame_information tfi;
	struct thread_info *task_ti;
	unsigned char* ptr = ptr_in;
	unsigned char* ptr_end;
	int frame_idx;
	int bytes_needed;
	int bytes_needed_sample;
	struct tsai_profiling_task_node* tnode;
	struct timespec timestamp;
	char full_path[256];
	char* ptr_full_path;
	int ret = 0;
	unsigned int identifier;
	int delta;

	identifier = *(unsigned int*)ptr; 							ptr += 4;
	if (!tsai_spy_profiler_trace_identifier_valid(identifier)) {
		ret = -1;
		goto Leave;
	}
	bytes_needed = *(int*)ptr ; 						ptr += 4;
	ASSERT(bytes_needed > 0 && bytes_needed< 1024 );
	ptr_end = ptr_in + bytes_needed;
	tnode = (struct tsai_profiling_task_node*)(NATIVE_UINT) (*(unsigned int*)ptr); 					ptr += 4;
	timestamp.tv_sec = *(unsigned int*)ptr ; 				ptr += 4;
	timestamp.tv_nsec = *(unsigned int*)ptr ; 				ptr += 4;

	delta = tsai_diff_microsec64(&pr->timestamp_lastread, &timestamp);
	ASSERT(delta >= 0);

	switch (identifier) {
	case CONSTR_BEGN:
		tsai_spy_mem_log(&pr->mem_log, "BEGIN OF TRACE @ts %d.%09d by worker task %d %s\n\n",
				timestamp.tv_sec, timestamp.tv_nsec, current->pid, current->comm);
		break;
	case CONSTR_ENDT:
		tsai_spy_mem_log(&pr->mem_log, "END OF TRACE @ts %d.%09d\n\n", timestamp.tv_sec, timestamp.tv_nsec);
		tsai_spy_mem_log_flush(&pr->mem_log, 1);
		tsai_spy_mem_log_flush(&pr->unwind_log, 1);
		/* do the actual free the trace, close the trace file, etc*/
		tsai_spy_profiler_defer_free(pr);
		goto Leave;
		break;
	case CONSTR_SLEP:
		tsai_spy_mem_log(&pr->mem_log, "ALL SLEEP @ts %d.%09d\n\n", timestamp.tv_sec, timestamp.tv_nsec);
		break;
	case CONSTR_SHON:
	case CONSTR_SHOF:
		{
			struct tsai_context_switch_info inf;
			memcpy(&inf, ptr, sizeof(inf)); ptr += sizeof(inf);

			if (identifier==CONSTR_SHON) {
				tsai_spy_mem_log(&pr->mem_log, "Task pid %d %s st %d SHED ON core %d, replacing %d %s st %d sleep_us %u @ts %d.%09d\n\n",
					inf.pid1, inf.comm1, inf.state1, inf.cpu_core, inf.pid2, inf.comm2, inf.state2,
					inf.sleep_us, timestamp.tv_sec, timestamp.tv_nsec);
			}
			else if (identifier==CONSTR_SHOF) {
				const char* sleep_type = (inf.state1)? "SLEEP":"CONTENTION" ;
				tsai_spy_mem_log(&pr->mem_log, "Task pid %d %s st %d io %d SHED OFF core %d (%s), giving to %d %s st %d wake_us %u @ts %d.%09d\n\n",
						inf.pid1, inf.comm1, inf.state1, inf.in_iowait2, inf.cpu_core, sleep_type, inf.pid2, inf.comm2, inf.state2, inf.sleep_us,
					timestamp.tv_sec, timestamp.tv_nsec);
			}

		}
		break;
	case CONSTR_WAKE:
		{
			struct tsai_context_switch_info inf;
			memcpy(&inf, ptr, sizeof(inf)); ptr += sizeof(inf);
			tsai_spy_mem_log(&pr->mem_log, "Task pid %d %s st %d WAKE by %d %s delta_us %u @ts %d.%09d\n\n",
				inf.pid2, inf.comm2, inf.state2, inf.pid1, inf.comm1,
				inf.sleep_us, timestamp.tv_sec, timestamp.tv_nsec);
		}
		break;
	case CONSTR_SMPL:
		{
			char sCore[4];
			char symbol[128];
			memcpy(&tfi, ptr, sizeof(tfi)); ptr += sizeof(tfi);
			if (tfi.task_on_cpu) {
				sCore[0] = '0' + tfi.task_on_core;
				sCore[1] = 0;
			}

			tsai_spy_mem_log(&pr->mem_log, "Task %s %d @ts %d.%09d seq %d state %d core %s fullframe %d kernframe %d prvts %d.%09d delta %d \n", tnode->task->comm, tnode->task->pid,
					timestamp.tv_sec, timestamp.tv_nsec, pr->seqno_lastread, tfi.task_state, (tfi.task_on_cpu? sCore:"N/A"),
							tfi.frame_full, tfi.frame_kern, pr->timestamp_lastread.tv_sec, pr->timestamp_lastread.tv_nsec, delta);
			bytes_needed_sample = ptr_end - ptr;
			task_ti = task_thread_info(tnode->task);
			for(frame_idx=0 ; ptr < ptr_end; frame_idx++) {
				unsigned int pc;
				pc = *(unsigned int*)ptr ;
				if (frame_idx < tfi.frame_kern) {
					ASSERT(pc > (unsigned int)task_ti->addr_limit);
					sprint_symbol_no_offset(symbol, pc);
					tsai_spy_mem_log(&pr->mem_log, "#%d %08x %s\n", frame_idx, pc, symbol );
				}
				else
				{
					unsigned int symbol_addr;
					const char* symbol_str;
					if (frame_idx == tfi.frame_kern) {
						if (tfi.frame_kern)
							tsai_spy_mem_log(&pr->mem_log, "---------------\n" );

						if (tfi.plt_target) {
							symbol_addr = tsai_callstack_demangle_bin_symbol(&pr->vma_mgr, tnode->task, (void*)(NATIVE_UINT)tfi.plt_target,
								full_path, sizeof(full_path), &ptr_full_path, &symbol_str);
							tsai_spy_mem_log(&pr->mem_log, "%08x=(PLT jumping to) %08x %s %s\n",
									pc, tfi.plt_target, symbol_addr?symbol_str:"", ptr_full_path);
						}
					}

					symbol_addr = tsai_callstack_demangle_bin_symbol(&pr->vma_mgr, tnode->task, (void*)(NATIVE_UINT)pc,
						full_path, sizeof(full_path), &ptr_full_path, &symbol_str);
					if (!symbol_addr) {
						if (frame_idx == tfi.frame_kern && tfi.plt_target)
							symbol_str = "(PLT)";
						else
							symbol_str = "N/A";
					}
					tsai_spy_mem_log(&pr->mem_log, "#%d %08x %s %s\n", frame_idx, pc, symbol_str, ptr_full_path);
				}

				ptr += 4;
			}
			tsai_spy_mem_log(&pr->mem_log, "\n");
			pr->seqno_lastread++;
		}
		break;
	case CONSTR_IRQC:
		{
			struct tsai_irq_core_info* pinf = (struct tsai_irq_core_info*)ptr;
			ptr += sizeof(*pinf);
			tsai_spy_mem_log(&pr->mem_log, "IRQ %d %s on pid %d @ts %d.%09d dur(us) %d \n",
					pinf->action->irq, pinf->action->name, pinf->pid,
					timestamp.tv_sec, timestamp.tv_nsec,
					pinf->duration_us);
		}
		break;
	default:
		BKPT;
		goto Leave;
	}
	pr->timestamp_lastread = timestamp;
	ret = bytes_needed;
Leave:
	return ret;
#else
	return 0;
#endif
}

TSAI_STATIC void tsai_spy_profiler_process_trace(struct TSAI_PROFILER_DATA* pr) {

	int exit_condition = 0;
	int r,w, curtail, size;
	int temp_limit;
	unsigned char* ptr;
	unsigned long irq_flags;
	size = pr->profiling_trace_buf_size;
ReTry:
	tsai_spy_mem_log_flush(&pr->unwind_log, 0);
	spin_lock_irqsave(&pr->profiling_trace_buf_lock, irq_flags);
		if (pr->profiling_trace_event_lost) {
			tsai_spy_mem_log(&pr->mem_log, "WARNING: %d events are lost\n", pr->profiling_trace_event_lost);
			pr->profiling_trace_event_lost = 0;
		}

		r = pr->profiling_trace_buf_cur_r;
		w = pr->profiling_trace_buf_cur_w;
		curtail = pr->profiling_trace_buf_curtail;

		if (r==w && !curtail)
			exit_condition = 1;
		else if (r==curtail) {
			r = pr->profiling_trace_buf_cur_r = 0;
			curtail = pr->profiling_trace_buf_curtail = 0;

			if (tsai_log_profiler_buffer_dyn)
				tsai_log_profiler_buffer = 0;

		}
		else if (curtail && (r > curtail) ) { /* an error situation and should have not happened */
			BKPT;
#ifdef DEBUG
			tsai_log_profiler_buffer = 1;
#endif
			if (tsai_log_profiler_buffer) {
				tsai_spy_mem_log(&pr->mem_log, "ERROR r=%d w=%d curtail=%d exit_condition=%d @%d\n", r, w, curtail, exit_condition, __LINE__);
			}

			r = pr->profiling_trace_buf_cur_r = 0;
			curtail = pr->profiling_trace_buf_curtail = 0;
		}

	spin_unlock_irqrestore(&pr->profiling_trace_buf_lock, irq_flags);
	if (tsai_log_profiler_buffer) {
		tsai_spy_mem_log(&pr->mem_log, "r=%d w=%d curtail=%d exit_condition=%d @%d\n", r, w, curtail, exit_condition, __LINE__);
	}

	if (!exit_condition) {
		if (r < w)
			temp_limit = w;
		if (r > w) {
			if (curtail)
				temp_limit = curtail;
			else
				temp_limit = pr->profiling_trace_buf_size;
		}

		if (r < temp_limit) {
			int ret;

			if (tsai_log_profiler_buffer) {
				tsai_spy_mem_log(&pr->mem_log, "r=%d w=%d temp_limit=%d\n", r, w, temp_limit);
			}

			ptr = (unsigned char*)pr->profiling_trace_buf + r;
			ret = tsai_spy_profiler_read_trace(pr, ptr);
			if (!ret) {
				goto Leave;
			}
			else if (ret==-1) {
				tsai_spy_mem_log(&pr->mem_log, "CORRUPTED TRACE DATA r=%d w=%d temp_limit=%d @%d\n", r, w, temp_limit, __LINE__);
				if (r > (pr->profiling_trace_buf_size - 1024)) { /* Error tolerance recovery */
					spin_lock_irqsave(&pr->profiling_trace_buf_lock, irq_flags);
					r = pr->profiling_trace_buf_cur_r =	0;
					pr->profiling_trace_buf_curtail = 0;
					spin_unlock_irqrestore(&pr->profiling_trace_buf_lock, irq_flags);
					tsai_spy_mem_log(&pr->mem_log, "SKIP CORRUPT TRACE DATA r=%d\n", r);
					goto ReTry;
				}
				else {
					BKPT;
					spin_lock_irqsave(&pr->profiling_trace_buf_lock, irq_flags);
					w = pr->profiling_trace_buf_cur_w;
					r = pr->profiling_trace_buf_cur_r =	pr->profiling_trace_buf_cur_w;
					pr->profiling_trace_buf_curtail = 0;
					spin_unlock_irqrestore(&pr->profiling_trace_buf_lock, irq_flags);
					tsai_spy_mem_log(&pr->mem_log, "SKIP CORRUPT TRACE DATA r=%d w=%d\n", r, w);
					goto Leave;
				}
			}
			ASSERT(ret > 0);
			r += ret;
		}
		spin_lock_irqsave(&pr->profiling_trace_buf_lock, irq_flags);
		pr->profiling_trace_buf_cur_r =	r;
		spin_unlock_irqrestore(&pr->profiling_trace_buf_lock, irq_flags);

		goto ReTry;
	}
Leave:
	atomic_set(&pr->profiler_work_pending, 0);
	//tsai_spy_mem_log_flush(&pr->mem_log, 0);
	tsai_spy_mem_log_flush(&pr->unwind_log, 0);
}


/* if nothing has changed, early out, this function is called before tnode->active_sample swap */
TSAI_STATIC  int tsai_spy_parse_stack_early_exit(struct TSAI_PROFILER_DATA* pr, struct task_struct* t, struct pt_regs* kregs, struct pt_regs* uregs, struct tsai_profiling_task_node* tnode) {
#ifdef __aarch64__
	/* not implmented yet */
	BKPT;
#else
	struct tsai_profiling_sample* prevs;
	unsigned int cur_state = tsai_tnode_task_state(tnode);
	prevs = &tnode->sample[ (tnode->active_sample) ];
	tnode->unchanged_kern = 0;
	tnode->unchanged_user = 0;

	if (cur_state == prevs->task_state) {
		struct tsai_profiling_frame* user_frame;
		if (kregs) {
			if (prevs->kern_frames ) {
				if (prevs->frame[0].pc != kregs->uregs[15]) {
					 ;
				}
				else if (prevs->frame[0].sp_saved != kregs->uregs[11]) {
					;
				}
				else {
					tnode->unchanged_kern = 1;
				}
			}
			else {
				;
			}
			TSAI_PROFILER_LOG("Checking kern_unchanged %d kreg prev R15 %08x R11 %08x Now R15 %08x R11 %08x @%d\n",
					tnode->unchanged_kern, prevs->kern_frames?prevs->frame[0].pc:0, prevs->kern_frames?prevs->frame[0].sp_saved:0,
							kregs->uregs[15], kregs->uregs[11], __LINE__);

		}
		else {
			if (prevs->kern_frames ) {
				;
			}
		}

		/* check user flag */
		user_frame = &prevs->frame[prevs->kern_frames];

		TSAI_PROFILER_LOG("Checking user mode reg prev R15 %08x R13 %08x Now R15 %08x R13 %08x @%d\n",
				user_frame->pc, user_frame->sp_saved, uregs->uregs[15], uregs->uregs[13], __LINE__);

		if (user_frame->pc == uregs->uregs[15] && user_frame->sp_saved==uregs->uregs[13])
			tnode->unchanged_user = 1;


		if (tnode->unchanged_kern && tnode->unchanged_user)
			return 1;

	}
#endif
	return 0;
}


/* return:
 * 0=ok
 * negative value = error code */
TSAI_STATIC int tsai_spy_parse_stack(struct TSAI_PROFILER_DATA* pr, struct task_struct* t, struct pt_regs* regs,
		struct tsai_profiling_task_node* tnode)
{
#ifdef __aarch64__
	BKPT;
	return 0;
#else
	struct thread_info* ti = current_thread_info();
	struct task_struct* cur_task = ti->task;
	int ret = 0;
	int ret2;
	int i;
	int early_out;
	unsigned int task_state;
	struct stackframe fr;
	int is_user_mode;
	struct pt_regs reg_stack;
	struct pt_regs* reg_user = NULL;
	struct mm_struct* saved_mm;
	int save_mm = 0;

	struct TSAI_TRACE_CALLBACK_DATA cd;
	struct tsai_profiling_sample* prevs;
	struct tsai_profiling_sample* s;
	struct timespec ts1;
	struct timespec ts2;

	if (!tnode)
		tnode = tsai_spy_profiling_find_task(pr,t->pid);

	task_state = tsai_tnode_task_state(tnode);
#ifdef DEBUG
	{
		const char* on_core_str = tsai_task_on_cpu_str(t);
		TSAI_PROFILER_LOG("===tsai_spy_parse_stack %d ts %d.%09d task %08x(%d) %s state %d core %s ->on_rq %d====@%d\n", pr->interrupts_cnt,
				pr->timestamp.tv_sec, pr->timestamp.tv_nsec, t, t->pid, t->comm, task_state, on_core_str,
				t->on_rq, __LINE__);
	}
#endif
	if (t->on_cpu) {
		if (tsai_task_on_cpu(t) != ti->cpu) {
			TSAI_PROFILER_LOG("LEAVE tsai_spy_parse_stack due task is on core but not this core====@%d\n", __LINE__);
			goto Leave;
		}
	}

	/* to avoid race condition, only first enter will be processed if 2 thread enter the same time with same task */
	if (atomic_cmpxchg(&tnode->is_in_process, 0, 1) == 1) {
		TSAI_PROFILER_LOG("LEAVE tsai_spy_parse_stack due to race condition ====@%d\n", __LINE__);
		goto Leave;
	}

	s = &tnode->sample[tnode->active_sample];

	cd.tnode = tnode;
	cd.on_pabort = 0;

	/* switch mmu to target process*/

	if (cur_task->mm != pr->profiling_task->mm ) {
		struct mm_struct* mm;
#ifdef DEBUG
		if (cur_task == pr->profiling_task) {
			BKPT;
		}
#endif
		BKPT; /* mm should have been handled by the caller, if entering this clause, something is wrong */
		saved_mm = cur_task->active_mm;
		atomic_inc(&saved_mm->mm_count);
		mm = tsai_get_task_mm_no_irq(pr->profiling_task);
		use_mm(mm);
		save_mm = 1;
	}

	if (!regs) {
		/* likely this is a currently sleep task, task_pt_regs(t) can only get user_mode registers */
		/* to retrive kernel register for a sleep task, use the info stored in thread_info
		 * but if hrtimer interrupt is called from soft IRQ, then cannot use thread info saved registers
		 * as there has been no context switch
		 *
		 * */
		if (t->on_cpu) {
			/* when entering this, meaning get_irq_regs() didn't work, so it's most likely coming through soft IRQ */
			reg_stack.uregs[0] = 0;
			reg_stack.uregs[1] = 0;
			reg_stack.uregs[2] = 0;
			reg_stack.uregs[3] = 0;
			reg_stack.uregs[4] = 0;
			reg_stack.uregs[5] = 0;
			reg_stack.uregs[6] = 0;
			reg_stack.uregs[7] = 0;
			reg_stack.uregs[8] = 0;
			reg_stack.uregs[9] = 0;
			reg_stack.uregs[10] = 0;
			__asm("mov %0,r11":"=r"(reg_stack.uregs[11]));
			__asm("mov %0,r12":"=r"(reg_stack.uregs[12]));
			__asm("mov %0,r13":"=r"(reg_stack.uregs[13]));
			__asm("mov %0,r14":"=r"(reg_stack.uregs[14]));
			__asm("mov %0,r15":"=r"(reg_stack.uregs[15]));
			__asm("mrs %0,cpsr":"=r"(reg_stack.uregs[16]));

			ASSERT( (reg_stack.uregs[16] & 0xF) );
		}
		else {
			struct thread_info* ti = task_thread_info(t);

			reg_stack.uregs[0] = 0;
			reg_stack.uregs[1] = 0;
			reg_stack.uregs[2] = 0;
			reg_stack.uregs[3] = 0;
			reg_stack.uregs[4] = ti->cpu_context.r4;
			reg_stack.uregs[5] = ti->cpu_context.r5;
			reg_stack.uregs[6] = ti->cpu_context.r6;
			reg_stack.uregs[7] = ti->cpu_context.r7;
			reg_stack.uregs[8] = ti->cpu_context.r8;
			reg_stack.uregs[9] = ti->cpu_context.r9;
			reg_stack.uregs[10] = 0;
			reg_stack.uregs[11] = ti->cpu_context.fp;
			reg_stack.uregs[12] = 0;
			reg_stack.uregs[13] = ti->cpu_context.sp;
			reg_stack.uregs[14] = 0;
			reg_stack.uregs[15] = ti->cpu_context.pc;
			reg_stack.uregs[16] = 0x13; /* make it in svc mode */
		}
		regs = &reg_stack;
	}

	is_user_mode = user_mode(regs);

	if (is_user_mode) {
		reg_user = regs;
	}
	else {
		reg_user = task_pt_regs(t);
	}

	/* before parsing kernel mode register, check whether things have not been changed at all */
	early_out = tsai_spy_parse_stack_early_exit(pr, t, is_user_mode?0:regs, reg_user, tnode);
	if (early_out) {
		TSAI_PROFILER_LOG("UNCHANGED, EARLY OUT @%d\n", __LINE__);
		/* TODO: write a sample with previous one, need to use a separate marker to save space */
		tsai_spy_profiler_write_trace_sample(pr, tnode, s);
	}
	else {
		getrawmonotonic(&ts1);
		prevs = &tnode->sample[tnode->active_sample];

		tnode->active_sample = (tnode->active_sample+1)&1;
		s = &tnode->sample[tnode->active_sample];
		tsai_profiling_sample_clear(s);
		s->task_state = tsai_tnode_task_state(tnode);
		s->ts_sec = pr->timestamp.tv_sec;
		s->ts_usec = pr->timestamp.tv_nsec;

		if (!is_user_mode) {
			if (tnode->unchanged_kern) {
				/* kernel side callstack is the same but user side has changed? interesting, verify */
				for (i=0; i<prevs->kern_frames; i++)
					s->frame[s->frame_cursor++] = prevs->frame[i];

			}
			else {
				fr.fp = regs->uregs[11];
				fr.sp = regs->uregs[13];
				fr.lr = regs->uregs[14];
				fr.pc = regs->uregs[15];
				walk_stackframe(&fr, tsai_spy_profiling_kernel_trace, &cd);
			}
		}

		s->kern_frames = s->frame_cursor;
		/* parse user mode stacks */

		if (!reg_user) {
			BKPT;
		}

		if (tnode->unchanged_user) {
			/* copy over */
			s->plt_target = prevs->plt_target;
			for (i=prevs->kern_frames; i<prevs->full_frames; i++) {
				s->frame[s->frame_cursor++] = prevs->frame[i];
			}
			s->full_frames = s->frame_cursor;
			TSAI_PROFILER_LOG("user_callstack unchanged, copying over full %d kern %d @%d\n", s->full_frames, s->kern_frames,__LINE__);
		}
		else
		{
			struct tsai_intermediate_regs kregs;
			struct TSAI_PARSE_USER_CALLSTACK param;
			for (i=0; i<16; i++)
				kregs.R[i] = reg_user-> uregs[i];

			kregs.sp_end = t->user_ssp;

			/* if the interrupt directly happen on top of user-mode, then cannot test whether it's Thumb by examine PC & 0x01
			 * in this case examine SPSR register instead
			 *
			 * */
			kregs.frame_is_thumb = (reg_user-> uregs[16] & 0x20) >> 5;
			kregs.on_pabort = cd.on_pabort;
			kregs.interrupt_on_user = is_user_mode?1:0;
			kregs.voluntary = 0;

			tnode->comp_cursor = prevs->kern_frames;

			//BKPT;
			memset(&param, 0, sizeof(param));
			param.tsk_mm = t->mm;
			param.vma_mgr = &pr->vma_mgr;
			param.regs = &kregs;
			param.user_trace = tsai_spy_profiling_user_trace;
			param.user_recover = tsai_spy_profiling_user_recover;
			param.data = tnode;
			ret2 = tsai_parse_user_callstack(&param, pr->interrupts_cnt);

			if (ret2<0)
				ret = ret2;
			if (ret2==1) { /* perfect end reaching entry point, mark the last frame as entry point */
				s->frame[s->frame_cursor-1].f_entrypoint = 1;
			}

			s->full_frames = s->frame_cursor;

		}
		/* write the new sample to trace buffer */
		tsai_spy_profiler_write_trace_sample(pr, tnode, s);
		getrawmonotonic(&ts2);

#ifdef DEBUG
		{
			int timespent = tsai_diff_microsec64(&ts1, &ts2);
			TSAI_PROFILER_LOG("parse_user_callstack ret %d sample frames full %d k %d copied start %d tv %d.%d tspent %d @%d\n",
				ret2, s->full_frames, s->kern_frames, s->copied_start_idx, s->ts_sec, s->ts_usec, timespent, __LINE__);
			if (s->full_frames < s->copied_start_idx)
				BKPT;
		}
#endif

	}

	if (save_mm) {
		mmput(pr->profiling_task->mm);
		use_mm(saved_mm);
		mmput(saved_mm);
	}

	tnode->handled_in_this_interrupt = 1;
	atomic_set(&tnode->is_in_process, 0);
Leave:
	TSAI_PROFILER_LOG("tsai_spy_parse_stack[exit] ret=%d @%d\n", ret, __LINE__);
	return ret;
#endif
}

#ifdef __aarch64__

static inline int tsai_atomic_and_return(int i, atomic_t *v) {
	BKPT;
	return 0;
}

static inline int tsai_atomic_or_return(int i, atomic_t *v) {
	BKPT;
	return 0;
}

#else
#define TSAI_ATOMIC_OP_RETURN(op, asm_op)				\
static inline int tsai_atomic_##op##_return(int i, atomic_t *v)		\
{									\
	unsigned long tmp;						\
	int result;							\
									\
	smp_mb();							\
	prefetchw(&v->counter);						\
									\
	__asm__ __volatile__("@ atomic_" #op "_return\n"		\
"1:	ldrex	%0, [%3]\n"						\
"	" #asm_op "	%0, %0, %4\n"					\
"	strex	%1, %0, [%3]\n"						\
"	teq	%1, #0\n"						\
"	bne	1b"							\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "Ir" (i)					\
	: "cc");							\
									\
	smp_mb();							\
									\
	return result;							\
}

TSAI_ATOMIC_OP_RETURN(and, and);
TSAI_ATOMIC_OP_RETURN(or, orr);
#endif

TSAI_STATIC void tsai_spy_smp_profiling(void *info) {
	struct tsai_spy_profiling_ipi_info* ipi = (struct tsai_spy_profiling_ipi_info*)info;
	struct TSAI_PROFILER_DATA* pr = container_of(ipi,struct TSAI_PROFILER_DATA, ipi);
	int cpu = smp_processor_id();
	unsigned int new_mask;
	unsigned int engine_pending_smp;
	int engine_restart = 0;

	if (current->tgid == pr->profiling_task->tgid) {
		if ( (pr->user_request.f_current_thread_only && current==pr->profiling_task) ||
				pr->user_request.f_current_thread_only==0)
		{
			struct pt_regs* const regs  = get_irq_regs();
			tsai_spy_parse_stack(pr, current, regs, NULL);
			ipi->shed_mask_core |= 1<<(cpu+24);
			pr->sche_mask |= ipi->shed_mask_core;

		}
	}
#if 0
	struct timeval tv_1;
	struct timeval tv_2;
	do_gettimeofday(&tv_1);
	while (1) {
		if (!atomic_read(&ipi->expected_core_reply)) {
			break;
		}
	}
	do_gettimeofday(&tv_2);
	microsec_busywait = tsai_diff_microsec(&tv_1, &tv_2);
	TSAI_PROFILER_LOG(" busy wait t1 %d.%d t2 %d.%d takes %d us \n",
			tv_1.tv_sec, tv_1.tv_usec, tv_2.tv_sec, tv_2.tv_usec, microsec_busywait);

#endif

	new_mask = tsai_atomic_and_return(~(1 << cpu), &ipi->expected_core_reply);
	engine_pending_smp = atomic_read(&pr->engine_pending_smp);
	if (!new_mask && engine_pending_smp) {
		atomic_set(&pr->engine_pending_smp, 0);
		engine_restart = 1;
	}
	TSAI_PROFILER_LOG("tsai_spy_smp_profiling from cpu %d cur pid %d tgid %d %s ptgid %d expected_core_reply %08x pending_smp %u restrt %d @%d\n",
			cpu, current->pid, current->tgid, current->comm, pr->profiling_task->tgid, new_mask, engine_pending_smp, engine_restart, __LINE__);
	if (engine_restart)
		tsai_profile_thread_fn_wake(pr, NULL);
}

/*
 * only make a currently not on cpu task not to be switched onto a cpu core
 * return:
 * 0: this task is now frozen and can be parsed for callstack
 * -1: done nothing
 * */
TSAI_STATIC int tsai_spy_freeze_task(struct TSAI_PROFILER_DATA* pr, struct tsai_profiling_task_node* tnode) {
	struct task_struct* t = tnode->task;
	int old_state;
	if (pr->opt_task_on_rq_backup) {
		int on_core;

		if (t->state == TASK_WAKING) {/* if this task is in middle of waking, wait for it to complete */
			/* if it takes too long, give up!*/
			struct timespec ts1;
			getrawmonotonic(&ts1);
			while (!t->on_rq) {
				struct timespec ts2;
				int delta;
				cpu_relax();
				getrawmonotonic(&ts2);
				delta = tsai_diff_microsec64(&ts1, &ts2);

				if (delta > 1000) { /* taking too long*/
					//BKPT;
					TSAI_PROFILER_LOG("WARNING:tsai_spy_freeze_task no action was taken, task waking take too long @%d \n", on_core, __LINE__);
					atomic_set(&tnode->save_state_flag, 0);
					tnode->saved_on_rq = 0;
					return -1;
				}
			}
		}

		if (tsai_task_prevent_run(t, 0, &tnode->save_state_flag, &old_state, &tnode->saved_on_rq, &on_core)==0) {

		}
		else {
			TSAI_PROFILER_LOG("tsai_spy_freeze_task no action was taken, task already on cpu %d @%d \n", on_core, __LINE__);
			atomic_set(&tnode->save_state_flag, 0);
			tnode->saved_on_rq = 0;
			pr->task_nonsleeping_cnt++;
			return -1;
		}
	}

	tnode->saved_state = old_state;
	//atomic_set(&tnode->save_state_flag , 1);
	if (pr->opt_task_state_trace) {
		t->state = __TASK_TRACED; /* should prevent task being woken up */
	}

	pr->task_freeze_cnt++;
	TSAI_PROFILER_LOG("FREEZE task #%d %08x(%d) %s s_st %d s_onrq %d on_cpu %d on_rq %d @%d\n",
			pr->task_freeze_cnt, t, t->pid, t->comm, tnode->saved_state, tnode->saved_on_rq ,t->on_cpu, t->on_rq, __LINE__);

	return 0;
}

TSAI_STATIC void tsai_spy_unfreeze_task(struct TSAI_PROFILER_DATA* pr, struct tsai_profiling_task_node* tnode) {
	struct task_struct* t = tnode->task;
	unsigned long irqflags;
	/* this function is competing against tsai_probe_sched_wakeup() tracepoint, both need to maintain saved state,
	 * tracepoint should take higher precedence because it holds system rq lock
	 * so if tsai_probe_sched_wakeup() is currently owns the rq lock, do a busy waiting until it frees
	 *  */
	void* rq;
	unsigned long rqflags;
	rq = tsai_task_rq_lock(tnode->task, &rqflags);

	spin_lock_irqsave(&tnode->save_state_lock, irqflags);
	if (atomic_read(&tnode->save_state_flag)) {
		if (pr->opt_task_state_trace) {
			if (tnode->task->state != __TASK_TRACED) {
				BKPT;
				tnode->prev_saved_state = tnode->task->state;
			}
			else {
			}
		}

		if (pr->opt_task_on_rq_backup) {

			TSAI_PROFILER_LOG("UNFREEZE task %d s_on_rq %08x s_stated %08x @%d \n", t->pid,
					tnode->saved_on_rq, tnode->saved_state,	__LINE__);
			tsai_task_restore_run(t, 1, &tnode->save_state_flag, &tnode->saved_state, &tnode->saved_on_rq );

		}
		tnode->prev_saved_state = tnode->saved_state;
		tnode->task->state = tnode->saved_state;
		TSAI_PROFILER_LOG("UNFREEZE task %p %d on_rq %d st %d @%d \n", t, t->pid,
				t->on_rq, t->state,	__LINE__);
	}
	else {
		TSAI_PROFILER_LOG("UNFREEZE save_state_flag=0 task %d s_on_rq %08x s_stated %08x @%d \n", t->pid,
				tnode->saved_on_rq, tnode->saved_state,	__LINE__);
		BKPT; /* should be an error situation! */
	}
	spin_unlock_irqrestore(&tnode->save_state_lock, irqflags);
	tsai_task_rq_unlock(rq, tnode->task, &rqflags);
}

/* return:
 * 1: caller should restart the timer to keep engine running
 * 0: all sleep and caller no need to restart the timer
 * */
TSAI_STATIC unsigned int tsai_spy_capture_sample(struct TSAI_PROFILER_DATA* pr)
{
	struct thread_info* ti = current_thread_info();
	int cpu = smp_processor_id();
	int max_cpu = setup_max_cpus;
	int i;
	int n;
	int task_about_to_wake_up = 0; /* if during parsing sleeping callstack, the task have been scheduled to be on, then increase this */
	struct tsai_spy_profiling_ipi_info* ipi;
	unsigned int unexpected_stop = 0;
	struct task_struct* cur_task = ti->task;
	unsigned int restart_timer = 0;
	unsigned int ret = 0;

#if 0 && defined(DEBUG) /* detect thread info corruption!, don't compare flags because it change a lot */
	unsigned int ti_preempt_count;
	unsigned int ti_addr_limit;
	unsigned int ti_cpu;

	ti_preempt_count = ti->preempt_count;
	ti_addr_limit = ti->addr_limit;
	ti_cpu = ti->cpu;
	if (ti_cpu != cpu) {
		BKPT;
	}
	tsai_install_watchpoint((u64)(u32)&ti->cpu, 2, "ti_flags");
#endif
	pr->task_freeze_cnt = 0;
	pr->task_nonsleeping_cnt = 0;

	{
		/* Match clock_gettime(CLOCK_MONOTONIC_RAW, &ts) from userspace */
		getrawmonotonic(&pr->timestamp);
		//u64 = timespec_to_ns(&ts);
		//do_gettimeofday(&pr->timestamp);
	}
	ipi = &pr->ipi;
	ipi->shed_mask_core = 0;

#ifdef DEBUG
	TSAI_PROFILER_LOG("====PROFILER capture cnt %d ts %d.%09d mask %08x cur task %p @%d\n",
			pr->interrupts_cnt, pr->timestamp.tv_sec, pr->timestamp.tv_nsec, pr->sche_mask,
			cur_task, __LINE__);
/*	TSAI_PROFILER_LOG("====PROFILER TIMER_INTERRUPT %d ts %d.%d mask %08x ti task %p precnt %d ad %08x cpu %d\n",
			pr->interrupts_cnt, pr->timestamp.tv_sec, pr->timestamp.tv_nsec, pr->sche_mask,
			cur_task, ti_preempt_count, ti_addr_limit, ti_cpu);
*/
	if (pr->sche_mask==0) {

	}
	if (0 && pr->interrupts_cnt > 1000000) {
		BKPT;
	}
#endif

	if (!pr->sche_mask) {
		goto EarlyOut;
	}

	atomic_set(&ipi->expected_core_reply, 0);
	/* walk through all threads and freeze currently sleep threads */
	{
		struct task_struct* t;
		i = 0;

		for (t = pr->profiling_task; t ;)
		{
			struct tsai_profiling_task_node* tnode = tsai_spy_profiling_find_task(pr,t->pid);
			if (!tnode) { /* new thread detected */
				tnode = tsai_spy_profiling_create_tnode(pr, t->pid, t);
			}
#ifdef DEBUG
			tsai_debug_task_nodes[i++] = tnode;
#endif
			tnode->handled_in_this_interrupt = 0;
			tnode->new_sample = 0;
			atomic_set(&tnode->save_state_flag , 0);

			if (t->state ) {
				/* sleep or other non-running state */
				if ( (t->state == tnode->prev_saved_state)) {
					unsigned int mask = 1 << (tsai_24bit_value(t->pid));
					if ((mask & pr->sche_mask)) {
						tsai_spy_freeze_task(pr, tnode);
					}
				}
				else {
					tsai_spy_freeze_task(pr, tnode);
				}
			}
			else { /* this task is in running state, but if it's going to sleep, then we can process it */
				if (!t->on_cpu) {
					/* it might be scheduled on a core very soon, take extra care for that situation*/

					TSAI_PROFILER_LOG("non-sleeping task %08x(%d) %s state %d on_cpu %d TO be sched away @%d\n",
						t, t->pid, t->comm, t->state, t->on_cpu ,__LINE__);
					tsai_spy_freeze_task(pr, tnode);

				}
				else {
					/* currently running, let IPI deal with them*/
				}
			}

			if (pr->user_request.f_current_thread_only==0)
				t = container_of(t->thread_group.next, struct task_struct, thread_group);
			if (t == pr->profiling_task) {
				t = 0;
			}
		}
	}

	/* when doing smp call, smp_call_function_many is not allowed when interrupt is disabled,
	 * we need to use int smp_call_function_single_async(int cpu, struct call_single_data *csd) instead */
	/* no need to wait */
	for (i=0; i<max_cpu; i++) {
		if (i != cpu) {
			unsigned int cpu_core_mask = 1 <<(24+i);
			if (pr->sche_mask & (cpu_core_mask) ) {
				unsigned int new_mask;
				pr->csd_stack[i].flags = 0;
				pr->csd_stack[i].func = tsai_spy_smp_profiling;
				pr->csd_stack[i].info = ipi;

				new_mask = tsai_atomic_or_return(1 << i, &ipi->expected_core_reply);
				TSAI_PROFILER_LOG("Expecting cpu core %d (prm %08x corem %08x)to take sample expected_core_reply %08x\n",
						i, pr->sche_mask, cpu_core_mask, new_mask );
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
				smp_call_function_single_async(i, &pr->csd_stack[i]);
#else
				BKPT;
#endif
			}
		}
	}

	/* deal with the currently sleep threads */
	{
		struct tsai_profiling_task_node* tnode;
		struct tsai_profiling_task_node* tfirst = (struct tsai_profiling_task_node*) rb_first(&pr->profiling_taskroot);
		struct tsai_profiling_task_node* tlast = (struct tsai_profiling_task_node*) rb_last(&pr->profiling_taskroot);

		/* switch mmu to target process*/
		struct mm_struct* saved_mm;
		int save_mm = 0;

		if (pr->task_freeze_cnt && (cur_task->mm != pr->profiling_task->mm) ) {
			//struct mm_struct* mm;

#ifdef DEBUG
			if (cur_task == pr->profiling_task) {
				BKPT;
			}
#endif
#if 1
			tsai_backup_mm(&save_mm, &saved_mm, pr->profiling_task->active_mm);
#else
			saved_mm = cur_task->active_mm;
			atomic_inc(&saved_mm->mm_count);
			mm = tsai_get_task_mm_no_irq(pr->profiling_task);
			use_mm(mm);
			save_mm = 1;
#endif

			TSAI_PROFILER_LOG("tsai_spy_capture_sample saved_mm %08x @%d\n", saved_mm, __LINE__);

		}
		ASSERT(tfirst);
		for (tnode=tfirst; tnode ; tnode = (struct tsai_profiling_task_node*) rb_next(&tnode->rb)) {
			if (tnode->handled_in_this_interrupt ) {
				continue;
			}
			if (atomic_read(&tnode->save_state_flag) ) {
				/* if this task is already on a core, then do nothing and let the IPI handle it */
				if (tnode->task->on_cpu) {
					atomic_set(&tnode->save_state_flag, 0);
					TSAI_PROFILER_LOG("Task pid %d already running on CPU no longer sleeping @%d\n",
							tnode->task->pid, __LINE__);
					continue;
				}
				else {
					TSAI_PROFILER_LOG("Task pid %d not on CPU yet task->on_cpu %d @%d\n",
							tnode->task->pid, tnode->task->on_cpu, __LINE__);
				}
				/* double check it is in frozen state */
				if (pr->opt_task_state_trace) {
					if (tnode->task->state != __TASK_TRACED) {
						TSAI_PROFILER_LOG("Task state %d for frozen task, indicating overwriting @%d\n",
								tnode->task->state, __LINE__);
						tnode->saved_state = tnode->task->state;
						tnode->task->state = __TASK_TRACED;
					}
				}

				n = tsai_spy_parse_stack(pr,tnode->task, NULL, tnode);

				if (tnode->sched_away) {
					TSAI_PROFILER_LOG("Task %d %s should be sleeping state %d @%d\n",
						tnode->task->pid, tnode->task->comm, tnode->task->state, __LINE__);
				}
				else {
					task_about_to_wake_up++;
					TSAI_PROFILER_LOG("Task %d %s is going to wake up state %d @%d\n",
						tnode->task->pid, tnode->task->comm, tnode->task->state, __LINE__);
				}
				tsai_spy_unfreeze_task(pr, tnode);

				if (n < 0) {
					unexpected_stop = 1;
					pr->profiler_work.task = tnode->task;
					break;
				}

			}

			if (tnode == tlast)
				break;
		}

		/* deal with sleeping task first,
		 * so that the one which was labelled running but was not on a actual core would have more grace period to wake up
		 * put it here so it doesn't have to switch MMU two times
		 * */
		tsai_spy_smp_profiling(ipi);

#if 1
		tsai_restore_mm(&save_mm, &saved_mm);
#else
		if (save_mm) {
			unuse_mm(pr->profiling_task->mm);
			mmput(pr->profiling_task->mm);

			if (saved_mm) {
				atomic_dec(&saved_mm->mm_count);
				use_mm(saved_mm);
			}
		}
#endif
	}

	/* busy wait until all CPU cores have responded */
	{
		if (atomic_read(&ipi->expected_core_reply)) {
			atomic_set(&pr->engine_pending_smp, 1);
			atomic_set(&pr->timer_status, 1);
			restart_timer = 0;
		}
	}

EarlyOut:
	pr->interrupts_cnt++;

	if (unexpected_stop) {
		/* put a deferred work to use kdebugd to try again */
		pr->profiler_work.cmd = TP_UNSPECIFIED;
		INIT_WORK(&pr->profiler_work.work, tsai_handle_profiler_work);
		schedule_work(&pr->profiler_work.work);
		atomic_set(&pr->profiler_work_pending, 1);

		ret = 0;
	}
	else {
		struct timespec tv_end;
		int microsec;

		pr->sche_mask = ipi->shed_mask_core;
		if (atomic_read(&pr->engine_pending_smp)==0 &&
				(pr->sche_mask || pr->task_nonsleeping_cnt || task_about_to_wake_up ))
		{
			restart_timer = 1;
		}
		else {
			//tsai_spy_profiler_write_trace_marker(pr, M_SLEP, &pr->timestamp, 0);
		}

		getrawmonotonic(&tv_end);
		microsec = tsai_diff_microsec64(&pr->timestamp, &tv_end);
		TSAI_PROFILER_LOG(" Capture Sample %d takes %d us nonsleeping_cnt %d mask %08x engine_looping=%d @%d\n",
			pr->interrupts_cnt, microsec, pr->task_nonsleeping_cnt, pr->sche_mask, restart_timer, __LINE__);

		ret = restart_timer ? 1: 0;
	}

	if (pr->user_request.max_duration_ms) {
		int msec;
		int microsec = tsai_diff_microsec64(&pr->timestamp_trace_begin, &pr->timestamp);
		msec = microsec >> 10;
		TSAI_PROFILER_LOG(" Elipsed time %d ms @%d\n", msec, __LINE__);
		if (msec >= pr->user_request.max_duration_ms) {
			struct TSAI_PROFILER_WORK* pw = kzalloc(sizeof(struct TSAI_PROFILER_WORK), GFP_KERNEL|GFP_ATOMIC);
			pw->pr = pr;
			pw->cmd = TP_AUTO_STOP;
			INIT_WORK(&pw->work, tsai_handle_profiler_work);
			schedule_work(&pw->work);
		}
	}

#if 0 && defined(DEBUG)
	if ( (cur_task != ti->task) ||
			(ti_preempt_count != ti->preempt_count) ||
			(ti_addr_limit != ti->addr_limit) ||
			(ti_cpu != ti->cpu) ||
			(ti_cpu != cpu))
	{
		BKPT;
	}
	tsai_remove_watchpoint((u64)(u32)&ti->cpu);
#endif
	return ret;
}

TSAI_STATIC enum hrtimer_restart tsai_spy_hrtimer_notify(struct hrtimer *hrtimer)
{
	enum hrtimer_restart ret = HRTIMER_NORESTART;
	struct TSAI_PROFILER_DATA* pr;
	pr = container_of(hrtimer, struct TSAI_PROFILER_DATA, profiling_timer);

	if (tsai_spy_capture_sample(pr)) {
		pr->profiling_hrtimer_expire = ktime_add(pr->profiling_timer.base->get_time(), pr->profiling_interval);
		hrtimer_forward(hrtimer, pr->profiling_hrtimer_expire, pr->profiling_interval);
	
		ret = HRTIMER_RESTART;
	}

	return ret; /* return HRTIMER_NORESTART if not continuing */
}

TSAI_STATIC int tsai_wait_atomic_t(atomic_t *a)
{
	schedule();
	return 0;
}



TSAI_STATIC void tsai_spy_profiler_flush_text_trace(void* cb_data, void* ptr, int len) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)cb_data;
	if (pr->filetrace)
		__vfs_write(pr->filetrace, ptr, len, &pr->filetrace->f_pos);
#else
	BKPT;
#endif
}

TSAI_STATIC void tsai_spy_profiler_flush_unwind_log(void* cb_data, void* ptr, int len) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct TSAI_PROFILER_DATA* pr = (struct TSAI_PROFILER_DATA*)cb_data;
	if (pr->filetrace) {
		if (pr->fileunwind) {
			//BKPT;
			__vfs_write(pr->fileunwind, ptr, len, &pr->fileunwind->f_pos);
		}
	}
#else
	BKPT;
#endif
}

struct tsai_spy_mem_log* tsai_unwind_log; /* instance in tsai_callstack_arm.c */

TSAI_STATIC void tsai_spy_profiler_defer_free(struct TSAI_PROFILER_DATA* pr) {
	pr->profiling_task = 0;

	if (pr->worker_thread) {
		tsai_profile_thread_fn_wake(pr, NULL);
		kthread_stop(pr->worker_thread);
	}

	tsai_spy_mem_log_free(&pr->mem_log);
	tsai_spy_mem_log_free(&pr->unwind_log);
	tsai_unwind_log = 0;


	if (pr->profiling_trace_buf) {
		vfree(pr->profiling_trace_buf);
		pr->profiling_trace_buf = 0;
		pr->profiling_trace_buf_cur_r = 0;
		pr->profiling_trace_buf_cur_w = 0;
		pr->profiling_trace_buf = 0;
	}

	if (pr->filetrace) {
		filp_close(pr->filetrace, (fl_owner_t)(NATIVE_UINT)current->pid);
		pr->filetrace = 0;
	}
	if (pr->fileunwind) {
		filp_close(pr->fileunwind, (fl_owner_t)(NATIVE_UINT)current->pid);
		pr->fileunwind = 0;
	}
}

int tsai_spy_profiler(struct TSpy_Profiler* p) {
	int ret = 0;
#if	LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	struct TSAI_PROFILER_DATA* pr = &tsai_spy_data.pr;
#ifdef DEBUG
	if (!tsai_spy_data.debug_flag) {
		return ret;
	}
#endif
	tsai_callstack_preload_symbol();

	if (p->on_off) {
		pr->opt_task_state_trace = 0;
		pr->opt_task_on_rq_backup = 1;

		if (!pr->profiling_task) {
			//int slen;
			pr->user_request = *p;
			pr->user_request.output_file = 0;

			if (!pr->user_request.timer_frequency)
				pr->user_request.timer_frequency = 5000; /* default 5000 samples per second */

			tsai_spy_mem_log_init(&pr->mem_log, "MEMLOG", 512*1024, tsai_spy_profiler_flush_text_trace, pr);
			tsai_spy_mem_log_init(&pr->unwind_log, "UNWIND", 512*1024, tsai_spy_profiler_flush_unwind_log, pr);
			tsai_unwind_log = &pr->unwind_log;

			pr->profiling_task = p->pid ? pid_task(find_vpid(p->pid), PIDTYPE_PID): current;
			pr->profiling_taskroot.rb_node = NULL;
			INIT_LIST_HEAD(&pr->list_deferred_task);

			/* open a trace binary file */
			{
				const char* filename = p->output_file;
				char tmp_filename[256] = {0} ;
				if (!filename) {
					sprintf(tmp_filename, "/tmp/tsai_%d.txt", current->pid);
					filename = tmp_filename;
				}
				pr->filetrace = filp_open(filename, O_RDWR|O_CREAT|O_TRUNC|O_LARGEFILE, S_IRWXU|S_IRWXG|S_IRWXO);
			}
			if (IS_ERR(pr->filetrace)) {
				BKPT;
				pr->filetrace = 0;
			}
			pr->fileunwind = filp_open("/tmp/tsai_unwind_log.txt", O_RDWR|O_CREAT|O_TRUNC|O_LARGEFILE, S_IRWXU|S_IRWXG|S_IRWXO);
			if (IS_ERR(pr->fileunwind)) {
				pr->fileunwind = 0;
			}

			pr->profiling_trace_buf_size = 512*1024;
			pr->profiling_trace_buf = vmalloc(pr->profiling_trace_buf_size);
			pr->profiling_trace_buf_cur_r = 0;
			pr->profiling_trace_buf_cur_w = 0;
			spin_lock_init(&pr->profiling_trace_buf_lock);
			pr->profiling_trace_event_lost = 0;

			pr->seqno_lastread = 0;

			/* go through all threads of this process and allocate a node for each of them */
			{
				struct task_struct* t;
				t = pr->profiling_task;

				do {
					struct tsai_profiling_task_node* tnode;
					tnode = tsai_spy_profiling_create_tnode(pr, t->pid, t);

					if (pr->user_request.f_current_thread_only==0)
						t = container_of(t->thread_group.next, struct task_struct, thread_group);
				} while ( (t != pr->profiling_task) );
			}

			atomic_set(&pr->worker_go, 0);
			pr->worker_thread = kthread_run(tsai_profile_thread_fn, (void*)pr, "TSAI_PROFILE");
			pr->profiler_collecting = 1;
			wake_up_process(pr->worker_thread);

			tsai_vma_mgr_init(&pr->vma_mgr);

			hrtimer_init(&pr->profiling_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);

			pr->sche_mask = 0xFFFFFFFF; /* the first interrupt, always check all tasks */
			pr->profiling_interval = ns_to_ktime(1000000000UL / (pr->user_request.timer_frequency) ); /* for now aiming at 10us interval */
			pr->slower_interval = ns_to_ktime(1000000000); /* slower interval, 1000ms */
			pr->profiling_hrtimer_expire = ktime_add(pr->profiling_timer.base->get_time(), pr->profiling_interval);
			pr->profiling_timer.function = tsai_spy_hrtimer_notify;

			spin_lock_init(&pr->profiler_work.lock);

			{
				getrawmonotonic(&pr->timestamp_trace_begin);

				pr->timestamp_lastwrite = pr->timestamp_trace_begin;
				pr->timestamp_lastread = pr->timestamp_lastwrite;
				tsai_spy_profiler_write_trace_marker(pr, M_BEGN, &pr->timestamp_trace_begin, 0);
			}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
			tracepoint_probe_register(tsai_spy_data.tracepoint_sched, tsai_probe_sched_switch, pr);
			tracepoint_probe_register(tsai_spy_data.tracepoint_sched_wakeup, tsai_probe_sched_wakeup, pr);
			tracepoint_probe_register(tsai_spy_data.tracepoint_sched_try_wakeup, tsai_probe_sched_try_wakeup, pr);
			tracepoint_probe_register(tsai_spy_data.tracepoint_irq_entry, tsai_probe_irq_entry, pr);
			tracepoint_probe_register(tsai_spy_data.tracepoint_irq_exit, tsai_probe_irq_exit, pr);
#else
			BKPT;
#endif
			atomic_set(&pr->timer_status, 1);

			if (pr->opt_engine_timer)
				hrtimer_start(&pr->profiling_timer, pr->profiling_hrtimer_expire, HRTIMER_MODE_ABS_PINNED);
		}
	}
	else {
		if (pr->profiling_task && pr->profiler_collecting) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
			tracepoint_probe_unregister(tsai_spy_data.tracepoint_sched, tsai_probe_sched_switch, pr);
			tracepoint_probe_unregister(tsai_spy_data.tracepoint_sched_wakeup, tsai_probe_sched_wakeup, pr);
			tracepoint_probe_unregister(tsai_spy_data.tracepoint_sched_try_wakeup, tsai_probe_sched_try_wakeup, pr);
			tracepoint_probe_unregister(tsai_spy_data.tracepoint_irq_entry, tsai_probe_irq_entry, pr);
			tracepoint_probe_unregister(tsai_spy_data.tracepoint_irq_exit, tsai_probe_irq_exit, pr);
#else
			BKPT;
#endif

			if (pr->opt_engine_timer)
				hrtimer_cancel(&pr->profiling_timer);

			pr->profiler_collecting = 0;
			TSAI_PROFILER_LOG("tsai_spy_profiler STOP TRACING waking worker thread  @%d\n", __LINE__);
			tsai_profile_thread_fn_wake(pr, NULL);
			kthread_stop(pr->worker_thread); /* wait for it to stop and get exit code*/
			pr->worker_thread = NULL;
			{
				struct timespec timestamp;
				getrawmonotonic(&timestamp);
				tsai_spy_profiler_write_trace_marker(pr, 1, &timestamp, 0);
				TSAI_PROFILER_LOG("tsai_spy_profiler STOP TRACING ts %d.%09d  @%d\n", timestamp.tv_sec, timestamp.tv_nsec, __LINE__);
			}
			/* here it is requesting to stop profiling, but there are still pending trace buffer to be processed,
			 * the actual freeing will happen in tsai_spy_profiler_defer_free() once all pending trace buffer is processed.
			 * */
		}
	}
#endif
	return ret;
}

struct TSAI_BACKTRACE {
	struct TSAI_VMA_MGR* vma_mgr;
	struct mm_struct *tsk_mm;
	void** buffer;
	unsigned int start_point_pending;
	const char** terminating_libs;
	const char** allowed_libs;
	int count;
	int filled; /* how many back traces wrtitten to buffer as of now */
};

TSAI_STATIC int tsai_spy_backtreace_cb(struct TSAI_USER_TRACE_SIMPLE* p) {
	struct TSAI_BACKTRACE* bt = (struct TSAI_BACKTRACE*)p->data;

	if (bt->start_point_pending) {
		if ((bt->start_point_pending & ~1) == (p->pc & ~1))
			bt->start_point_pending = 0;
	}
	else {
		//bt->buffer[bt->filled] = (void*) p->pc;
		tsai_force_write_user_address_size(bt->tsk_mm, (unsigned int)(NATIVE_UINT)&bt->buffer[bt->filled], &p->pc, sizeof(p->pc));
		bt->filled++;

		if (bt->terminating_libs) {
			const char** plib;
			struct vm_area_struct* vma;

			vma = find_vma(bt->tsk_mm, p->pc);
			if (vma && vma->vm_file) {
				const char* plib_str;
				//char tmp[8];
				plib_str = (const char*)(NATIVE_UINT) tsai_force_read_user_address(
						bt->tsk_mm, (unsigned int)(NATIVE_UINT)bt->terminating_libs);
				tsai_force_read_user_address(bt->tsk_mm, (unsigned int)(NATIVE_UINT)plib_str);
				for(plib=bt->terminating_libs; *plib; plib++) {
					if (strcmp(vma->vm_file->f_path.dentry->d_iname, *plib)==0) {
						return 1;
					}
				}
			}
		}
		if (bt->allowed_libs) {
			const char** plib;
			struct vm_area_struct* vma;

			vma = find_vma(bt->tsk_mm, p->pc);
			if (vma && vma->vm_file) {
				const char* plib_str;
				//char tmp[8];
				plib_str = (const char*)(NATIVE_UINT) tsai_force_read_user_address(bt->tsk_mm, (unsigned int)(NATIVE_UINT)bt->allowed_libs);
				tsai_force_read_user_address(bt->tsk_mm, (unsigned int)(NATIVE_UINT)plib_str);
				for(plib=bt->allowed_libs; *plib; plib++) {
					if (strcmp(vma->vm_file->f_path.dentry->d_iname, *plib)) {
						return 1;
					}
				}
			}
		}
		if (bt->filled >= bt->count)
			return 1;
	}
	return 0;
}

/* return how many levels are unwinded */
TSAI_STATIC int tsai_spy_backtrace(struct TSpy_Backtrace* pbt) {
#ifdef __aarch64__
	BKPT;
	return 0;
#else
	struct TSAI_PARSE_USER_CALLSTACK param;
	struct TSAI_BACKTRACE bt;

	int ret = 0;
	int n;
	int i;
	struct pt_regs* reg_user;
	struct tsai_intermediate_regs kregs;
	struct ts_prof_proc_node* proc_node;
#ifdef DEBUG
	if (!tsai_spy_data.debug_flag) {
		return ret;
	}
#endif
	proc_node = ts_get_proc_node(current->tgid);

	bt.buffer = pbt->buffer;
	bt.count = pbt->count;
	bt.filled = 0;
	bt.vma_mgr = proc_node->vma_mgr;
	bt.tsk_mm = current->mm;
	bt.start_point_pending = pbt->start_point;
	bt.allowed_libs = pbt->allowed_libs;
	bt.terminating_libs = pbt->terminating_libs;

	if (!tsai_spy_data.log_msg) {
		tsai_spy_data.log_msg = vmalloc(512*1024);
		tsai_spy_data.log_msg_max = 512*1024;
		tsai_spy_data.log_msg_cur = 0;
	}

	if (pbt->regs) {
		for (i=0; i<16; i++)
			kregs.R[i] = pbt->regs[i];

		kregs.frame_is_thumb = (pbt->regs[16] & 0x20) >> 5;
	}
	else {
		reg_user = task_pt_regs(current);
		for (i=0; i<16; i++)
			kregs.R[i] = reg_user-> uregs[i];

		kregs.frame_is_thumb = (reg_user-> uregs[16] & 0x20) >> 5;
	}
	/* if the interrupt directly happen on top of user-mode, then cannot test whether it's Thumb by examine PC & 0x01
	 * in this case examine SPSR register instead
	 *
	 * */

	kregs.sp_end = current->user_ssp;

	kregs.on_pabort = 0;
	kregs.interrupt_on_user = 0;
	kregs.voluntary = 1;

	memset(&param, 0, sizeof(param));
	param.tsk_mm = bt.tsk_mm;
	param.vma_mgr = bt.vma_mgr;
	param.regs = &kregs;
	param.max_depth = bt.count;
	param.user_trace_simple = tsai_spy_backtreace_cb;
	param.user_recover = 0;
	param.data = &bt;
	ret = tsai_parse_user_callstack(&param, 0);

	return bt.filled;
#endif
}

int tsai_spy_profiler_snapshot(pid_t pid) {
#ifdef __aarch64__
	BKPT;
	return 0;
#else
	struct TSAI_PARSE_USER_CALLSTACK param;
	struct TSAI_BACKTRACE bt;
	struct task_struct* task;
	unsigned int* buffer;

	int ret = 0;
	int n;
	int i;
	struct pt_regs* reg_user;
	struct tsai_intermediate_regs kregs;
	struct ts_prof_proc_node* proc_node;
#ifdef DEBUG
	if (!tsai_spy_data.debug_flag) {
		return ret;
	}
#endif

	if (pid)
		task = pid_task(find_vpid(pid), PIDTYPE_PID);
	else
		task = current;
	proc_node = ts_get_proc_node(task->tgid);
	buffer = kzalloc(4*128, GFP_KERNEL);

	bt.buffer = (void**)buffer;
	bt.count = 128;
	bt.filled = 0;
	bt.vma_mgr = proc_node->vma_mgr;
	bt.tsk_mm = task->mm;
	bt.start_point_pending = 0;
	bt.allowed_libs = 0;
	bt.terminating_libs = 0;

	if (!tsai_spy_data.log_msg) {
		tsai_spy_data.log_msg = vmalloc(512*1024);
		tsai_spy_data.log_msg_max = 512*1024;
		tsai_spy_data.log_msg_cur = 0;
	}


	{
		reg_user = task_pt_regs(current);
		for (i=0; i<16; i++)
			kregs.R[i] = reg_user-> uregs[i];

		kregs.frame_is_thumb = (reg_user-> uregs[16] & 0x20) >> 5;
	}
	/* if the interrupt directly happen on top of user-mode, then cannot test whether it's Thumb by examine PC & 0x01
	 * in this case examine SPSR register instead
	 *
	 * */

	kregs.sp_end = task->user_ssp;

	kregs.on_pabort = 0;
	kregs.interrupt_on_user = 0;
	kregs.voluntary = 0;

	memset(&param, 0, sizeof(param));
	param.tsk_mm = bt.tsk_mm;
	param.vma_mgr = bt.vma_mgr;
	param.regs = &kregs;
	param.max_depth = bt.count;
	param.user_trace_simple = tsai_spy_backtreace_cb;
	param.user_recover = 0;
	param.data = &bt;
	ret = tsai_parse_user_callstack(&param, 0);

	/* get the symbol information and print out */
	{
		int i;
		//BKPT;
		for (i=0; i< bt.filled; i++) {
			unsigned int pc = buffer[i];
			tsai_callstack_print_bin_symbol(i, bt.vma_mgr, bt.tsk_mm, (void*)pc);
		}

		tsai_callstack_print_bin_symbol_free();
	}

	kfree(buffer);
	return ret;
#endif
}


/* ======================================================================================== */
#ifdef CONFIG_KDEBUGD
#include <kdebugd.h>

#define KUBT_TRACE_COUNT	32
#define KDEBUGD_PRINT_ELF   "#%d  0x%08lx in %s () from %s\n"
#define KDEBUGD_PRINT_DWARF "#%d  0x%08lx in %s () at %s:%d\n"
#define KDUBGD_ONLY_ADDR	"#%d  0x%08lx in ??\n"
#define KDEBUGD_MAIN_TITLE	"Pid: %d, Tid: %d, comm: %s[%d] exec_start[%u.%09u]\n"

#define KERNEL_BT_BUF_SIZE	300

void* g_bt_frame_buffer;
int tsai_print_user_callstack_mute = 0;
#endif

/*  */
unsigned long tsai_print_user_callstack(struct task_struct* thetask, struct file* fout) {
#ifdef CONFIG_KDEBUGD
	struct kdbg_bt_buffer kubt_buffer;
	int tmp_count = 0;
	char *kernel_bt_buf = NULL;
	char* buf[64]; //64 levels of user side call stack
	int i;
	if (tsai_print_user_callstack_mute) {
		return 0;
	}

	kubt_buffer.max_entries = KUBT_TRACE_COUNT;
	kubt_buffer.nr_entries = 0;

	if (!g_bt_frame_buffer) {
		i = sizeof(struct bt_frame) * KUBT_TRACE_COUNT;
		g_bt_frame_buffer = kzalloc(i, GFP_NOFS);
	}

	kubt_buffer.symbol = (struct bt_frame *)g_bt_frame_buffer;
	if (kubt_buffer.symbol) {
		int call_depth = 0;
		__s32 sec = 0;
		__s32 nsec = 0;
		u64 ts;
		__kernel_size_t alloc_size = 0;
		kernel_bt_buf = kzalloc(KERNEL_BT_BUF_SIZE, GFP_NOFS);
		if (kernel_bt_buf == NULL) {
			kfree(kubt_buffer.symbol);
			goto Leave;
		}
		show_user_backtrace_pid((pid_t)thetask->pid, 0, 0, &kubt_buffer);


		if (kubt_buffer.nr_entries > 0) {
			ts = kubt_buffer.exec_start;
			nsec = do_div(ts, NSEC_PER_SEC);
			sec = ts;

			snprintf(kernel_bt_buf, KERNEL_BT_BUF_SIZE, KDEBUGD_MAIN_TITLE,
			kubt_buffer.pid, kubt_buffer.tid, kubt_buffer.comm,
			kubt_buffer.cpu_number, sec, nsec);

			alloc_size = strlen(kernel_bt_buf) + 1;
			buf[tmp_count] = kzalloc(alloc_size, GFP_NOFS);
			if (buf[tmp_count]) {
				snprintf(buf[tmp_count], alloc_size, "%s", kernel_bt_buf);
				tmp_count++;
			}
		}

		for (i = 0 ; i < kubt_buffer.nr_entries ; i++) {
			switch (kubt_buffer.symbol[i].type) {
			case KDEBUGD_BACKTRACE_ONLY_ADDR:
				snprintf(kernel_bt_buf, KERNEL_BT_BUF_SIZE, KDUBGD_ONLY_ADDR, call_depth,
				kubt_buffer.symbol[i].addr);
				call_depth++;
				break;
#ifdef CONFIG_ELF_MODULE
			case KDEBUGD_BACKTRACE_ELF:
				snprintf(kernel_bt_buf, KERNEL_BT_BUF_SIZE, KDEBUGD_PRINT_ELF,
				call_depth, kubt_buffer.symbol[i].addr,
				kubt_buffer.symbol[i].sym_name,
				kubt_buffer.symbol[i].lib_name);
				call_depth++;
				break;
#ifdef CONFIG_DWARF_MODULE
			case KDEBUGD_BACKTRACE_DWARF:
				snprintf(kernel_bt_buf, KERNEL_BT_BUF_SIZE, KDEBUGD_PRINT_DWARF,
				call_depth,	kubt_buffer.symbol[i].addr,
				kubt_buffer.symbol[i].sym_name,
				kubt_buffer.symbol[i].df_file_name,
				kubt_buffer.symbol[i].df_line_no);
				call_depth++;
				break;
#endif
#endif
			default:
				snprintf(kernel_bt_buf, KERNEL_BT_BUF_SIZE, "Error kubt Type");
			break;
			}
			alloc_size = strlen(kernel_bt_buf) + 1;
			buf[tmp_count] = kzalloc(alloc_size, GFP_NOFS);
			if (buf[tmp_count]) {
				snprintf(buf[tmp_count], alloc_size, "%s", kernel_bt_buf);
				tmp_count++;
			} else {
				printk(KERN_INFO "[smart-deadlock][kernel_bt_buf Memory Allocation failed]\n");
				break;
			}
		}

		//kfree(kubt_buffer.symbol);
		kfree(kernel_bt_buf);
	}
	if (fout) {
		mm_segment_t oldfs = get_fs();
		set_fs(KERNEL_DS);

		for (i=0; i<tmp_count; i++) {
			int len = strlen(buf[i]);
			vfs_write(fout, buf[i], len, &fout->f_pos);
//			__vfs_write(fout, buf[i], len, &fout->f_pos);
		}

		set_fs(oldfs);
	}
	else {
		for (i=0; i<tmp_count; i++) {
			int len = strlen(buf[i]);
			TSAI_PROFILER_LOG("%s", buf[i]);
		}
	}


	for (i=0; i<tmp_count; i++) {
		kfree(buf[i]);
	}

Leave:
#endif
	return 0;
}

EXPORT_SYMBOL(tsai_print_user_callstack);

#include <linux/irq.h>
struct tsai_spy_isr_data_struct {
	void* p;
} tsai_spy_isr_data ;

TSAI_STATIC irqreturn_t tsai_spy_isr(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

void tsai_spy_call_func(void *info) {
	int cpu = smp_processor_id();
	printk("tsai_spy_call_func from cpu %d \n", cpu);
}

TSAI_STATIC void tsai_spy_smp_call_func(void) {
	tsai_spy_walk_through_modules();
	smp_call_function_single(0,tsai_spy_call_func,0,1);
	smp_call_function_single(1,tsai_spy_call_func,0,1);
	smp_call_function_single(2,tsai_spy_call_func,0,1);
	smp_call_function_single(3,tsai_spy_call_func,0,1);
}


/* if this pid is a process, print all threads */
unsigned long tsai_print_process_callstack(struct task_struct* thetask, struct file* fout) {
	unsigned long ret;
	struct task_struct* threadtask = thetask;
	ret = tsai_print_user_callstack(thetask, fout);
	printk("tsai_print_process_callstack %u fpos %d \n", thetask->pid, (unsigned int)fout->f_pos);
	if ((unsigned int)fout->f_pos==0) {
		BKPT;
	}

	do {
		threadtask = container_of(threadtask->thread_group.next, struct task_struct, thread_group);
		if (threadtask == thetask) {
			break;
		}
		ret = tsai_print_user_callstack(threadtask, fout);
		printk("tsai_print_process_callstack %u fpos %d \n", thetask->pid, (unsigned int)fout->f_pos);
	} while (1);

	return ret;
}

int tsai_allow_ld_annotate;

TSAI_STATIC int tsai_spy_ld_annotate_relocate(struct TSpy_LD_Param* p) {
	if (tsai_allow_ld_annotate) {
		SRUK_ANNOTATE_CHANNEL_COLOR(201, ANNOTATE_RED, "ld relocate %s", p->filename);
	}

	return 0;
}

TSAI_STATIC int tsai_spy_ld_annotate_lookup(struct TSpy_LD_Param* p) {
	if (tsai_allow_ld_annotate) {
		SRUK_ANNOTATE_CHANNEL_COLOR(202, ANNOTATE_PURPLE, "ld lookup %s", p->symbolname);
	}
	return 0;
}


TSAI_STATIC long tsai_spy_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	long ret = 0;
	//struct file *filp;

	switch (cmd) {
	case TSpyCmd_Fd_To_Gem:
		{
		struct TSpy_Fd_To_Gem* a = (struct TSpy_Fd_To_Gem*) arg;
		a->gem_name = fd_to_gem_name(a->fd);
		}
		break;
	case TSpyCmd_Fd_To_File_Ptr:
		{
		struct TSpy_Fd_To_File_Ptr* a = (struct TSpy_Fd_To_File_Ptr*) arg;
		//struct file* p = fget(a->fd);

		a->fileptr = 0;
#if defined(__aarch64__)
		BKPT;
#else
		*(unsigned int*)(&a->fileptr) = *(unsigned int*)&p;
#endif
		}
		break;
	case TSpyCmd_LastGpuSchedulePid:
		{
			u32* a = (u32*) arg;
			*a = tsai_last_gpu_sched_pid();
		}
		break;
	case TSpyCmd_Annotate_prefetch:
		{
#ifdef __aarch64__
			BKPT; /* not implemented yet */
#else
			tsai_annotate_handle_prefetch = *(u32*)arg;
			tsai_annotate_handle_prefetch_task = current;
#endif
		}
		break;
	case TSpyCmd_Annotate_current_task:
		{
			struct TSpy_Task* ut = (struct TSpy_Task*)arg;
			tsai_annotate_current_task(ut);
		}
		break;
	case TSpyCmd_Install_Watchpoint:
		{
			struct TSpy_Watchpoint* w = (struct TSpy_Watchpoint*)arg;
			ret = tsai_spy_install_watch_point(w);
		}
		break;
	case TSpyCmd_Profiler:
		{
			struct TSpy_Profiler* p = (struct TSpy_Profiler*)arg;
			ret = tsai_spy_profiler(p);
		}
		break;
	case TSpyCmd_Callstack_Print:
		ret = tsai_spy_profiler_snapshot(0);
		//ret = tsai_print_user_callstack(current, 0);
		break;
	case TSpyCmd_Backtrace:
		{
		struct TSpy_Backtrace* a = (struct TSpy_Backtrace*) arg;
		a->ret = tsai_spy_backtrace(a);
		ret = 0;
		}
		break;
	case TSpyCmd_LD_Annotate_Relocate:
		ret = tsai_spy_ld_annotate_relocate((struct TSpy_LD_Param*)arg);
		break;
	case TSpyCmd_LD_Annotate_Lookup:
		ret = tsai_spy_ld_annotate_lookup((struct TSpy_LD_Param*)arg);
		break;
	case TSpyCmd_User_Var01:
		{
			u32* a = (u32*) arg;
			*a = tsai_spy_user_var_01;
		}
		break;
	case TSpyCmd_Printk:
		{
			struct TSpy_Printk* p = (struct TSpy_Printk*)arg;
			char kern_msg[256];
			char* user_msg;
			int res;
#ifdef __aarch64__
			user_msg = (char*)p->ptr_msg;
#else
			user_msg = (char*)(uint32_t)p->ptr_msg;
#endif
			if (p->msg_len > 0 && p->msg_len <256) {
				res = copy_from_user(kern_msg, user_msg, p->msg_len);
				kern_msg[p->msg_len] = 0;
				printk("TSAI usermode %s\n", kern_msg);
			}
		}
		break;
	default:
		printk("[%s:%d] Unknown ioctl cmd\n", __func__, __LINE__);
		return -EINVAL;
	}

	return ret;
}

atomic_t tsai_test;

ssize_t tsai_spy_write(struct file *f, char const __user *buf, size_t count_orig, loff_t *offset)
{
	int res;
	char scmd[64];
	char sarg[128];
	const char* psarg = NULL;

#if 0
	BKPT;
	atomic_set(&tsai_test, 1001);
	{
		int value;
		printk("ori %d \n", atomic_read(&tsai_test));
		value = atomic_dec_return(&tsai_test);
		printk("%d\n", value);
	}
#endif

	res = sscanf(buf, "%s %s", scmd, sarg);
	if (res > 0) {
		psarg = buf + strlen(scmd) + 1;
	}

	if (strcmp(scmd, "user_callstack")==0) {
		pid_t pid = -1;
		struct task_struct* thetask = NULL;
		res = sscanf(sarg, "%u", &pid);
		if (res) {
			thetask = pid_task(find_vpid(pid), PIDTYPE_PID);
		}
		else {
			/* argument is a process name, find the task */
			thetask = tsai_find_process_by_name(sarg);
		}

		if (thetask) {
			struct file* fout = filp_open("/opt/tsai_output.txt", O_RDWR|O_CREAT|O_TRUNC|O_LARGEFILE, 0666);
			if (fout) {
				tsai_print_process_callstack(thetask, fout);
				filp_close(fout, (fl_owner_t)(NATIVE_UINT)current->pid);
			}
			else {
				printk("tsai_spy_write user_callstack: unable to open output file \n");
			}
		}
	}
	else if (strcmp(scmd, "profile_pid")==0) {
		pid_t pid = -1;
		struct task_struct* thetask = NULL;
		res = sscanf(sarg, "%u", &pid);
		if (res) {
			thetask = pid_task(find_vpid(pid), PIDTYPE_PID);
		}
		else {
			/* argument is a process name, find the task */
			thetask = tsai_find_process_by_name(sarg);
		}

		if (thetask) {
			struct TSpy_Profiler pf;
			char output[128];
			sprintf(output, "/tmp/tsai_%d.txt", pid);
			pf.on_off = 1;
			pf.pid = thetask->pid;
			pf.output_file = output;
			pf.timer_frequency = 1000*10;
			pf.max_depth = 0;
			pf.f_current_thread_only = 1;
			pf.f_annotate_ds5 = 0;
			tsai_spy_profiler(&pf);
		}
	}
	else if (strcmp(scmd, "profile_proc_thre")==0) {
		char proc[32];
		char thre[32];
		struct task_struct* thetask = NULL;
		res = sscanf(psarg, "%s %s", proc, thre);
		if (res) {
			thetask = tsai_find_process_thread_by_name(proc, thre);
		}

		if (thetask) {
			struct TSpy_Profiler pf;
			char output[128];
			sprintf(output, "/tmp/tsai_%d.txt", (int)thetask->pid);
			memset(&pf, 0, sizeof(pf));
			pf.on_off = 1;
			pf.pid = thetask->pid;
			pf.output_file = output;
			pf.timer_frequency = 1000*10;
			pf.max_depth = 0;
			pf.f_current_thread_only = 1;
			pf.f_annotate_ds5 = 0;
			tsai_spy_profiler(&pf);
		}
	}
	else if (strcmp(scmd, "profile_stop")==0) {
		struct TSpy_Profiler p;
		p.on_off = 0;
		tsai_spy_profiler(&p);
	}
	else if (strcmp(scmd, "profile_engine")==0) {
		unsigned int engine = 0;
		res = sscanf(sarg, "%u", &engine);
		if (res == 1) {
			tsai_spy_data.pr.opt_engine_timer = engine;
		}
	}
	else if (strcmp(scmd, "rss_page")==0) {
#ifdef __aarch64__
		BKPT;
#else
		/* eg rss_page enlightenment libmali.so */
		char proc[32];
		char lib[64];
		struct task_struct* thetask = NULL;
		res = sscanf(psarg, "%s %s", proc, lib);
		if (res) {
			thetask = tsai_find_process_by_name(proc);
			tsai_print_process_rss(thetask, lib);
		}
#endif
	}
	else if (strcmp(scmd, "debug_wake_up_task")==0) {
		char proc[32];
		char thre[32];
		struct task_struct* thetask = NULL;
		res = sscanf(psarg, "%s %s", proc, thre);
		if (res) {
			thetask = tsai_find_process_thread_by_name(proc, thre);
		}

		if (thetask) {
			if (!tsai_spy_data.ptr_tsai_debug_wake_up_task)
				tsai_spy_data.ptr_tsai_debug_wake_up_task = (struct task_struct**)__symbol_get("tsai_debug_wake_up_task");

			if (tsai_spy_data.ptr_tsai_debug_wake_up_task)
				*(tsai_spy_data.ptr_tsai_debug_wake_up_task) = thetask;
		}
	}
	else if (strcmp(scmd, "smp_call_func")==0) {
		tsai_spy_smp_call_func();
	}
	else {
	#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
		tsai_callstack_preload_symbol();
	#else
		BKPT;
	#endif
	}
	return count_orig;
}

static int tsai_spy_open(struct inode *inode, struct file *file) {
	/* since I want to use mmap, O_TRUCATE will get in the way and whenever it is open,
	 * previous mmap will be affected and map to zero page, so get rid of unwanted flags here! */
	//file->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	//inode->i_mode &= ~S_IFREG;
	printk("tsai_spy_open called in %s %u\n", current->comm, current->pid);
	return 0;
}
/* usage example:

To trigger a breakpoint next time the specific task is being waken up (not scheduled on core!)
 echo "debug_wake_up_task surfaceflinger surfaceflinger" > /dev/tsai_spy


 * */

DEFINE_SPINLOCK(tsai_spy_log_lock);
TSAI_STATIC unsigned int tsai_spy_spinlock_entered;
TSAI_STATIC unsigned int tsai_spy_spinlock_entered_core;

int tsai_spy_log(const char* fmt, ...) {
	va_list args;
	int i;
	char* buf;
	int len;
	int cpu = smp_processor_id();
	unsigned long irq_flags;
	int skip_lock = 0;

	if (!(tsai_spy_data.log_msg_max && tsai_spy_data.log_msg)) {
		return 0;
	}

	if (tsai_spy_spinlock_entered && tsai_spy_spinlock_entered_core==cpu) {
		skip_lock = 1;
	}

	if (skip_lock) {
	}
	else {
		spin_lock_irqsave(&tsai_spy_log_lock, irq_flags);
		tsai_spy_spinlock_entered++;
		tsai_spy_spinlock_entered_core = cpu;
	}

ReTry:
	if (tsai_spy_data.log_msg_cur >= 512*1024) {
		tsai_spy_data.log_msg_cur = 0;
	}
	buf = tsai_spy_data.log_msg + tsai_spy_data.log_msg_cur;
	len = tsai_spy_data.log_msg_max - tsai_spy_data.log_msg_cur;
	va_start(args, fmt);

	if (len > 2) {
		buf[0] = '0'+ cpu;
		buf[1] = ' ';
		buf += 2; len -= 2;
	}
#ifdef DEBUG
	if ((unsigned int)len > 512*1024) {
		BKPT;
	}
#endif
	i = vsnprintf((char*)buf, len, fmt, args);

	va_end(args);

	if (i>0) {
		tsai_spy_data.log_msg_cur += i+2;
	}
	else {
		tsai_spy_data.log_msg_cur = 0;
		goto ReTry;
	}

	if (!skip_lock) {
		spin_unlock_irqrestore(&tsai_spy_log_lock, irq_flags);
		tsai_spy_spinlock_entered--;
		tsai_spy_spinlock_entered_core = 0;
	}

	return i;
}
EXPORT_SYMBOL(tsai_spy_log);

TSAI_STATIC int tsai_spy_mem_log_rq_is_locked(void);
/* force flush in a convenient time, such as not in interrupt or atomic context
 * return:
 * 1: flush did happen
 * 0: flush did not happen
 * */
int tsai_spy_mem_log_flush(struct tsai_spy_mem_log* ml, int force) {
	//struct thread_info* ti = current_thread_info();
	/* if using preempt_count() to determine whether flush can happen, preempt_count is not zero if in spinlock */
	int dontflush = in_interrupt();
	//int preempt_cnt = preempt_count();
	unsigned long irqflags;
	int ret = 0;
	void* ptr = 0;
	int len = 0;
	int cpu = smp_processor_id();
	int skip_lock = 0;
	int rq_locked;
	if (ml->spinlock_entered[cpu] || (rq_locked=tsai_rq_is_locked())) {
		skip_lock = 1;
	}
	if (skip_lock) {
		return 0;
	}
	if (tsai_spy_mem_log_rq_is_locked()) { /* don't flush if we know we are inside scheduler tracepoints */
		return 0;
	}

	/*TODO: if this function is called from sched_switch tracepoint, complication may happen! */
	spin_lock_irqsave(&ml->log_lock, irqflags);
	ml->spinlock_entered[cpu]++;

	if (ml->pfnCB && dontflush==0) {

		if (ml->curtail) {
			ptr = ml->log_msg + ml->flush_cur;
			len = ml->curtail - ml->flush_cur;
			ml->flush_total += len;
#ifdef DEBUG
			tsai_spy_log("%s flush %d--%d cur %d total %d @%d\n", ml->name, ml->flush_cur, ml->flush_cur+len-1,
					ml->log_msg_cur, ml->flush_total, __LINE__);
#endif
			//spin_lock_irqsave(&ml->log_lock, irqflags);
			ml->curtail = 0;
			ml->flush_cur = 0;
			//spin_unlock_irqrestore(&ml->log_lock, irqflags);
			ret = 1;
			goto Leave;
		}

		//spin_lock_irqsave(&ml->log_lock, irqflags);
			ptr = ml->log_msg + ml->flush_cur;
			len = ml->log_msg_cur - ml->flush_cur;
		//spin_unlock_irqrestore(&ml->log_lock, irqflags);

			ASSERT(ml->log_msg_cur >= ml->flush_cur);
		if (!force && len < 64*1024) /* only flush if more than 32KB data*/
			goto Leave;
		else {
			ml->flush_total += len;
#ifdef DEBUG
			tsai_spy_log("%s flush %d--%d (0x%p,%d bytes) cur %d total %d @%d\n", ml->name, ml->flush_cur, ml->flush_cur+len-1,
					ptr, len, ml->log_msg_cur, ml->flush_total, __LINE__);
#endif
			ml->flush_cur += len;
			ret = 1;
			goto Leave;
		}
	}
	else {
#ifdef DEBUG
			tsai_spy_log("%s cannot flush dontflush %08x cur %d fcur %d curtask pid %d %s @%d\n",
					ml->name, dontflush, ml->log_msg_cur, ml->flush_cur, current->pid, current->comm, __LINE__);
#endif
	}
Leave:
	if (ret==1 && ptr && len) { /* assuming writing to tempfs would not lead to context switch, let it be done within spinlock */
		(*ml->pfnCB)(ml->cb_data, ptr, len);
	}

	ml->spinlock_entered[cpu] = 0;
	spin_unlock_irqrestore(&ml->log_lock, irqflags);


	return ret;
}

/* this is a FIFO data structure */
struct tsai_pending_message_pool {
	char string_pool[16*256];
	struct tsai_spy_mem_log_pending pending[16];
	int free_pool[16]; /* content is interger - index*/
	int free_cnt;
	spinlock_t lock;

	int rq_locked[8]; /* if a CPU RQ lock is locked, set the corresponding flag to 1 */
};

TSAI_STATIC struct tsai_pending_message_pool tsai_pending_pool;


void tsai_spy_mem_log_mark_rq_lock(int lock_on) {
	int cpu = smp_processor_id();
	tsai_pending_pool.rq_locked[cpu] = lock_on;
}

TSAI_STATIC int tsai_spy_mem_log_rq_is_locked(void) {
	int cpu = smp_processor_id();
	return tsai_pending_pool.rq_locked[cpu];
}

TSAI_STATIC void tsai_pending_pool_init(void) {
	int i;
	for (i=0; i<16; i++) {
		tsai_pending_pool.free_pool[i] = i;
		tsai_pending_pool.pending[i].msg = &tsai_pending_pool.string_pool[i*256];
	}
	tsai_pending_pool.free_cnt = 16;
	spin_lock_init(&tsai_pending_pool.lock);
}

TSAI_STATIC struct tsai_spy_mem_log_pending* tsai_pending_pool_pop(void) {
	struct tsai_spy_mem_log_pending* ret = NULL;
	unsigned long irqflags;
	spin_lock_irqsave(&tsai_pending_pool.lock, irqflags);
	if (tsai_pending_pool.free_cnt > 0) {
		int index = tsai_pending_pool.free_pool[--tsai_pending_pool.free_cnt];
		ret = &tsai_pending_pool.pending[index];
	}
	spin_unlock_irqrestore(&tsai_pending_pool.lock, irqflags);

	return ret;
}

TSAI_STATIC void tsai_pending_pool_push(struct tsai_spy_mem_log_pending* p) {
	int index = p - tsai_pending_pool.pending;
	unsigned long irqflags;
	spin_lock_irqsave(&tsai_pending_pool.lock, irqflags);
	tsai_pending_pool.free_pool[tsai_pending_pool.free_cnt++] = index;
	spin_unlock_irqrestore(&tsai_pending_pool.lock, irqflags);
}

TSAI_STATIC void tsai_spy_mem_log_add_pending(struct tsai_spy_mem_log* ml, struct tsai_spy_mem_log_pending* pending, int len) {
	unsigned long irq_flags;
	INIT_LIST_HEAD(&pending->list);
	pending->len = len;
	spin_lock_irqsave(&ml->pending_lock, irq_flags);
	list_add_tail(&pending->list, &ml->pending);

	spin_unlock_irqrestore(&ml->pending_lock, irq_flags);

}

int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...)
{
	va_list args;
	int i;
	char* buf;
	int len;
	unsigned long irq_flags;
	int cpu = smp_processor_id();
	int skip_lock = 0;
	int header_written = 0;
	int rq_locked;

	if (ml->opt_no_header)
		header_written = 1;

	if (ml->spinlock_entered[cpu] || (rq_locked=tsai_rq_is_locked()) ) {
		skip_lock = 1;
	}

	if (skip_lock) {
		/* the tmpfs implementation uses irq_enabled instead of irq_restore_flags, so IRQ will be accidentally enabled.
		 * if re-entering due to IRQ, there is no way to keep consistency of the cursors, better give up this message */
		struct tsai_spy_mem_log_pending* pend;
		int bytes_used = 0;

		pend = tsai_pending_pool_pop();
		if (pend) {
			buf = (char*)pend->msg;
			len = 256;

			va_start(args, fmt);
			if (!header_written) {
				if (len > 2) {
					buf[0] = '0'+ cpu;
					buf[1] = ' ';
					buf += 2; len -= 2;
					header_written = 1;
					bytes_used += 2;
				}
			}
			i = vsnprintf((char*)buf, len, fmt, args);
			va_end(args);

			bytes_used += (i<len? i: len);

			tsai_spy_mem_log_add_pending (ml, pend, bytes_used);
		}
		return 0;
	}
	else {
		spin_lock_irqsave(&ml->log_lock, irq_flags);
		ml->spinlock_entered[cpu]++;
	}
ReTry:
	if (ml->log_msg_cur > ml->log_msg_max) {
		BKPT;
	}
	else if (ml->log_msg_cur == ml->log_msg_max) {
		ml->curtail = ml->log_msg_cur;
		ml->log_msg_cur = 0;
#ifdef DEBUG
			tsai_spy_log("%s need flush curtail=%d @%d\n", ml->name, ml->curtail, __LINE__);
#endif
	}

	buf = ml->log_msg + ml->log_msg_cur;
	len = ml->log_msg_max - ml->log_msg_cur;

	if ( !list_empty(&ml->pending) ) {
		unsigned long irqflags;
		struct tsai_spy_mem_log_pending* pend;
		int bytes_to_copy;
		{
			spin_lock_irqsave(&ml->pending_lock, irqflags);
			pend = container_of(ml->pending.next, struct tsai_spy_mem_log_pending, list);
			list_del(&pend->list);
			spin_unlock_irqrestore(&ml->pending_lock, irqflags);

			bytes_to_copy = (len > pend->len)? pend->len : len;
			memcpy(buf, pend->msg, bytes_to_copy);
			ml->log_msg_cur += bytes_to_copy;

			tsai_pending_pool_push(pend);
		}
		goto ReTry;
	}
	else {
		va_start(args, fmt);
		if (!header_written) {
			if (len > 2) {
				buf[0] = '0'+ cpu;
				buf[1] = ' ';
				buf += 2; len -= 2;
				header_written = 1;
				ml->log_msg_cur += 2;
			}
		}
	#ifdef DEBUG
		if ((unsigned int)len > ml->log_msg_max) {
			BKPT;
		}
	#endif
		i = vsnprintf((char*)buf, len, fmt, args);

		va_end(args);
	}

	if (i>0) {
		if (i > len) { /* buffer not enough, return value i is the value 'would have been' if enough buffer */
			ml->curtail = ml->log_msg_cur;
			ml->log_msg_cur = 0;
#ifdef DEBUG
			tsai_spy_log("%s need flush curtail=%d @%d\n", ml->name, ml->curtail, __LINE__);
#endif
			goto ReTry;
		}
		else {
			ml->log_msg_cur += i;
#ifdef DEBUG
			if (ml->log_msg_cur > ml->log_msg_max) {
				BKPT;
			}
#endif
		}
	}
	else {
		ml->curtail = ml->log_msg_cur;
		ml->log_msg_cur = 0;
		goto ReTry;
	}

	if (!skip_lock) {
		ml->spinlock_entered[cpu] = 0;
		spin_unlock_irqrestore(&ml->log_lock, irq_flags);
	}
	tsai_spy_mem_log_flush(ml, 0);

	return i;
}

void tsai_spy_mem_log_free(struct tsai_spy_mem_log* ml) {
	tsai_spy_mem_log_flush(ml, 1);
}

void tsai_spy_mem_log_init(struct tsai_spy_mem_log* ml, const char* name, int size, PFN_FLUSH_CB pfnCB, void* cb_data)
{
	if (!ml->log_msg) {
		ml->log_msg = vmalloc(size);
	}

	memcpy(ml->name, name, 8);

	ml->log_msg_max = size;
	ml->log_msg_cur = 0;

	ml->curtail = 0;
	ml->flush_cur = 0;
	ml->flush_total = 0;

	spin_lock_init(&ml->log_lock);
	ml->pfnCB = pfnCB;
	ml->cb_data = cb_data;

	INIT_LIST_HEAD(&ml->pending);
	ml->spinlock_entered[0] = 0;
	ml->spinlock_entered[1] = 0;
	ml->spinlock_entered[2] = 0;
	ml->spinlock_entered[3] = 0;
	ml->spinlock_entered[4] = 0;
	ml->spinlock_entered[5] = 0;
	ml->spinlock_entered[6] = 0;
	ml->spinlock_entered[7] = 0;

}

TSAI_STATIC const struct file_operations tsai_spy_ops = {
	.owner = THIS_MODULE,
	.open = tsai_spy_open,
	.write = tsai_spy_write,
	.unlocked_ioctl = tsai_spy_ioctl,
	.compat_ioctl = tsai_spy_ioctl,
};

#include <linux/kallsyms.h>
extern void do_PrefetchAbort(unsigned long addr, unsigned int ifsr, struct pt_regs *regs);

TSAI_STATIC void tsai_save_tracepoint(struct tracepoint *tp, void *priv) {
	struct TSAI_SPY_DATA* d = (struct TSAI_SPY_DATA*)priv;
	if (strcmp(tp->name, "sched_switch")==0) {
		d->tracepoint_sched = tp;
		printk("TSAI SPY __tracepoint_sched_switch = %p \n", d->tracepoint_sched);
	}
	else if (strcmp(tp->name, "sched_wakeup")==0) {
		d->tracepoint_sched_wakeup = tp;
		printk("TSAI SPY __tracepoint_sched_wakeup = %p \n", d->tracepoint_sched_wakeup);
	}
	else if (strcmp(tp->name, "irq_handler_entry")==0) {
		d->tracepoint_irq_entry = tp;
	}
	else if (strcmp(tp->name, "irq_handler_exit")==0) {
		d->tracepoint_irq_exit = tp;
	}
	else if (strcmp(tp->name, "tsai_sched_try_wakeup")==0) {
		d->tracepoint_sched_try_wakeup = tp;
	}
}

struct ts_callstack_binary_cache* tsai_spy_get_bincache(void) {
	return &tsai_spy_data.bincache;
}

int tsai_move_on;

//#include "../../../kernel/fs/sysfs/sysfs.h"

int tsai_spy_init(void)
{
	int ret;

	tsai_spy_dev.minor = MISC_DYNAMIC_MINOR; //0xFF;
	tsai_spy_dev.name = tsai_spy_dev_name;
	tsai_spy_dev.fops = &tsai_spy_ops;
	tsai_spy_dev.parent = NULL;
	//tsai_spy_dev.mode = S_IRUGO|S_IWUGO;
	//BKPT;
	//while (!tsai_move_on)
	//	cpu_relax();

	ret = misc_register(&tsai_spy_dev);
	if (IS_ERR((const void*)(NATIVE_UINT)ret)) {
		printk("failed to create tsai_spy device");
		return -1;
	}

	//tsai_spy_dev.this_device->kobj.sd->s_mode |= (S_IFDIR | S_IRUGO | S_IWUGO);

	/* get pabort symbol*/
	{
#ifdef __aarch64__
		/* not implemented yet */
#else
		char name[KSYM_NAME_LEN];
		char* pmodname;
		unsigned long offset;
		tsai_spy_data.pabort_symbol.addr = (unsigned int)(NATIVE_UINT)do_PrefetchAbort;
		kallsyms_lookup((unsigned long)tsai_spy_data.pabort_symbol.addr, (unsigned long*)&tsai_spy_data.pabort_symbol.size, &offset,
				    &pmodname, name);
#endif
	}

	if (!tsai_spy_data.log_msg) {
		tsai_spy_data.log_msg = vmalloc(512*1024);
		tsai_spy_data.log_msg_max = 512*1024;
		tsai_spy_data.log_msg_cur = 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
	for_each_kernel_tracepoint(tsai_save_tracepoint, &tsai_spy_data);
	ts_callstack_binary_cache_init(&tsai_spy_data.bincache);
#else
	/* not implemented yet */
#endif

	printk("TSAI Spy initialized\n");
	tsai_spy_data.debug_flag = 1;
	tsai_spy_data.pr.opt_engine_timer = 0; /* prefer dedecated profiling worker thread instead of hrtimer */

	tsai_pending_pool_init();

	return 0;
}

void tsai_spy_exit(void)
{
	misc_deregister(&tsai_spy_dev);
}

module_init(tsai_spy_init);
module_exit(tsai_spy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samsung Electronics");
MODULE_VERSION("0.1");
