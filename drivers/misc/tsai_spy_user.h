/*
 * tsai_spy_user.h
 *
 *  Created on: 28 Feb 2017
 *      Author: cheng.tsai
 *      2019-03-07
 */

#ifndef TSAI_SPY_USER_H_
#define TSAI_SPY_USER_H_

#if !defined(__KERNEL__)
	//typedef uint64_t u64;
	//typedef uint32_t u32;
#endif

enum TsaiSpyCmd {
	TSpyCmd_Invalid = 0,
	TSpyCmd_Base = 0x00010000,
	TSpyCmd_Fd_To_Gem = TSpyCmd_Base + 1,
	TSpyCmd_Fd_To_File_Ptr,
	TSpyCmd_LastGpuSchedulePid,
	TSpyCmd_Annotate_prefetch,
	TSpyCmd_Annotate_current_task,
	TSpyCmd_Install_Watchpoint,
	TSpyCmd_Profiler,
	TSpyCmd_Callstack_Print,
	TSpyCmd_Backtrace,
	TSpyCmd_LD_Annotate_Relocate,
	TSpyCmd_LD_Annotate_Lookup,
	TSpyCmd_Printk,
	TSpyCmd_User_Var01 = TSpyCmd_Base + 101,
	TSpyCmdCount
};

struct TSpy_Fd_To_Gem {
	int fd;
	int gem_name; /* [out] */
};

struct TSpy_Fd_To_File_Ptr {
	int fd;
	unsigned long long fileptr; /* [out] */
};

struct TSpy_Task {
	unsigned int ptr_task;
	unsigned int tgid;
	unsigned int pid;
	char comm[16];
};

typedef enum _TSAI_wp_access {
	WP_READ_BIT = 0x1,
	WP_WRITE_BIT = 0x2,
} tsai_wp_access ;

struct TSpy_Watchpoint {
	uint64_t address;
	uint32_t length;
	tsai_wp_access access;
	int on_off;
	const char* label;
};

struct TSpy_Profiler {
	int on_off;
	uint32_t pid; /* PID of the thread to be profiled */
	const char* output_file; /* specify an output file */
	int timer_frequency; /* if 1ms=1000, 1us=1000000 */
	int max_depth; /* 0=keep going, or positive number indicate how many level stacks to parse */
	int max_duration_ms; /* auto stop after specific period (ms) */
	unsigned int f_current_thread_only:1;
	unsigned int f_annotate_ds5:1; /* annotate stack information on DS-5 streamline */
};

struct TSpy_LD_Param {
	const char* filename;
	const char* symbolname;
};

struct TSpy_Backtrace {
	int count;
	int ret; /* how many entries are extracted during unwinding */
	void** buffer;
	unsigned int start_point; /* only begin counting after entering this return address on stack */
	const char** allowed_libs; /* if specified, early exit when encountering anything not on the list */
	const char** terminating_libs; /* an array of const char*, if specified, once encoutering these libraries, stop unwinding */
	unsigned int* regs; /* point to an array of 16 unsigned int, as register values */
};

struct TSpy_Printk {
	uint64_t ptr_msg; /* can be casted to const char* */
	uint32_t msg_len; /* msg len in characters, excluding null terminator */
};

#ifdef __KERNEL__
/* Kernel mode */

#if defined(__aarch64__)
	typedef uint64_t NATIVE_UINT;
#else
	typedef uint32_t NATIVE_UINT;
#endif

/* To avoid toolchain specifying -Wunused-function, I let static functions to be allowed unused */
#define TSAI_STATIC static __attribute__((unused))

	struct tsai_spy_mem_log_pending {
		struct list_head list;
		const char* msg;/* a buffer of 256 bytes for pending message in spinlock re-entering case */
		int len;
	};

	typedef void (*PFN_FLUSH_CB)(void* cb_data, void* ptr, int len);

	/* TSAI: 20180910, tsai_spy_mem_log usually use with tmpfs, and the underlying implementation linux-4.1.10\mm\shmem.c
	 * uses spin_lock_irq /  spin_unlock_irq, instead of spin_lock_irqsave/spin_unlock/irqrestore
	 * Therefore, it is expected tsai_spy_mem_log will re-enter on IRQ context because IRQ is enabled (by mistake) by shmem.c
	 * To avoid this, we can only detect IRQ re-entering situation and avoid deadlock from ourside!
	 * */

	struct tsai_spy_mem_log {
		char name[8];
		spinlock_t log_lock;
		unsigned int spinlock_entered[8];

		struct list_head pending;
		spinlock_t pending_lock;
		/* log buffer */
		void* log_msg;
		unsigned int log_msg_max;
		unsigned int log_msg_cur;

		unsigned int curtail; /* when the buffer is not enough, set the tail and restart from beginning */
		unsigned int flush_cur; /* flush cursor */
		unsigned int flush_total;

		unsigned int opt_no_header:1; /* do not print CPU header */

		PFN_FLUSH_CB pfnCB;
		void* cb_data;
	};


	unsigned long tsai_print_process_callstack(struct task_struct* thetask, struct file* fout);
	unsigned long tsai_print_user_callstack(struct task_struct* thetask, struct file* fout);
	int tsai_spy_log(const char* fmt, ...);

	void tsai_spy_mem_log_init(struct tsai_spy_mem_log* ml, const char* name, int size, PFN_FLUSH_CB pfnCB, void* cb_data);
	void tsai_spy_mem_log_free(struct tsai_spy_mem_log* ml);
	int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...);
	int tsai_spy_mem_log_flush(struct tsai_spy_mem_log* ml, int force);

	void tsai_spy_mem_log_mark_rq_lock(int lock_on);

	struct ts_callstack_binary_cache* tsai_spy_get_bincache(void);
#else

#ifdef __cplusplus
	extern "C" {
#endif

	void tsai_spy_init(void);

	void tsai_spy_ld_annotate_relocate(struct TSpy_LD_Param* p);
	void tsai_spy_ld_annotate_lookup(struct TSpy_LD_Param* p);

	int tsai_spy_fd_to_gem(int fd);
	int tsai_spy_fd_to_file_ptr(int fd, unsigned long long* out_ptr);
	unsigned int tsai_spy_user_var_01(void);
	int tsai_spy_stop_ds5_capture(void);
	unsigned int tsai_spy_last_gpu_sched_pid(void);

	void tsai_spy_annotate_prefetch(int onoff);
	void tsai_spy_annotate_current_task(struct TSpy_Task* t);

	int tsai_spy_watchpoint(uint64_t addr, uint32_t len, unsigned int access, int on_off, const char* label);

	int tsai_spy_profiler(struct TSpy_Profiler* prf);
	int tsai_spy_callstack_print(void);

	int tsai_spy_backtrace(void **buffer, int count);
	int tsai_spy_printk(const char* fmt, ...);
#ifdef __cplusplus
	}
#endif


#endif /* USER modes*/

#endif /* TSAI_SPY_USER_H_ */
