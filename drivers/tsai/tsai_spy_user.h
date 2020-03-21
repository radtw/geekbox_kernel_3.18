/*
 * tsai_spy_user.h
 *
 * 2020-02-12
 */

#ifndef TSAI_SPY_USER_H_
#define TSAI_SPY_USER_H_

#if !defined(__KERNEL__)
	//typedef uint64_t u64;
	//typedef uint32_t u32;
#include <stdint.h> /* for uint32_t */
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
	TSpyCmd_FindION, /* given an array for FDs, find if any of them is ION and extract ION name from it */
	TSpyCmd_AndroidSysProp, /* coming from Android libc */
    TSpyCmd_MarkDebugProcessThread, /* notify kernel which process/thread is of interest*/	
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

struct TSpy_FindIon {
	uint32_t num_fd;
	uint32_t padding; /* padding for alignment*/
	uint64_t ptr;
};

struct TSpy_AndroidSysProp {
	uint32_t readwrite; /* 0=read, 1=write*/
	uint64_t ptr_prop_name;
	uint64_t ptr_prop_value;
};



struct Tspy_MarkDebugProcessThread {
    uint32_t set_get; /* 0=get, 1=set */
    uint32_t slot;
    uint32_t process_or_thread; /* 0=process, 1=thread*/
    uint32_t pid;
    uint32_t tid;
    uint32_t result;  /*[out] the answer to return to user mode */
};


#if defined(__aarch64__)
	typedef uint64_t NATIVE_UINT;
#else
	typedef uint32_t NATIVE_UINT;
#endif


#ifdef __KERNEL__
/* Kernel mode */

/* To avoid toolchain specifying -Wunused-function, I let static functions to be allowed unused */
#define TSAI_STATIC static __attribute__((unused))

	unsigned long tsai_print_process_callstack(struct task_struct* thetask, struct file* fout);
	unsigned long tsai_print_user_callstack(struct task_struct* thetask, struct file* fout);
	int tsai_spy_log(const char* fmt, ...);
	struct ts_callstack_binary_cache* tsai_spy_get_bincache(void);
#else

#ifdef __cplusplus
	extern "C" {
#endif

	int tsai_spy_init(void);

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

	int tsai_spy_backtrace(struct TSpy_Backtrace* bt);
	int tsai_spy_printk(const char* fmt, ...);
	int tsai_spy_printk_raw(const char* msg);
	int tsai_spy_find_ion(int num_fds, uint32_t* ptr);
	unsigned int tsai_cpu_core_id(void);
	unsigned int tsai_mark_debug_current(int slot);
	int tsai_is_current_mark_debug(int slot, int process_or_thread );
#ifdef ANDROID
#ifdef AOSP //Fixme: define AOSP if you know you can build from AOSP source tree
	struct native_handle;
	int tsai_android_native_buffer_to_ion_name(const struct native_handle* hdl);
#endif
#endif


#ifdef __cplusplus
	}
#endif


#endif /* USER modes*/

#endif /* TSAI_SPY_USER_H_ */
