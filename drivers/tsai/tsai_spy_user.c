/*
 * tsai_spy_user.c
 *
 *  Created on: 28 Feb 2017
 *      Author: cheng.tsai
 *  2020-01-29
 *
For Android, the best way to include this file is in Android.mk
#TSAI:
LOCAL_SRC_FILES += tsai_spy_user.c

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h> /* strcpy */

/* ================================================================ */
#include "tsai_spy_user.h"
/* ================================================================== */


//if TSAI_SPY_LD, then it is meant to be used in ld.so, need to have only minimum function
//#define TSAI_SPY_LD


#ifdef TSAI_SPY_NO_EXPORT
	#define EXPORT
#else
	#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int tsai_spy_fd = 0;


int tsai_spy_init(void) {
	int ret = 0;
	tsai_spy_fd = open("/dev/tsai_spy", O_RDWR);
	if (tsai_spy_fd == -1) {
		int err = errno;
		printf("TSAI: tsai_spy_init fail to open err=%d \n", err);
		ret = err;
	}
	return ret;
}

void tsai_spy_ld_annotate_relocate(struct TSpy_LD_Param* p) {
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_LD_Annotate_Relocate, p, sizeof(struct TSpy_LD_Param) );
}
void tsai_spy_ld_annotate_lookup(struct TSpy_LD_Param* p) {
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_LD_Annotate_Lookup, p, sizeof(struct TSpy_LD_Param) );
}

int tsai_spy_printk(const char* fmt, ...) {
	int ret = 0;
	if (tsai_spy_fd>0) {
		struct TSpy_Printk p;
		int len;
		char msg[256];
		va_list args;
		va_start(args, fmt);
		len = vsnprintf((char*)msg, sizeof(msg), fmt, args);
		va_end(args);

		if (len > 0) {
#ifdef __aarch64__
			p.ptr_msg = (uint64_t)msg;
#else
			p.ptr_msg = (uint32_t)msg;
#endif
			p.msg_len = (uint32_t)len;
			ret = ioctl(tsai_spy_fd, TSpyCmd_Printk, &p, sizeof(struct TSpy_Printk) );
		}
	}
	return ret;
}

int tsai_spy_printk_raw(const char* msg) {
	int ret = 0;
	if (tsai_spy_fd>0) {
		struct TSpy_Printk p;
		if (msg) {
		        p.ptr_msg = (NATIVE_UINT)msg;
			p.msg_len = (uint32_t)strlen(msg);
			ret = ioctl(tsai_spy_fd, TSpyCmd_Printk, &p, sizeof(struct TSpy_Printk) );
		}
	}
	return ret;
}
#if !defined(TSAI_SPY_LD)


#include <stdlib.h>


int tsai_spy_fd_to_gem(int fd) {
	struct TSpy_Fd_To_Gem arg;
	arg.fd = fd;
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_Fd_To_Gem, &arg, sizeof(arg) );
	return arg.gem_name;
}

int tsai_spy_fd_to_file_ptr(int fd, unsigned long long* out_ptr) {
	struct TSpy_Fd_To_File_Ptr arg;
	arg.fd = fd;
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_Fd_To_File_Ptr, &arg, sizeof(arg) );
	if (out_ptr) {
		*out_ptr = arg.fileptr;
	}
	return 0;
}


unsigned int tsai_spy_user_var_01(void) {
	unsigned int arg = 0;
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_User_Var01, &arg, sizeof(arg) );
	return arg;
}

unsigned int tsai_spy_last_gpu_sched_pid(void) {
	unsigned int arg = 0;
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_LastGpuSchedulePid, &arg, sizeof(arg) );
	return arg;
}

/* make DS-5 show annotation of prefetch abort */
void EXPORT tsai_spy_annotate_prefetch(int onoff) {
	int arg = onoff;
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_Annotate_prefetch, &arg, sizeof(arg) );
	return;
}

/* write 0 to /dev/gator/enable will only stop the capture, but the capture directory need to have captured.xml
 * otherwise the desktop ds5 won't accept it.
 * in order to do that , need to kill "gator-child"
 * */
int EXPORT tsai_spy_stop_ds5_capture(void) {
	int ret = 0;
	int r;
	char cmd[256] = {0};
	strcpy(cmd, "pkill gatord-child");
	r = system(cmd);
	if (r == 0) {
		ret = 1;
	}

	return ret;
}

void EXPORT tsai_spy_annotate_current_task(struct TSpy_Task* t) {
	if (tsai_spy_fd>0)
		ioctl(tsai_spy_fd, TSpyCmd_Annotate_current_task, t, sizeof(struct TSpy_Task) );
}

int tsai_spy_watchpoint(uint64_t addr, uint32_t len, unsigned int access, int on_off, const char* label)
{
	int ret = 0;
	struct TSpy_Watchpoint w;
	w.address = addr;
	w.length = len;
	w.access = (tsai_wp_access)access;
	w.on_off = on_off;
	w.label = label;
	if (tsai_spy_fd>0)
		ret = ioctl(tsai_spy_fd, TSpyCmd_Install_Watchpoint, &w, sizeof(w) );
	return ret;

}

int tsai_spy_profiler(struct TSpy_Profiler* prf) {
	int ret = 0;
	if (tsai_spy_fd>0)
		ret = ioctl(tsai_spy_fd, TSpyCmd_Profiler, prf, sizeof(struct TSpy_Profiler) );
	return ret;
}

int tsai_spy_callstack_print(void) {
	int ret = 0;
	if (tsai_spy_fd>0)
		ret = ioctl(tsai_spy_fd, TSpyCmd_Callstack_Print, 0, 0 );
	return ret;

}

/* a replace of GNU backtrace() because it relies on edxidx section and is not useful in reality */
int tsai_spy_backtrace(struct TSpy_Backtrace* bt) {
	int ret = 0;
	if (tsai_spy_fd>0 && bt) {
		if (bt->regs) {
			/* obtain thumb bit through such indirect way! */
#if defined(__aarch64__)
			unsigned int lr = (unsigned int)(uint64_t)__builtin_return_address(0);
#else
			unsigned int lr = (unsigned int)__builtin_return_address(0);
#endif
			bt->regs[16] |= (lr & 0x01)?0x20:0;
		}
		ret = ioctl(tsai_spy_fd, TSpyCmd_Backtrace, bt, sizeof(struct TSpy_Backtrace) );
		(void)ret;
	}
	return bt?bt->ret:0;
}

int tsai_spy_find_ion(int num_fds, uint32_t* ptr) {
	int ret = 0;
	struct TSpy_FindIon arg;
	arg.num_fd = (uint32_t)num_fds;
	arg.padding = 0;
	arg.ptr = (NATIVE_UINT)ptr;
	if (tsai_spy_fd>0) {
		ret = ioctl(tsai_spy_fd, TSpyCmd_FindION, &arg, sizeof(arg) );
	}
	return ret;
}


unsigned int tsai_cpu_core_id(void) {
	unsigned int MPIDR;
#if defined(__aarch64__)
	/* TODO: add 64bit version */
	MPIDR = 0;
#else
	/* TSAI: Android toolchain only allow mrc in kernel mode. Tizen doesn't care
           error: invalid instruction mnemonic 'mrc' 
        */
	#ifdef ANDROID
	MPIDR = 0;
	#else
	__asm volatile("mrc p15, 0, %0, c0, c0, 5" : "=r" (MPIDR));
	#endif
#endif
	/* MRC p15, 0, <Rt>, c0, c0, 5; Read Multiprocessor Affinity Register */
	return (MPIDR & 3);
}

#ifdef ANDROID
	#include <cutils/native_handle.h>
	int tsai_android_native_buffer_to_ion_name(const struct native_handle* hdl) {
		int ret = 0;
		uint32_t fds[16];
		int fd_count = hdl->numFds > 16? 16:hdl->numFds;
		int i;
		for (i=0; i<fd_count; i++) {
			fds[i] = hdl->data[i];
		}
		ret = tsai_spy_find_ion(fd_count, fds);
		return ret;
	}
#endif

#endif

#ifdef __cplusplus
}
#endif
