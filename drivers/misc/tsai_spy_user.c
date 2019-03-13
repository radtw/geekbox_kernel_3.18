/*
 * tsai_spy_user.c
 *
 *  Created on: 28 Feb 2017
 *      Author: cheng.tsai
 *  2018-05-15
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <sys/ioctl.h>

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


void tsai_spy_init(void) {
	tsai_spy_fd = open("/dev/tsai_spy", O_RDWR);
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
			p.msg_len = len;
			ret = ioctl(tsai_spy_fd, TSpyCmd_Printk, p, sizeof(struct TSpy_LD_Param) );
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
int tsai_spy_backtrace(void **buffer, int count) {
	int ret = 0;
	struct TSpy_Backtrace arg;
	arg.count = count;
	arg.buffer = buffer;
	arg.ret = 0;
	if (tsai_spy_fd>0) {
		ret = ioctl(tsai_spy_fd, TSpyCmd_Backtrace, &arg, sizeof(arg) );
		(void)ret;
	}
	return arg.ret;
}



#endif

#ifdef __cplusplus
}
#endif
