/*
 * tsai_breakpoint.c
 *
 *  Created on: 1 Apr 2015
 *      Author: cheng.tsai
 *  2017-12-28
 *
 *  2019-02-25: adding implementation for aarch64
 */

//#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/version.h>

#include "tsai_macro.h"

static DEFINE_SPINLOCK(mtx_tsai_wp);

static unsigned int tsai_breakpoint_print = 0;

/*
mutex_lock(&mtx_tsai_wp);
mutex_unlock(&mtx_tsai_wp);
*/

#if defined(__aarch64__)

	#define ARM_DBG_READ_64(wpidx, wcrwvr, VAL) do {\
		asm volatile("MRS %0, " #wcrwvr#wpidx "_EL1" : "=r" (VAL));\
	} while (0)

	#define ARM_DBG_WRITE_64(wpidx, wcrwvr, VAL) do {\
		asm volatile("MSR " #wcrwvr#wpidx "_EL1, %0 " : : "r" (VAL));\
	} while (0)

#else
	/* Accessor macros for the debug registers. */
	#define ARM_DBG_READ(M, OP2, VAL) do {\
		asm volatile("mrc p14, 0, %0, c0," #M ", " #OP2 : "=r" (VAL));\
	} while (0)

	#define ARM_DBG_WRITE(M, OP2, VAL) do {\
		asm volatile("mcr p14, 0, %0, c0," #M ", " #OP2 : : "r" (VAL));\
	} while (0)

/*
	#define PREFETCH_FLUSH do {\
		u32 sbz=0; \
		asm volatile("mcr p15,0,%0,c7,c5,4" : : "r" (sbz)); \
	} while (0)
*/

#endif

typedef enum _wp_access {
	WP_NONE = 0,
	WP_READ = 1,
	WP_WRITE = 2,
	WP_READWRITE = 3
} wp_access ;

typedef struct _tsai_watchpoint {
	u64 addr;
	u64 addr_backup;
	wp_access access;
	unsigned core_setup; /* which core setup this? */
	unsigned core_remove; /* which core remove this? */
	char label[108];
} tsai_watchpoint;

tsai_watchpoint tsai_watchpoints[4];


void read_watchpoint_registers(int idx, u64* pDBGWVR, u64* pDBGWCR) {
#if defined(__aarch64__)
	u64 wvr;
	u64 wcr;
#else
	u32 wvr;
	u32 wcr;
#endif

#if defined(__aarch64__)
	dmb(0);
	if (idx==0) {
		ARM_DBG_READ_64(0, DBGWVR, wvr);
		ARM_DBG_READ_64(0, DBGWCR, wcr);
	}
	else if (idx==1) {
		ARM_DBG_READ_64(1, DBGWVR, wvr);
		ARM_DBG_READ_64(1, DBGWCR, wcr);
	}
	else if (idx==2) {
		ARM_DBG_READ_64(2, DBGWVR, wvr);
		ARM_DBG_READ_64(2, DBGWCR, wcr);
	}
	else if (idx==3) {
		ARM_DBG_READ_64(3, DBGWVR, wvr);
		ARM_DBG_READ_64(3, DBGWCR, wcr);
	}
#else
	dmb();
	if (idx==0) {
		ARM_DBG_READ(c0, 6, wvr);
		ARM_DBG_READ(c0, 7, wcr);
	}
	else if (idx==1) {
		ARM_DBG_READ(c1, 6, wvr);
		ARM_DBG_READ(c1, 7, wcr);
	}
	else if (idx==2) {
		ARM_DBG_READ(c2, 6, wvr);
		ARM_DBG_READ(c2, 7, wcr);
	}
	else if (idx==3) {
		ARM_DBG_READ(c3, 6, wvr);
		ARM_DBG_READ(c3, 7, wcr);
	}
#endif

	if (pDBGWVR)
		*pDBGWVR = wvr;

	if (pDBGWCR)
		*pDBGWCR = wcr;

	isb();
#if defined(__aarch64__)
	dsb(0);
#else
	dsb();
#endif
}

/* idx: watchpoint index, there are 4 watch point available */
void write_watchpoint_register(int idx, u64 address, wp_access access) {
#if defined(__aarch64__)
	u64 wvr;
	u64 wcr;
#else
	u32 wvr;
	u32 wcr;
#endif

#if defined(__aarch64__)
	wvr = (address) & (~0x03) ;
#else
	wvr = ((u32)address) & (~0x03) ;
#endif
	wcr = 	0x1 | /* enabled*/
			(0x03 << 1)| /* match all access */
			(access & 0x03) << 3 | /* read / write / readwrite */
			(0x0F) << 5; /* bas 1111*/
#if defined(__aarch64__)
	dmb(0);
	if (idx==0) {
		asm volatile("MSR DBGWVR0_EL1, %0 " :: "r" (wvr));\
		//ARM_DBG_WRITE_64(0, DBGWVR, wvr);
		ARM_DBG_WRITE_64(0, DBGWCR, wcr);
	}
	else if (idx==1) {
		ARM_DBG_WRITE_64(1, DBGWVR, wvr);
		ARM_DBG_WRITE_64(1, DBGWCR, wcr);
	}
	else if (idx==2) {
		ARM_DBG_WRITE_64(2, DBGWVR, wvr);
		ARM_DBG_WRITE_64(2, DBGWCR, wcr);
	}
	else if (idx==3) {
		ARM_DBG_WRITE_64(3, DBGWVR, wvr);
		ARM_DBG_WRITE_64(3, DBGWCR, wcr);
	}
#else
	dmb();
	if (idx==0) {
		ARM_DBG_WRITE(c0, 6, wvr); /* mcr     p14,0x0,r3,c0,c0,0x6 r3=wvr*/
		ARM_DBG_WRITE(c0, 7, wcr); /* mcr     p14,0x0,r3,c0,c0,0x7 r3=wcr control register */
	}
	else if (idx==1) {
		ARM_DBG_WRITE(c1, 6, wvr);
		ARM_DBG_WRITE(c1, 7, wcr);
	}
	else if (idx==2) {
		ARM_DBG_WRITE(c2, 6, wvr);
		ARM_DBG_WRITE(c2, 7, wcr);
	}
	else if (idx==3) {
		ARM_DBG_WRITE(c3, 6, wvr);
		ARM_DBG_WRITE(c3, 7, wcr);
	}
#endif

	/*TSAI experiment: see if it can write to other cores?
	ARM_DBG_WRITE(c0, c4, 6, wvr);
	 * no, such assembly will become undefined instruction fault
	 * mcr     p14,0x0,r3,c0,c4,0x6
	 * */

	isb();
#if defined(__aarch64__)
	dsb(0);
#else
	dsb();
#endif

}

void reset_watchpoint_register(int idx) {
#if defined(__aarch64__)
	u64 wvr;
	u64 wcr;
#else
	u32 wvr;
	u32 wcr;
#endif
	int cpu = smp_processor_id();


	wvr = 0;
	wcr = 0;
#if defined(__aarch64__)
	dmb(0);
	if (idx==0) {
		ARM_DBG_WRITE_64(0, DBGWVR, wvr);
		ARM_DBG_WRITE_64(0, DBGWCR, wcr);
	}
	else if (idx==1) {
		ARM_DBG_WRITE_64(1, DBGWVR, wvr);
		ARM_DBG_WRITE_64(1, DBGWCR, wcr);
	}
	else if (idx==2) {
		ARM_DBG_WRITE_64(2, DBGWVR, wvr);
		ARM_DBG_WRITE_64(2, DBGWCR, wcr);
	}
	else if (idx==3) {
		ARM_DBG_WRITE_64(3, DBGWVR, wvr);
		ARM_DBG_WRITE_64(3, DBGWCR, wcr);
	}
#else
	dmb();
	if (idx==0) {
		ARM_DBG_WRITE(c0, 6, wvr);
		ARM_DBG_WRITE(c0, 7, wcr);
	}
	else if (idx==1) {
		ARM_DBG_WRITE(c1, 6, wvr);
		ARM_DBG_WRITE(c1, 7, wcr);
	}
	else if (idx==2) {
		ARM_DBG_WRITE(c2, 6, wvr);
		ARM_DBG_WRITE(c2, 7, wcr);
	}
	else if (idx==3) {
		ARM_DBG_WRITE(c3, 6, wvr);
		ARM_DBG_WRITE(c3, 7, wcr);
	}
#endif
	isb();
#if defined(__aarch64__)
	dsb(0);
#else
	dsb();
#endif

	if (tsai_breakpoint_print)
		printk("reset_watchpoint_register from cpu %d idx %d\n", cpu, idx);

}

/* looks like update in one core will not show up in another core soon, extra check to force sync */
void force_sync_watchpoint(void) {
	int i;
	for (i=0; i<4; i++) {
		if (tsai_watchpoints[i].addr) {
			write_watchpoint_register(i, (u64)tsai_watchpoints[i].addr, tsai_watchpoints[i].access);
		}
		else {
			reset_watchpoint_register(i);
		}
	}
}

typedef enum _tsai_ipi_type {
	TSAI_IPI_INSTALL_WP = 1,
	TSAI_IPI_REMOVE_WP,
} tsai_ipi_type ;

struct tsai_ipi_info {
	tsai_ipi_type command;
	int point_number; /* breakpoint or watch point number, 0 based index */
	u64 address;
	u32 access;
	unsigned int expected_core_reply[8]; /* assuming no more than eight cores */
};

static void tsai_smp_call_func(void *info) {
	struct tsai_ipi_info* pinfo = (struct tsai_ipi_info*)info;
	int cpu = smp_processor_id();
	if (pinfo->command == TSAI_IPI_INSTALL_WP) {
		write_watchpoint_register(pinfo->point_number , pinfo->address, pinfo->access);
	}
	else if (pinfo->command == TSAI_IPI_REMOVE_WP) {
		reset_watchpoint_register(pinfo->point_number);
	}

	pinfo->expected_core_reply[cpu] = 0;
	if (tsai_breakpoint_print)
		printk("tsai_smp_call_func from cpu %d \n", cpu);
}




/* return: 0: no available watch point
 * 1,2,3,4 the watchpoint has been installed at which slot
 *
 * */
int tsai_install_watchpoint(u64 address, unsigned int access, const char* label) {
	int i,j;
	int ret = 0;
	int cpuid = smp_processor_id();
	int max_cpu = setup_max_cpus;
	struct call_single_data csd_stack[8];
	/* NOTE: smp_call_function_many() cannot be called from interrupt context! */

	/* don't disable interrupt, this class itself rely on interprocessor interrupt to go on,
	 * disable interrupt will make previous unfinished request have no chance to complete*/
	spin_lock(&mtx_tsai_wp);
	//force_sync_watchpoint();
	for (i=0; i<4; i++) {
		if (! tsai_watchpoints[i].addr) {
			struct tsai_ipi_info info;
			//struct cpumask cpu;
			u64 wvr2;
			u64 wcr2;

			info.command = TSAI_IPI_INSTALL_WP;
			info.address = (u64)address;
			info.access = access;
			info.point_number = i;

			//write_watchpoint_register(i, address, access);
			for (j=0; j<max_cpu; j++) {
				if (j != cpuid) {
					csd_stack[j].flags = 0;
					csd_stack[j].func = tsai_smp_call_func;
					csd_stack[j].info = &info;
					info.expected_core_reply[j] = 1;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 18, 0)
					smp_call_function_single_async(j, &csd_stack[j]);
#else
					__smp_call_function_single(j, &csd_stack[j],0);
#endif
				}
				else {
					info.expected_core_reply[j] = 0;
				}
			}
			tsai_smp_call_func(&info);
			//smp_call_function_many(&cpu, tsai_smp_call_func, &info, 1);
			/* busy wait until all CPU cores have responded */
			while (1) {
				int pending = 0;
				for (j=0; j<max_cpu; j++) {
					pending += info.expected_core_reply[j];
				}
				if (!pending) {
					break;
				}
			}

			/* verify the register update take effect! */
			read_watchpoint_registers(i, &wvr2, &wcr2);
			if (wvr2 != address ) {
				BKPT;
			}

			tsai_watchpoints[i].addr = tsai_watchpoints[i].addr_backup = address;
			tsai_watchpoints[i].access = access;
			tsai_watchpoints[i].core_setup = smp_processor_id();
			if (label) {
				strncpy(tsai_watchpoints[i].label, label, sizeof(tsai_watchpoints[i].label));
			}
			else {
				tsai_watchpoints[i].label[0] = 0;
			}
			ret = i + 1;
			break;
		}
	}
	spin_unlock(&mtx_tsai_wp);

	return ret;
}

EXPORT_SYMBOL(tsai_install_watchpoint);

int tsai_remove_watchpoint(u64 address) {
	int ret = 0;
	int i,j;
	int cpuid = smp_processor_id();
	int max_cpu = setup_max_cpus;
	struct call_single_data csd_stack[8];
	//unsigned long irq_flags;

	u64 wvr;
	u64 wcr;
	spin_lock(&mtx_tsai_wp);
//	force_sync_watchpoint();
	for (i=0; i<4; i++) {
		if (tsai_watchpoints[i].addr == address) {
			/*
			 *  watch point setup by another code could not be seen by this core, how to fix?
			 *
			read_watchpoint_registers(i, &wvr, &wcr);
			if (wvr != (u32)address ) {
				__asm("bkpt");
			}
			*/
			struct tsai_ipi_info info;
			//struct cpumask cpu;
			//u32 wvr2;
			//u32 wcr2;

			info.command = TSAI_IPI_REMOVE_WP;
			info.address = (u64)address;
			info.access = 0;
			info.point_number = i;

			//write_watchpoint_register(i, address, access);
			for (j=0; j<max_cpu; j++) {
				if (j != cpuid) {
					csd_stack[j].flags = 0;
					csd_stack[j].func = tsai_smp_call_func;
					csd_stack[j].info = &info;
					info.expected_core_reply[j] = 1;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 18, 0)
					smp_call_function_single_async(j, &csd_stack[j]);
#else
					__smp_call_function_single(j, &csd_stack[j],0);
#endif
				}
				else {
					info.expected_core_reply[j] = 0;
				}
			}
			tsai_smp_call_func(&info);
			//smp_call_function_many(&cpu, tsai_smp_call_func, &info, 1);
			/* busy wait until all CPU cores have responded */
			while (1) {
				int pending = 0;
				for (j=0; j<max_cpu; j++) {
					pending += info.expected_core_reply[j];
				}
				if (!pending) {
					break;
				}
			}

			/* verify the register update take effect! */
			read_watchpoint_registers(i, &wvr, &wcr);
			if (wvr || wcr ) {
				BKPT;
			}

			tsai_watchpoints[i].addr = 0;
			tsai_watchpoints[i].core_remove = smp_processor_id();
			ret = 1;
			break;
		}
	}
	spin_unlock(&mtx_tsai_wp);
	return ret;
}

EXPORT_SYMBOL(tsai_remove_watchpoint);
