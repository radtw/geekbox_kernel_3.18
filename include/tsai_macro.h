/*
 * sruk_bkpt.h
 *
 *  Created on: 7 Nov 2016
 *      Author: cheng.tsai
 */

#ifndef TSAI_ASSERT_H_
#define TSAI_ASSERT_H_

#if defined(__aarch64__)
	#define BKPT __asm("hlt #0")
//#define BKPT pr_info("BKPT but NO JTAG %s%d\n", __FILE__, __LINE__)
#else
	#define BKPT __asm("bkpt")
#endif

#if !defined(ASSERT)
	#if defined(DEBUG)
		#define ASSERT(x) if (!(x)) {BKPT;}
	#else
		#define ASSERT(x)
	#endif
#endif

extern int tsai_move_on; /* instance in tsai_spy.c */
#define TSAI_BUSY_WAIT while(!tsai_move_on) {\
                        static int tsai_print_count;\
	                cpu_relax();\
			if ( tsai_print_count++ < 20 ) \
	                     pr_info("TSAI_BUSY_WAIT @%s%d\n", __FILE__, __LINE__);\
						}

#endif /* TSAI_ASSERT_H_ */
