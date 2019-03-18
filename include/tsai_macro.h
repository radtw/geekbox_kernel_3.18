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
#else
	#define BKPT __asm("bkpt")
#endif

#if defined(DEBUG)
	#define ASSERT(x) if (!(x)) {BKPT;}
#else
	#define ASSERT(x)
#endif

extern int tsai_move_on; /* instance in tsai_spy.c */
#define TSAI_BUSY_WAIT while(!tsai_move_on) cpu_relax();

#endif /* TSAI_ASSERT_H_ */
