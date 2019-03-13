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

#endif /* TSAI_ASSERT_H_ */
