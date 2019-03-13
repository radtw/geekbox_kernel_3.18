/*
 * rk_backward_compatible.h
 *
 *  Created on: 11 Mar 2019
 *      Author: cheng.tsai
 */

#ifndef RK_BACKWARD_COMPATIBLE_H_
#define RK_BACKWARD_COMPATIBLE_H_

#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 48))
static inline struct workqueue_struct * __deprecated __system_nrt_wq(void)
{
	return system_wq;
}

static inline struct workqueue_struct * __deprecated __system_nrt_freezable_wq(void)
{
	return system_freezable_wq;
}

/* equivlalent to system_wq and system_freezable_wq, deprecated */
#define system_nrt_wq			__system_nrt_wq()
#define system_nrt_freezable_wq		__system_nrt_freezable_wq()

#endif

#endif /* RK_BACKWARD_COMPATIBLE_H_ */
