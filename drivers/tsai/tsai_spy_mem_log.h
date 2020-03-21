/*
 * tsai_spy_men_log.h
 *
 *  Created on: 27 Apr 2020
 *      Author: julian
 */

#ifndef DRIVERS_TSAI_TSAI_SPY_MEM_LOG_H_
#define DRIVERS_TSAI_TSAI_SPY_MEM_LOG_H_

#include <linux/list.h>


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

		/* when the buffer is not enough, set the tail and restart from beginning,
		 * when flushing or reading, clear this variable when it's no longer needed */
		unsigned int curtail;

		unsigned int flush_cur; /* flush cursor */
		unsigned int flush_total;

		unsigned int opt_no_header:1; /* do not print CPU header */
		unsigned int flag_overrun:1; /* it has received more than log_msg_max bytes and has recycled the cursor */

		PFN_FLUSH_CB pfnCB;
		void* cb_data;
	};


	void tsai_spy_mem_log_global_init(void);
	void tsai_spy_mem_log_init(struct tsai_spy_mem_log* ml, const char* name, int size, PFN_FLUSH_CB pfnCB, void* cb_data);
	void tsai_spy_mem_log_free(struct tsai_spy_mem_log* ml);
	int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...);
	int tsai_spy_mem_log_flush(struct tsai_spy_mem_log* ml, int force);
	int tsai_spy_mem_log_read(struct tsai_spy_mem_log* ml, char __user *buf, size_t count_orig);
	void tsai_spy_mem_log_read_prepare(struct tsai_spy_mem_log* ml);
	void tsai_spy_mem_log_mark_rq_lock(int lock_on);




#endif /* DRIVERS_TSAI_TSAI_SPY_MEM_LOG_H_ */
