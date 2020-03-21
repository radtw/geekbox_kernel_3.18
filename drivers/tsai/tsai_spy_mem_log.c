/*
 * tsai_spy_mem_log.c
 *
 *  Created on: 27 Apr 2020
 *      Author: julian
 */

#include <linux/rbtree.h>
#include <linux/list.h>

#include <linux/tracepoint.h>
#include <linux/atomic.h>

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/stacktrace.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "tsai_spy_user.h"
#include "tsai_macro.h"
#include "tsai_spy_mem_log.h"

//if enable debug, it will use tsai_spy_log() to record the message
//#define DEBUG

extern int tsai_rq_is_locked(void);

TSAI_STATIC int tsai_spy_mem_log_rq_is_locked(void);
/* force flush in a convenient time, such as not in interrupt or atomic context
 * return:
 * 1: flush did happen
 * 0: flush did not happen
 * */
int tsai_spy_mem_log_flush(struct tsai_spy_mem_log* ml, int force) {
	//struct thread_info* ti = current_thread_info();
	/* if using preempt_count() to determine whether flush can happen, preempt_count is not zero if in spinlock */
	int dontflush = in_interrupt();
	//int preempt_cnt = preempt_count();
	unsigned long irqflags;
	int ret = 0;
	void* ptr = 0;
	int len = 0;
	int cpu = smp_processor_id();
	int skip_lock = 0;
	int rq_locked;
	if (ml->spinlock_entered[cpu] || (rq_locked=tsai_rq_is_locked())) {
		skip_lock = 1;
	}
	if (skip_lock) {
		return 0;
	}
	if (tsai_spy_mem_log_rq_is_locked()) { /* don't flush if we know we are inside scheduler tracepoints */
		return 0;
	}

	/*TODO: if this function is called from sched_switch tracepoint, complication may happen! */
	spin_lock_irqsave(&ml->log_lock, irqflags);
	ml->spinlock_entered[cpu]++;

	if (ml->pfnCB && dontflush==0) {

		if (ml->curtail) {
			ptr = ml->log_msg + ml->flush_cur;
			len = ml->curtail - ml->flush_cur;
			ml->flush_total += len;
#ifdef DEBUG
			tsai_spy_log("%s flush %d--%d cur %d total %d @%d\n", ml->name, ml->flush_cur, ml->flush_cur+len-1,
					ml->log_msg_cur, ml->flush_total, __LINE__);
#endif
			//spin_lock_irqsave(&ml->log_lock, irqflags);
			ml->curtail = 0;
			ml->flush_cur = 0;
			//spin_unlock_irqrestore(&ml->log_lock, irqflags);
			ret = 1;
			goto Leave;
		}

		//spin_lock_irqsave(&ml->log_lock, irqflags);
			ptr = ml->log_msg + ml->flush_cur;
			len = ml->log_msg_cur - ml->flush_cur;
		//spin_unlock_irqrestore(&ml->log_lock, irqflags);

			ASSERT(ml->log_msg_cur >= ml->flush_cur);
		if (!force && len < 64*1024) /* only flush if more than 32KB data*/
			goto Leave;
		else {
			ml->flush_total += len;
#ifdef DEBUG
			tsai_spy_log("%s flush %d--%d (0x%p,%d bytes) cur %d total %d @%d\n", ml->name, ml->flush_cur, ml->flush_cur+len-1,
					ptr, len, ml->log_msg_cur, ml->flush_total, __LINE__);
#endif
			ml->flush_cur += len;
			ret = 1;
			goto Leave;
		}
	}
	else {
#ifdef DEBUG
			tsai_spy_log("%s cannot flush dontflush %08x cur %d fcur %d curtask pid %d %s @%d\n",
					ml->name, dontflush, ml->log_msg_cur, ml->flush_cur, current->pid, current->comm, __LINE__);
#endif
	}
Leave:
	if (ret==1 && ptr && len) { /* assuming writing to tempfs would not lead to context switch, let it be done within spinlock */
		(*ml->pfnCB)(ml->cb_data, ptr, len);
	}

	ml->spinlock_entered[cpu] = 0;
	spin_unlock_irqrestore(&ml->log_lock, irqflags);


	return ret;
}

/* call this function before calling tsai_spy_mem_log_read(),
 * so it can determine whether the message buffer need to be dumped in full*/
void tsai_spy_mem_log_read_prepare(struct tsai_spy_mem_log* ml) {
	if (ml->flag_overrun) {
		unsigned char* pData = (unsigned char*)ml->log_msg;
		ml->flush_cur = ml->log_msg_cur;
		if (pData[ml->flush_cur]==0) {
			/* usually the byte at write cursor is 0x00 due to last write, I intentionally don't want to skip one byte,
			 * so setting this null byte to space character instead */
			pData[ml->flush_cur] = 0x20;
		}
	}
}

//suitable for calling this function from .read operation
int tsai_spy_mem_log_read(struct tsai_spy_mem_log* ml, char __user *buf, size_t count_orig)  {
	int user_copied = 0; //how many bytes copied to user buffer
	int bytes_to_copy;
	unsigned char* kern_buf = ml->log_msg;
	int user_bytes_available = count_orig;
	int r, w;

	while (user_bytes_available) {
		r = ml->flush_cur;
		w = ml->log_msg_cur;

		if (r < w) {
			bytes_to_copy = w - r;
		}
		else if ( r > w) {
			if (ml->curtail)
				bytes_to_copy = ml->curtail - r;
			else
				bytes_to_copy = ml->log_msg_max - r;
		}
		else { //r==w, so either nothing to read or read whole buffer
			if (ml->curtail)
				bytes_to_copy = ml->curtail - r;
			else {
				bytes_to_copy = 0;
				break;
			}
		}

		if (bytes_to_copy > user_bytes_available) {
			bytes_to_copy = user_bytes_available;
		}

		pr_info("Copying src (%d--%d) to dst (%d--%d) %d bytes \n", r, (r+bytes_to_copy-1),
				user_copied, (user_copied+bytes_to_copy-1), bytes_to_copy );

		if (!(bytes_to_copy > 0))
			break;

		if (copy_to_user(buf+user_copied, kern_buf + r, bytes_to_copy) == 0) {
			/*return value 0 = copy success */
			user_copied += bytes_to_copy;
			ml->flush_cur = (ml->flush_cur + bytes_to_copy) ;
			if (ml->flush_cur >= ml->log_msg_max)
				ml->flush_cur -= ml->log_msg_max;

			user_bytes_available -= bytes_to_copy;

			if (ml->flush_cur == ml->curtail) {
				ml->flush_cur = 0;
				ml->curtail = 0;
			}
		}
	}

	return user_copied;
}


/* this is a FIFO data structure */
struct tsai_pending_message_pool {
	char string_pool[16*256];
	struct tsai_spy_mem_log_pending pending[16];
	int free_pool[16]; /* content is interger - index*/
	int free_cnt;
	spinlock_t lock;

	int rq_locked[8]; /* if a CPU RQ lock is locked, set the corresponding flag to 1 */
};

TSAI_STATIC struct tsai_pending_message_pool tsai_pending_pool;

/* When entering a tracepoint probe function
 * in the Add these in enter/exit
 tsai_spy_mem_log_mark_rq_lock(1);
 tsai_spy_mem_log_mark_rq_lock(0);
 * */
void tsai_spy_mem_log_mark_rq_lock(int lock_on) {
	int cpu = smp_processor_id();
	tsai_pending_pool.rq_locked[cpu] = lock_on;
}

TSAI_STATIC int tsai_spy_mem_log_rq_is_locked(void) {
	int cpu = smp_processor_id();
	return tsai_pending_pool.rq_locked[cpu];
}

TSAI_STATIC void tsai_pending_pool_init(void) {
	int i;
	for (i=0; i<16; i++) {
		tsai_pending_pool.free_pool[i] = i;
		tsai_pending_pool.pending[i].msg = &tsai_pending_pool.string_pool[i*256];
	}
	tsai_pending_pool.free_cnt = 16;
	spin_lock_init(&tsai_pending_pool.lock);
}

TSAI_STATIC struct tsai_spy_mem_log_pending* tsai_pending_pool_pop(void) {
	struct tsai_spy_mem_log_pending* ret = NULL;
	unsigned long irqflags;
	spin_lock_irqsave(&tsai_pending_pool.lock, irqflags);
	if (tsai_pending_pool.free_cnt > 0) {
		int index = tsai_pending_pool.free_pool[--tsai_pending_pool.free_cnt];
		ret = &tsai_pending_pool.pending[index];
	}
	spin_unlock_irqrestore(&tsai_pending_pool.lock, irqflags);

	return ret;
}

TSAI_STATIC void tsai_pending_pool_push(struct tsai_spy_mem_log_pending* p) {
	int index = p - tsai_pending_pool.pending;
	unsigned long irqflags;
	spin_lock_irqsave(&tsai_pending_pool.lock, irqflags);
	tsai_pending_pool.free_pool[tsai_pending_pool.free_cnt++] = index;
	spin_unlock_irqrestore(&tsai_pending_pool.lock, irqflags);
}

TSAI_STATIC void tsai_spy_mem_log_add_pending(struct tsai_spy_mem_log* ml, struct tsai_spy_mem_log_pending* pending, int len) {
	unsigned long irq_flags;
	INIT_LIST_HEAD(&pending->list);
	pending->len = len;
	spin_lock_irqsave(&ml->pending_lock, irq_flags);
	list_add_tail(&pending->list, &ml->pending);

	spin_unlock_irqrestore(&ml->pending_lock, irq_flags);

}

int tsai_spy_mem_log(struct tsai_spy_mem_log* ml, const char* fmt, ...)
{
	va_list args;
	int i;
	char* buf;
	int len;
	unsigned long irq_flags;
	int cpu = smp_processor_id();
	int skip_lock = 0;
	int header_written = 0;
	int rq_locked;

	if (ml->opt_no_header)
		header_written = 1;

	if (ml->spinlock_entered[cpu] || (rq_locked=tsai_rq_is_locked()) ) {
		skip_lock = 1;
	}

	if (skip_lock) {
		/* the tmpfs implementation uses irq_enabled instead of irq_restore_flags, so IRQ will be accidentally enabled.
		 * if re-entering due to IRQ, there is no way to keep consistency of the cursors, better give up this message */
		struct tsai_spy_mem_log_pending* pend;
		int bytes_used = 0;

		pend = tsai_pending_pool_pop();
		if (pend) {
			buf = (char*)pend->msg;
			len = 256;

			va_start(args, fmt);
			if (!header_written) {
				if (len > 2) {
					buf[0] = '0'+ cpu;
					buf[1] = ' ';
					buf += 2; len -= 2;
					header_written = 1;
					bytes_used += 2;
				}
			}
			i = vsnprintf((char*)buf, len, fmt, args);
			va_end(args);

			bytes_used += (i<len? i: len);

			tsai_spy_mem_log_add_pending (ml, pend, bytes_used);
		}
		return 0;
	}
	else {
		spin_lock_irqsave(&ml->log_lock, irq_flags);
		ml->spinlock_entered[cpu]++;
	}
ReTry:
	if (ml->log_msg_cur > ml->log_msg_max) {
		BKPT;
	}
	else if (ml->log_msg_cur == ml->log_msg_max) {
		/* in this clause, means now message buffer has now overrun and recycle again */
		ml->curtail = ml->log_msg_cur;
		ml->log_msg_cur = 0;
		ml->flag_overrun = 1;
#ifdef DEBUG
			tsai_spy_log("%s need flush curtail=%d @%d\n", ml->name, ml->curtail, __LINE__);
#endif
	}

	buf = ml->log_msg + ml->log_msg_cur;
	len = ml->log_msg_max - ml->log_msg_cur;

	if ( !list_empty(&ml->pending) ) {
		unsigned long irqflags;
		struct tsai_spy_mem_log_pending* pend;
		int bytes_to_copy;
		{
			spin_lock_irqsave(&ml->pending_lock, irqflags);
			pend = container_of(ml->pending.next, struct tsai_spy_mem_log_pending, list);
			list_del(&pend->list);
			spin_unlock_irqrestore(&ml->pending_lock, irqflags);

			bytes_to_copy = (len > pend->len)? pend->len : len;
			memcpy(buf, pend->msg, bytes_to_copy);
			ml->log_msg_cur += bytes_to_copy;

			tsai_pending_pool_push(pend);
		}
		goto ReTry;
	}
	else {
		va_start(args, fmt);
		if (!header_written) {
			if (len > 2) {
				buf[0] = '0'+ cpu;
				buf[1] = ' ';
				buf += 2; len -= 2;
				header_written = 1;
				ml->log_msg_cur += 2;
			}
		}
	#ifdef DEBUG
		if ((unsigned int)len > ml->log_msg_max) {
			BKPT;
		}
	#endif
		i = vsnprintf((char*)buf, len, fmt, args);

		va_end(args);
	}

	if (i>0) {
		if (i > len) { /* buffer not enough, return value i is the value 'would have been' if enough buffer */
			ml->curtail = ml->log_msg_cur;
			ml->log_msg_cur = 0;
			ml->flag_overrun = 1;
#ifdef DEBUG
			tsai_spy_log("%s need flush curtail=%d @%d\n", ml->name, ml->curtail, __LINE__);
#endif
			goto ReTry;
		}
		else {
			ml->log_msg_cur += i;
#ifdef DEBUG
			if (ml->log_msg_cur > ml->log_msg_max) {
				BKPT;
			}
#endif
		}
	}
	else {
		ml->curtail = ml->log_msg_cur;
		ml->log_msg_cur = 0;
		ml->flag_overrun = 1;
		goto ReTry;
	}

	if (!skip_lock) {
		ml->spinlock_entered[cpu] = 0;
		spin_unlock_irqrestore(&ml->log_lock, irq_flags);
	}
	tsai_spy_mem_log_flush(ml, 0);

	return i;
}

void tsai_spy_mem_log_free(struct tsai_spy_mem_log* ml) {
	tsai_spy_mem_log_flush(ml, 1);
}

void tsai_spy_mem_log_init(struct tsai_spy_mem_log* ml, const char* name, int size, PFN_FLUSH_CB pfnCB, void* cb_data)
{
	if (!ml->log_msg) {
		ml->log_msg = vmalloc(size);
	}

	memcpy(ml->name, name, 8);

	ml->log_msg_max = size;
	ml->log_msg_cur = 0;

	ml->curtail = 0;
	ml->flush_cur = 0;
	ml->flush_total = 0;

	spin_lock_init(&ml->log_lock);
	ml->pfnCB = pfnCB;
	ml->cb_data = cb_data;

	INIT_LIST_HEAD(&ml->pending);
	spin_lock_init(&ml->pending_lock);
	ml->spinlock_entered[0] = 0;
	ml->spinlock_entered[1] = 0;
	ml->spinlock_entered[2] = 0;
	ml->spinlock_entered[3] = 0;
	ml->spinlock_entered[4] = 0;
	ml->spinlock_entered[5] = 0;
	ml->spinlock_entered[6] = 0;
	ml->spinlock_entered[7] = 0;

}

/* should be called from tsai_spy_init() */
void tsai_spy_mem_log_global_init(void) {
	tsai_pending_pool_init();
}
