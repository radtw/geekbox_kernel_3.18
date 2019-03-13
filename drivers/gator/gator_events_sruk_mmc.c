/*
 * Example events provider
 *
 * Copyright (C) ARM Limited 2010-2015. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Similar entries to those below must be present in the events.xml file.
 * To add them to the events.xml, create an events-mmap.xml with the
 * following contents and rebuild gatord:
 *
 * <category name="mmapped">
 *   <event counter="mmapped_cnt0" title="Simulated1" name="Sine" display="maximum" class="absolute" description="Sort-of-sine"/>
 *   <event counter="mmapped_cnt1" title="Simulated2" name="Triangle" display="maximum" class="absolute" description="Triangular wave"/>
 *   <event counter="mmapped_cnt2" title="Simulated3" name="PWM" display="maximum" class="absolute" description="PWM Signal"/>
 * </category>
 *
 * When adding custom events, be sure to do the following:
 * - add any needed .c files to the gator driver Makefile
 * - call gator_events_install in the events init function
 * - add the init function to GATOR_EVENTS_LIST in gator_main.c
 * - add a new events-*.xml file to the gator daemon and rebuild
 *
 * Troubleshooting:
 * - verify the new events are part of events.xml, which is created when building the daemon
 * - verify the new events exist at /dev/gator/events/ once gatord is launched
 * - verify the counter name in the XML matches the name at /dev/gator/events
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/ratelimit.h>
#include <linux/module.h>
#include <linux/mmc/core.h>

#include <trace/events/block.h>


#include "gator.h"

/*======================================================================================================*/

void gator_annotate_channel_color_ts(int channel, int color, const char *str, u64* ts, int* ppid);
void gator_annotate_channel_end(int channel);

#define TSAI_ATOMIC_OP_RETURN(op, asm_op)				\
static inline int tsai_atomic_##op##_return(int i, atomic_t *v)		\
{									\
	unsigned long tmp;						\
	int result;							\
									\
	smp_mb();							\
	prefetchw(&v->counter);						\
									\
	__asm__ __volatile__("@ atomic_" #op "_return\n"		\
"1:	ldrex	%0, [%3]\n"						\
"	" #asm_op "	%0, %0, %4\n"					\
"	strex	%1, %0, [%3]\n"						\
"	teq	%1, #0\n"						\
"	bne	1b"							\
	: "=&r" (result), "=&r" (tmp), "+Qo" (v->counter)		\
	: "r" (&v->counter), "Ir" (i)					\
	: "cc");							\
									\
	smp_mb();							\
									\
	return result;							\
}

TSAI_ATOMIC_OP_RETURN(and, and);
TSAI_ATOMIC_OP_RETURN(or, orr);

struct TSAI_PENDING_MESSAGE {
	char* msg; /* allocated by kmalloc */
	int channel; /* always 0*/
	unsigned int color;
	u64 ts_begin;
	u64 ts_end;
	spinlock_t lock;
};

#define MAX_PEND_MSG_COUNT (128)
#define MAX_PEND_MSG_LEN (64)
struct TSAI_PENDING_MESSAGE pend_msg[MAX_PEND_MSG_COUNT];
atomic_t pend_msg_r;
atomic_t pend_msg_w;


void tsai_push_pend_msg(int channel, unsigned int color, u64 ts_begin, u64 ts_end, const char* fmt, ...) {
	va_list args;
	int i;
	unsigned long flags;
	struct TSAI_PENDING_MESSAGE* m;
	int cur = atomic_inc_return(&pend_msg_w);
	tsai_atomic_and_return(MAX_PEND_MSG_COUNT-1, &pend_msg_w);
	m = & pend_msg[cur];
	va_start(args, fmt);
	spin_lock_irqsave(&m->lock, flags);
	m->channel = channel;
	m->color = color;
	m->ts_begin = ts_begin;
	m->ts_end = ts_end;
	if (!m->msg)
		m->msg = kmalloc(MAX_PEND_MSG_LEN, GFP_KERNEL| GFP_ATOMIC);

	i = vsnprintf((char*)m->msg, MAX_PEND_MSG_LEN, fmt, args);
	if (i >= MAX_PEND_MSG_LEN)
		m->msg[MAX_PEND_MSG_LEN-1] = 0;

	spin_unlock_irqrestore(&m->lock, flags);
	va_end(args);
}

void tsai_pop_pend_msg(void) {
	unsigned long flags;
	struct TSAI_PENDING_MESSAGE* m;
	while(1) {
		int w = atomic_read(&pend_msg_w);
		int r = atomic_inc_return(&pend_msg_r);
		tsai_atomic_and_return(MAX_PEND_MSG_COUNT-1, &pend_msg_r);
		if (r == w)
			break;

		m = & pend_msg[r];
		spin_lock_irqsave(&m->lock, flags);

		spin_unlock_irqrestore(&m->lock, flags);
	}
}

void tsai_pend_msg_init(void) {
	int i;
	for (i=0; i<MAX_PEND_MSG_COUNT; i++) {
		spin_lock_init(&pend_msg[i].lock);
	}
}

/*======================================================================================================*/

#define sruk_COUNTERS_NUM 0

#if 0
static struct {
	unsigned long enabled;
	unsigned long key;
} sruk_counters[sruk_COUNTERS_NUM];
#endif

struct SRUK_DS5_ACTIVITY {
	unsigned long enabled;
	unsigned long key;
};
static struct SRUK_DS5_ACTIVITY sruk_activity;
static struct SRUK_DS5_ACTIVITY sruk_sdp_mmc_activity;
static struct SRUK_DS5_ACTIVITY sruk_sdp_unzip_activity;


static int sruk_buffer[sruk_COUNTERS_NUM * 2]; /* key and value */

/* export symbols so that gator can retrieve memory infomation as well */

/* export symbols so that gator can retrieve memory infomation as well */
struct sruk_mali_kctx_mem_prof_streamline {
	unsigned int version; /* version of this structure */
	unsigned int size; /* size of this structure */
	unsigned int mali_kctx_used_page_byte; /* current mali used memory */
	unsigned int mali_histogram_byte; /* current mali limitation */
	unsigned int mali_hoard_byte;
};


struct MMC_REQ_NODE {
	struct rb_node rb;
	struct request *rq;
};

struct SRUK_MMC {
	atomic_t count;
	unsigned int pid;
	spinlock_t lock;
	struct rb_root req_root; /* now use a RB-tree to look for API entry */

	struct mmc_request *sdp_mrq;
} sruk_mmc;


GATOR_DEFINE_PROBE(tsai_sdp_mmch_request, TP_PROTO(struct mmc_host *host, struct mmc_request *mrq)) {
#if 0
	/* TSAI: 20181212
	 * there are observed sdp_mrp overlap, check later*/
	if (sruk_mmc.sdp_mrq)
		__asm("bkpt");
#endif

	sruk_mmc.sdp_mrq = mrq;
	gator_marshal_activity_switch(0, sruk_sdp_mmc_activity.key, 1, current->pid);

}

GATOR_DEFINE_PROBE(tsai_sdp_mmch_isr, TP_PROTO(int irq, void *dev_id, struct mmc_request *mrq)) {
	if (sruk_mmc.sdp_mrq && sruk_mmc.sdp_mrq==mrq) {
		sruk_mmc.sdp_mrq = 0;
		gator_marshal_activity_switch(0, sruk_sdp_mmc_activity.key, 0, 0);
	}
}


/* to set a breakpoint, function name is probe_block_rq_issue */
GATOR_DEFINE_PROBE(block_rq_issue, TP_PROTO(struct request_queue *q, struct request *rq)) {
	int first;
	struct MMC_REQ_NODE* n;
	n = kzalloc(sizeof(struct MMC_REQ_NODE), GFP_KERNEL );
	n->rq = rq;
	spin_lock(&sruk_mmc.lock);
	first = atomic_inc_return(&sruk_mmc.count);
	if (first == 1) {
		sruk_mmc.pid = current->pid;
		gator_marshal_activity_switch(0, sruk_activity.key, 1, sruk_mmc.pid);
	}
	{
			struct rb_node **pnew;
			struct MMC_REQ_NODE* parent = NULL;
			pnew = &sruk_mmc.req_root.rb_node;
			while (*pnew) {
				parent = (struct MMC_REQ_NODE*)*pnew;
				if (rq < parent->rq)
					pnew = &parent->rb.rb_left;
				else
					pnew = &parent->rb.rb_right;
			}

			rb_link_node(&n->rb, &parent->rb, pnew);
			rb_insert_color(&n->rb, &sruk_mmc.req_root); /* insert is already done, change color, or rotate if necessary */
	}
	spin_unlock(&sruk_mmc.lock);
}

GATOR_DEFINE_PROBE(block_rq_complete, TP_PROTO(struct request_queue *q, struct request *rq, unsigned int nr_bytes))
{
	struct MMC_REQ_NODE* found = 0;
	spin_lock(&sruk_mmc.lock);
	{
		struct MMC_REQ_NODE* n = (struct MMC_REQ_NODE*)sruk_mmc.req_root.rb_node;

		while (n) {
			if (rq > n->rq) {
				n = (struct MMC_REQ_NODE*)n->rb.rb_right;
			}
			else if (rq < n->rq) {
				n = (struct MMC_REQ_NODE*)n->rb.rb_left;
			}
			else {
				found = n;
				break;
			}
		}
	}
	if (found) {
		rb_erase(&found->rb, &sruk_mmc.req_root);
		kfree(found);
		if (atomic_dec_return(&sruk_mmc.count)==0) {
			gator_marshal_activity_switch(0, sruk_activity.key, 0, 0);
			sruk_mmc.pid = 0;
		}
	}
	spin_unlock(&sruk_mmc.lock);
}

GATOR_DEFINE_PROBE(sched_switch, TP_PROTO(struct task_struct *prev, struct task_struct *next))
{

}




/* success: hard coded to be true,
 * within this function, rq is already locked, it's not ok to place any deferred work, etc.
 *
 *  */
GATOR_DEFINE_PROBE(sched_wakeup, TP_PROTO(struct task_struct *p, int success))
{
	if (p->in_iowait) {
#if 0
		int pid = p->pid;
		gator_annotate_channel_color_ts(0, 0x00FFFF88, "RQ", NULL, &pid);
		gator_annotate_channel_end(0);
#endif
	}
}

GATOR_DEFINE_PROBE(cpu_idle, TP_PROTO(unsigned int state, unsigned int cpu))
{
/* in our platform this tracepoint is never called */
}


GATOR_DEFINE_PROBE(tsai_sdp_unzip_start, TP_PROTO(unsigned int input_bytes, unsigned int output_bytes))
{
	if (sruk_sdp_unzip_activity.enabled) {
		pid_t pid = current->pid;
		gator_marshal_activity_switch(0, sruk_sdp_unzip_activity.key, 1, pid);
	}

}
GATOR_DEFINE_PROBE(tsai_sdp_unzip_isr, TP_PROTO(unsigned int output_bytes))
{
	if (sruk_sdp_unzip_activity.enabled) {
		gator_marshal_activity_switch(0, sruk_sdp_unzip_activity.key, 0, 0);
	}
}


/* streamline may call this function to retrieve memory statistics info */
typedef void (*ptr_sruk_mali_kctxmem_prof_streamline_read) (struct sruk_mali_kctx_mem_prof_streamline* info);
static ptr_sruk_mali_kctxmem_prof_streamline_read sruk_mali_kctxmem_prof_streamline_read;

/* Adds sruk_cntX directories and enabled, event, and key files to /dev/gator/events */
static int gator_events_sruk_create_files(struct super_block *sb,
					     struct dentry *root)
{
	int i;

	{
		char buf[32];
		struct dentry *dir;

		sprintf(buf, "sruk_mmc_busy");
		dir = gatorfs_mkdir(sb, root, buf);
		if (WARN_ON(!dir))
			return -1;
		gatorfs_create_ulong(sb, dir, "enabled",
				     &sruk_activity.enabled);
		gatorfs_create_ro_ulong(sb, dir, "key",
					&sruk_activity.key);
	}
	{
		char buf[32];
		struct dentry *dir;

		sprintf(buf, "sruk_sdp_mmc_busy");
		dir = gatorfs_mkdir(sb, root, buf);
		if (WARN_ON(!dir))
			return -1;
		gatorfs_create_ulong(sb, dir, "enabled",
				     &sruk_sdp_mmc_activity.enabled);
		gatorfs_create_ro_ulong(sb, dir, "key",
					&sruk_sdp_mmc_activity.key);
	}
	{
		char buf[32];
		struct dentry *dir;

		sprintf(buf, "sruk_sdp_unzip_busy");
		dir = gatorfs_mkdir(sb, root, buf);
		if (WARN_ON(!dir))
			return -1;
		gatorfs_create_ulong(sb, dir, "enabled",
				     &sruk_sdp_unzip_activity.enabled);
		gatorfs_create_ro_ulong(sb, dir, "key",
					&sruk_sdp_unzip_activity.key);
	}

#if 0
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		char buf[32];
		struct dentry *dir;

		snprintf(buf, sizeof(buf), "sruk_malimemcnt%d", i);
		dir = gatorfs_mkdir(sb, root, buf);
		if (WARN_ON(!dir))
			return -1;
		gatorfs_create_ulong(sb, dir, "enabled",
				     &sruk_counters[i].enabled);
		gatorfs_create_ro_ulong(sb, dir, "key",
					&sruk_counters[i].key);
	}
#endif

	return 0;
}

static int gator_events_sruk_start(void)
{
	int i;

	atomic_set(&sruk_mmc.count, 0);
	sruk_mmc.sdp_mrq = 0;
	if (GATOR_REGISTER_TRACE(cpu_idle)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(sched_switch)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(sched_wakeup)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(block_rq_issue)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(block_rq_complete)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(tsai_sdp_mmch_request)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(tsai_sdp_mmch_isr)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(tsai_sdp_unzip_start)) {
		goto Leave;
	}
	if (GATOR_REGISTER_TRACE(tsai_sdp_unzip_isr)) {
		goto Leave;
	}


#if 0
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		if (sruk_counters[i].enabled) {
			sruk_mmc_enabled = 1;
			break;
		}
	}

	/* obtain function pointer address */
	if (!sruk_mali_kctxmem_prof_streamline_read) {
		sruk_mali_kctxmem_prof_streamline_read = (ptr_sruk_mali_kctxmem_prof_streamline_read)symbol_get(sruk_mali_kctxmem_prof_streamline_read);
	}
#endif
Leave:
	return 0;
}

static void gator_events_sruk_stop(void)
{
	GATOR_UNREGISTER_TRACE(cpu_idle);
	GATOR_UNREGISTER_TRACE(sched_switch);
	GATOR_UNREGISTER_TRACE(sched_wakeup);
	GATOR_UNREGISTER_TRACE(block_rq_issue);
	GATOR_UNREGISTER_TRACE(block_rq_complete);
	GATOR_UNREGISTER_TRACE(tsai_sdp_mmch_request);
	GATOR_UNREGISTER_TRACE(tsai_sdp_mmch_isr);
	GATOR_UNREGISTER_TRACE(tsai_sdp_unzip_start);
	GATOR_UNREGISTER_TRACE(tsai_sdp_unzip_isr);
	spin_lock(&sruk_mmc.lock);
	{
		struct MMC_REQ_NODE* node;
		struct MMC_REQ_NODE* n;
		struct rb_root* root;
		root = &sruk_mmc.req_root;
		rbtree_postorder_for_each_entry_safe(node, n, root, rb) {
			kfree(node);
		}
		root->rb_node = 0;
	}
	spin_unlock(&sruk_mmc.lock);
	sruk_mmc.sdp_mrq = 0;
}

static int gator_events_sruk_mmc_read(int **buffer, bool sched_switch)
{
	int len = 0;
	struct sruk_mali_kctx_mem_prof_streamline mali_info;

	//tsai_pop_pend_msg(); /* if any pending message, flush them! */
#if 0
	/* System wide counters - read from one core only */
	if (!on_primary_core() || !sruk_mmc_enabled)
		return 0;
	if (!sruk_mali_kctxmem_prof_streamline_read) {
		goto Leave;
	}

	sruk_mali_kctxmem_prof_streamline_read(&mali_info);

	/* mali limit */
	if (sruk_counters[0].enabled) {
		sruk_buffer[len++] = sruk_counters[0].key;
		sruk_buffer[len++] = mali_info.mali_kctx_used_page_byte;
	}
	/* mali usage */
	if (sruk_counters[1].enabled) {
		sruk_buffer[len++] = sruk_counters[1].key;
		sruk_buffer[len++] = mali_info.mali_histogram_byte;
	}
	/* hoard */
	if (sruk_counters[2].enabled) {
		sruk_buffer[len++] = sruk_counters[2].key;
		sruk_buffer[len++] = mali_info.mali_hoard_byte;
	}
#endif
#if 0
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		if (sruk_counters[i].enabled) {
			sruk_buffer[len++] = sruk_counters[i].key;
			sruk_buffer[len++] =
			    sruk_simulate(i, delta_in_us);
		}
	}


	if (buffer)
		*buffer = sruk_buffer;

Leave:
#endif
	return len;
}

static struct gator_interface gator_events_sruk_interface = {
	.create_files = gator_events_sruk_create_files,
	.start = gator_events_sruk_start,
	.stop = gator_events_sruk_stop,
	.read = gator_events_sruk_mmc_read,
};

/* Must not be static! */
/* TSAI: don't put init keyword here */
int gator_events_sruk_mmc_init(void)
{
	int i;

	tsai_pend_msg_init();
	spin_lock_init(&sruk_mmc.lock);

	{
		sruk_activity.enabled = 0;
		sruk_activity.key = gator_events_get_key();
		sruk_sdp_mmc_activity.enabled = 0;
		sruk_sdp_mmc_activity.key = gator_events_get_key();
	}

#if 0
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		sruk_counters[i].enabled = 0;
		sruk_counters[i].key = gator_events_get_key();
	}
#endif

	return gator_events_install(&gator_events_sruk_interface);
}
