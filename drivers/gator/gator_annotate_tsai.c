/*
 * gator_annotate_tsai.c
 *
 *  Created on: 15 Dec 2017
 *      Author: cheng.tsai
 */

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>

#include <tsai_spy_mem_log.h>

#include "gator.h"
#include "gator_annotate_tsai.h"

extern struct tsai_spy_mem_log tsai_gator_log;

/* TSAI: if annotations are used excessively, it may run-out very quick.
 * Try increase the buffer size by changing ANNOTATE_BUFFER_SIZE value
 * */

#define DBG 1

void gator_buffer_write_packed_int(int cpu, int buftype, int x);
extern u64 gator_get_time(void);
#if TSAI
	extern unsigned long gator_started;
	extern u64 gator_get_timestamp_now(void);

	extern u64 gator_get_time_from_timestamp(u64 timestamp);
	extern wait_queue_head_t gator_annotate_wait;
	extern bool buffer_check_space(int cpu, int buftype, int bytes);

	extern void tsai_lock_kannotate(unsigned long* pflags);
	extern void tsai_unlock_kannotate(unsigned long* pflags);
	extern void kannotate_write_ts(const char *ptr, unsigned int size, u64* timestamp, int* ppid);
#endif

extern spinlock_t annotate_lock;
extern bool collect_annotations;

enum {
	SUMMARY_BUF,
	BACKTRACE_BUF,
	NAME_BUF,
	COUNTER_BUF,
	BLOCK_COUNTER_BUF,
	ANNOTATE_BUF,
	SCHED_TRACE_BUF,
	IDLE_BUF,
	ACTIVITY_BUF,
	NUM_GATOR_BUFS
};

DECLARE_PER_CPU(char *[NUM_GATOR_BUFS], gator_buffer);



DEFINE_SPINLOCK(annotate_atomic_lock);
struct task_struct* atomic_lock_owner;

enum ia_type {
	IA_ANNOTATE = 0,
	IA_LOCK,
	IA_UNLOCK
};


struct ds5_irq_node
{
	enum ia_type type;
	size_t count;
	u64 timestamp;
	int pid;
	char buf[0];
};

struct ds5_irq_node_container {
	unsigned int seq_no;
	int node_cnt;
	int complete; /* when exit_lock has been done */
	struct ds5_irq_node* pnode[4]; /* annotate_visual use 4 annotate_write */
};

/* TSAI: 20181212: tasklet should be more efficient than a worker thread queue, since tasklet is handled after interrupt happen
 * so tasklet is supposed to be checked more frequently than worker thread.
 * but note tasklet is like a parasite using host's CPU resource and need to be keep short!
 *
 * tasklet handler happens on top of __irq_svc and still in atomic context, therefore it cannot wait for buffer to be consumed.
 * Therefore taskelet is not an option!
 *
 * */
struct TSAI_DS5_IRQ {
	struct ds5_irq_node_container node_fifo[256];
	spinlock_t lock;
	struct tasklet_struct ds5_irq_tl;
	struct workqueue_struct* ds5_irq_wq;
	struct work_struct irq_work;

	union {
		unsigned int read_cursor_dbg;
		atomic_t read_cursor;
	};

	union {
		unsigned int write_cursor_dbg;
		atomic_t write_cursor;
	};

	union {
		unsigned int curtail_dbg;
		atomic_t curtail;
	};

	unsigned int queue_own_atomic_lock;

	union {
		unsigned int worker_busy_dbg;
		atomic_t worker_busy;
	};

	int flag_full;

	struct ds5_irq_node_container* pending_container[8];

} tsai_ds5_irq;

static void tsai_ds5_irq_tasklet(unsigned long data) {

}

/* called from gator_annotate_create_files() in gator_annotate.c */
int tsai_alloc_ds5_irq_workqueue(void)
{
	tsai_ds5_irq.ds5_irq_wq = alloc_ordered_workqueue("tsai_ds5_irq", WQ_HIGHPRI);

	if (!tsai_ds5_irq.ds5_irq_wq)
	{
		printk("Failed to create irq_annotation_wq in alloc_irq_annotation_workqueue()\n");
		return -ENOMEM;
	}

	spin_lock_init(&tsai_ds5_irq.lock);
	tasklet_init(&tsai_ds5_irq.ds5_irq_tl, tsai_ds5_irq_tasklet, (unsigned long)0);
	tasklet_disable(&tsai_ds5_irq.ds5_irq_tl);
	tasklet_enable(&tsai_ds5_irq.ds5_irq_tl);

	printk("tsai_ds5_irq.ds5_irq_wq created\n");
	return 0;
}

void tsai_wait_for_annotate_buffer_space(unsigned int bytes) {
	unsigned int available;
	unsigned int cpu = 0;
	wait_event_interruptible(gator_annotate_wait, buffer_check_space(cpu, ANNOTATE_BUF, bytes) || !gator_started );
}

/*
 * slot_required: how many slots are required to complete a request,
 * when in tsai_annotate_enter_lock(), slot_required = 1, otherwise 0
 * return:
 * not negative: w cursor
 * -1: not enough slot available
 * */
static int tsai_obtain_w_cursor(int slot_required) {
	int ret;
	unsigned int w = atomic_read(&tsai_ds5_irq.write_cursor);
	unsigned int r = atomic_read(&tsai_ds5_irq.read_cursor);
	unsigned int avail;

	if (!slot_required && tsai_ds5_irq.flag_full) {
		ret = -1;
		goto Leave;
	}

	if (tsai_ds5_irq.curtail_dbg) {
		avail = r-w;
	}
	else {
		avail = (r+256) - w;
	}

	if (avail >= slot_required) {
		tsai_ds5_irq.write_cursor_dbg = (w + 1);
		if (tsai_ds5_irq.write_cursor_dbg >= 256) {
			tsai_ds5_irq.curtail_dbg = 256;
			tsai_ds5_irq.write_cursor_dbg &= 0xFF;
		}
		ret = (int)w;
		if (tsai_ds5_irq.flag_full)
			tsai_ds5_irq.flag_full = 0;
	}
	else {
		ret = -1;
		tsai_ds5_irq.flag_full = 1;
	}
Leave:
	return ret ;
}

static int tsai_obtain_r_cursor(void) {
	int r = atomic_read(&tsai_ds5_irq.read_cursor);
	int next_r = r+1;
	if (atomic_read(&tsai_ds5_irq.curtail)) {
		if ((next_r) >= 256) {
			next_r &= 0xFF;
			atomic_set(&tsai_ds5_irq.curtail, 0);
		}
	}
	else {
		if (next_r == atomic_read(&tsai_ds5_irq.write_cursor)) {
			r = -1;
			goto Leave;
		}

	}
	atomic_set(&tsai_ds5_irq.read_cursor, next_r);
Leave:
	return r;
}

static unsigned int tsai_last_irq_seq_no;

static void tsai_ds5_irq_worker(struct work_struct *work)
{
	//struct irq_annotation *irq_work = (struct irq_annotation *)work;
	struct ds5_irq_node* node;
	struct ds5_irq_node_container* c;
	unsigned r;
	int i;
	unsigned long atomic_lock_irqflags = 0;
	int lock_balance = 0; /* inside this function, IA_LOCK and IA_UNLOCK should be equal! */

	while (1)
	{
		/* tentative run to make sure this container is complete */
		r = atomic_read(&tsai_ds5_irq.read_cursor);
		c = &tsai_ds5_irq.node_fifo[r];
		if (!c->complete)
			break;

		r = tsai_obtain_r_cursor();
		if (r == -1)
			break;

		c = &tsai_ds5_irq.node_fifo[r];
#if DBG
		if (!c->node_cnt) BKPT;
#endif

		/* LOCK */
		{
			tsai_wait_for_annotate_buffer_space(4096);
#if DBG
			{
				unsigned int expect_seq_no = tsai_last_irq_seq_no + 1;
				if (c->seq_no != expect_seq_no)
					BKPT;

				tsai_last_irq_seq_no = expect_seq_no;
			}
#endif
			tsai_lock_kannotate(&atomic_lock_irqflags);
			tsai_ds5_irq.queue_own_atomic_lock = 1;
			lock_balance++;
		}

		for (i=0; i<c->node_cnt; i++)
		{
			int pid, cpu, header_size, available, contiguous, length1, length2, size, count;
			node = c->pnode[i];

			count = node->count & 0x7fffffff;
			if (!tsai_ds5_irq.queue_own_atomic_lock) {
				BKPT;
			}
			kannotate_write_ts(&node->buf[0] , node->count, &node->timestamp, &node->pid);
			kfree((void *)node);
			c->pnode[i] = 0;
		}
		/* Unlock */
		{
			tsai_ds5_irq.queue_own_atomic_lock = 0;
			tsai_unlock_kannotate(&atomic_lock_irqflags);
			lock_balance--;
		}
		c->seq_no = 0;
		c->node_cnt = 0;
		c->complete = 0;
	}

	atomic_set(&tsai_ds5_irq.worker_busy, 0);

	if (lock_balance) { /* expected to be 0 */
		BKPT;
	}
}

int tsai_schedule_ds5_irq_annotate(char const *buf, size_t count_orig, u64* timestamp, int* ppid, unsigned int seq_no) {
	if(tsai_ds5_irq.ds5_irq_wq)
	{
		int cpu_id = smp_processor_id();
		struct ds5_irq_node_container* c = tsai_ds5_irq.pending_container[cpu_id];
		if (c) {
			struct ds5_irq_node *node = (struct ds5_irq_node *)kmalloc(sizeof(struct ds5_irq_node)+count_orig, GFP_ATOMIC); // use GFP_ATOMIC rather than GFP_KERNEL to avoid possible scheduling-while-atomic problems.
#if DBG
			if (c->seq_no != seq_no)
				BKPT;
			if (c->node_cnt >= 4)
				BKPT;
#endif
			if(node)
			{
				node->type = IA_ANNOTATE;

				if (timestamp)
					node->timestamp = *timestamp;
				else
					node->timestamp = gator_get_timestamp_now();
				node->count=count_orig;

				if (ppid) {
					node->pid = *ppid;
				}
				else {
					if (current == NULL) {
						node->pid=0;
					} else {
						node->pid = current->pid;
					}
				}
				memcpy(&node->buf[0], buf, count_orig); // this memcpy is safe, as we never actually get an __user pointer (this is only called in interrupt context)

				c->pnode[c->node_cnt++] = node;

				return 0;
			}
		}
	}
	return -1;
}

void tsai_annotate_enter_lock(int cpu_id, unsigned int seq_no) {
	bool interrupt_context = in_interrupt();
	if (interrupt_context) {
		int w = tsai_obtain_w_cursor(1);
		if (w != -1) {
			struct ds5_irq_node_container* c = &tsai_ds5_irq.node_fifo[w];
			c->seq_no = seq_no;
			c->node_cnt = 0;
			c->complete = 0;
			tsai_ds5_irq.pending_container[cpu_id] = c;
		}
	}
}

void tsai_annotate_exit_lock(int cpu_id, unsigned int seq_no) {
	bool interrupt_context = in_interrupt();
	if (interrupt_context) {
		struct ds5_irq_node_container* c = tsai_ds5_irq.pending_container[cpu_id];
		if (c) {
#if DBG
			if (c->seq_no != seq_no)
				BKPT;
#endif
			c->complete = 1;
			if (atomic_read(&tsai_ds5_irq.worker_busy)==0) {
				INIT_WORK((struct work_struct*)&tsai_ds5_irq.irq_work, tsai_ds5_irq_worker);
				queue_work(tsai_ds5_irq.ds5_irq_wq, &tsai_ds5_irq.irq_work);
				atomic_set(&tsai_ds5_irq.worker_busy, 1);
				//tasklet_schedule(&tsai_ds5_irq.ds5_irq_tl);
			}
			tsai_ds5_irq.pending_container[cpu_id] = 0;
		}
	}
}

/*==== TSAI: Buffer Status =========================================================================*/

#include "tsai_rb_node_array.h"

extern u64 gator_annotate_get_ts(void);
extern void gator_annotate_channel_color_ts(int channel, int color, const char *str, u64* ts, int* ppid);
extern void gator_annotate_channel_end_ts_pid(int channel, u64* ts, int* ppid);
extern void gator_annotate_name_group_pid(int group, const char *str, int* ppid);
extern void gator_annotate_name_channel_pid(int channel, int group, const char *str, int* ppid);

extern unsigned int tsai_gator_started(void);
extern unsigned long gator_started;

#define ANNOTATE_WHITE  0xffffff1b
#define ANNOTATE_LTGRAY 0xbbbbbb1b

#define TSAI_CH_OS_VSYNC  (64000)
#define TSAI_CH_BUF_OWNED (64001)
#define TSAI_GROUP  (2)

#define MAX_BUF_ANNOTATION (64) //how many buffers are likely to be annotated at the same time?

struct TBUFANNO {
	struct ts_rba rb;
	uint32_t channel;
};

struct TSAI_BUFINFO {
	struct rb_root req_root; /* rb tree to find buffer record based on buffer name */
	unsigned int fOsHdr : 1;
	struct TBUFANNO* buf_anno[MAX_BUF_ANNOTATION];
	struct TSAI_RBA rta;
	uint32_t slot_free_stack[MAX_BUF_ANNOTATION];
	uint32_t slot_used;
	uint32_t slot_used_max;

	struct TBUFANNO* dbg_chan_map[MAX_BUF_ANNOTATION]; //debug only
	spinlock_t lock;
}
tsai_bufinfo = {
	.rta = {
		.pRBAptr = (struct ts_rba**) tsai_bufinfo.buf_anno,
		.max_count = MAX_BUF_ANNOTATION,
		.lock = __SPIN_LOCK_UNLOCKED(lock),
	},
	.lock = __SPIN_LOCK_UNLOCKED(lock),
};

/* uint64_t os_ts: OS timestamp:
 * seqno: optional seqno provided by the OS */
void tsai_bufinfo_os_vsync(uint64_t os_ts, u32 seqno) {
	pid_t pid = 0;
	unsigned int color;
	static int color_ix;
	u64 ts = gator_annotate_get_ts();
	color_ix = (color_ix+1) & 1;
	color = color_ix? ANNOTATE_WHITE: ANNOTATE_LTGRAY;
	gator_annotate_channel_color_ts(TSAI_CH_OS_VSYNC, color, "", &ts, &pid);

}

static uint32_t tsai_bufinfo_get_free_slot(struct TBUFANNO* bi) {
	int ret = 0;
	bool expand_channel = false;
	spin_lock(&tsai_bufinfo.lock);
	ret = tsai_bufinfo.slot_free_stack[tsai_bufinfo.slot_used++];
	bi->channel = ret;

	if (tsai_bufinfo.dbg_chan_map[ret]) {
		pr_info("this is error @%d", __LINE__);
	}
	tsai_bufinfo.dbg_chan_map[ret] = bi;

	if (tsai_bufinfo.slot_used > tsai_bufinfo.slot_used_max) {
		tsai_bufinfo.slot_used_max = tsai_bufinfo.slot_used;
		expand_channel = true;
	}
	spin_unlock(&tsai_bufinfo.lock);

	//name this channel
	if (expand_channel) {
		char msg[16];
		pid_t pid = 0;
		sprintf(msg, "BufOwned #%d", ret);
		gator_annotate_name_channel_pid(TSAI_CH_BUF_OWNED+ret, TSAI_GROUP, msg, &pid);
	}

	return ret;
}

static void tsai_bufinfo_put_free_slot(struct TBUFANNO* bi) {
	spin_lock(&tsai_bufinfo.lock);
	tsai_bufinfo.dbg_chan_map[bi->channel] = 0;
	tsai_bufinfo.slot_free_stack[--tsai_bufinfo.slot_used] = bi->channel;
	spin_unlock(&tsai_bufinfo.lock);

}

/* owner: now always 1, Android surfacefling
 * buf: gem/ion name of the buffer
 * on_off: 1=owned, 0=released
 * */
void tsai_bufinfo_owner(uint32_t owner, uint32_t buf, uint32_t on_off) {
#if 1
	if (1 || gator_started) {
		pid_t pid = 0;
		u64 ts = gator_annotate_get_ts();

		if (on_off) { /* On */
			char msg[32];
			struct TBUFANNO* bi = kzalloc(sizeof(struct TBUFANNO), GFP_KERNEL);
			bi->rb.key = buf;
			tsai_bufinfo_get_free_slot(bi);
			TSAI_RBA_insert(&tsai_bufinfo.rta, &bi->rb);
			snprintf(msg, sizeof(msg), "I%d", buf);
			gator_annotate_channel_color_ts(TSAI_CH_BUF_OWNED + bi->channel, ANNOTATE_WHITE, msg, &ts, &pid);
		}
		else { /* Off */
			struct TBUFANNO* bi  = (struct TBUFANNO*)TSAI_RBA_find_by_key(&tsai_bufinfo.rta, buf);
			if (bi) {
				gator_annotate_channel_end_ts_pid(TSAI_CH_BUF_OWNED + bi->channel, &ts, &pid);
				tsai_bufinfo_put_free_slot(bi);
				TSAI_RBA_remove_by_key(&tsai_bufinfo.rta, buf);
			}
		}
	}
#endif
}

/* called from tsai_annotate_start() */
void tsai_bufinfo_capture_start(void) {
	int i;
	tsai_bufinfo.fOsHdr = 0;

	if (!tsai_bufinfo.fOsHdr) {
		pid_t pid = 0;
		//ANNOTATE_NAME_GROUP_PID(1, "Buff Status", &pid);
		gator_annotate_name_group_pid(TSAI_GROUP, "GraphicsStatus", &pid);

		//ANNOTATE_NAME_CHANNEL_PID(TSAI_CH_OS_VSYNC, 1, "V-Sync", &pid);
		gator_annotate_name_channel_pid(TSAI_CH_OS_VSYNC, TSAI_GROUP, "OS VSync", &pid);

		tsai_bufinfo.slot_used_max = 0;
		tsai_bufinfo.fOsHdr = 1;
	}

}

void tsai_bufinfo_capture_stop(void) {


}

/* ====================================== */

struct GATOR_DATA_USER_SHARE* tsai_gator_user_share;
unsigned long long tsai_gator_user_share_paddr;
unsigned int tsai_gator_read_prepared;

static const char tsai_gator_dev_name[] = "gator_annotate_tsai";

extern const struct file_operations tsai_annotate_fops; /* instance in gator_annotate.c */

//read the annotation log to user space, eg
//cat /dev/gator_annotate_tsai
ssize_t tsai_annotate_read(struct file *f, char __user *buf, size_t count_orig, loff_t *offset) {
	ssize_t ret = 0;
	if (! gator_started) { //only allow to read log when it's not in capture session
		if (!tsai_gator_read_prepared) { /* after each capture session, need to do prepare again */
			tsai_spy_mem_log_read_prepare(&tsai_gator_log);
			tsai_gator_read_prepared = 1;
		}
		ret = tsai_spy_mem_log_read(&tsai_gator_log, buf, count_orig);
	}
	return ret;
}

static struct miscdevice tsai_gator_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &tsai_annotate_fops,
	.name = tsai_gator_dev_name,
    .parent = NULL,
	.mode = S_IRUGO|S_IWUGO,
};


static int tsai_register_chardev(void) {
	int ret;
	//__asm("bkpt");
	ret = misc_register(&tsai_gator_dev);
	if (ERR_PTR(ret)) {
		pr_info("failed to create tsai_gator device");
		return -1;
	}

	//examine the file mode here
#if 0
	{
		struct file* f = filp_open("/dev/gator_annotate_tsai", O_RDWR, 0);
		if (f && !ERR_PTR(f)) {
			filp_close(f, (fl_owner_t)current->pid);
		}
	}
#endif

	return 0;
}

//called from gator_module_init > gator_init > tsai_annotate_init
int tsai_annotate_init(void) {
	int i;
	struct page* pg;
	tsai_register_chardev();
	tsai_gator_user_share = (struct GATOR_DATA_USER_SHARE*)vmalloc_user(4096);

	pg = vmalloc_to_page( (const void *) tsai_gator_user_share);
	tsai_gator_user_share_paddr = page_to_phys(pg);

	tsai_gator_user_share->id = 'G' | 'A'<<8 | 'T'<<16 | 'R' <<24;

	//initialize bufinfo
	//populate free slot;
	for (i=0; i<MAX_BUF_ANNOTATION; i++) {
		tsai_bufinfo.slot_free_stack[i] = i;
	}

	return 0;
}


void tsai_annotate_start(void) {
	if (tsai_gator_user_share)
		tsai_gator_user_share->gator_started = 1;

	tsai_gator_read_prepared = 0;
	tsai_spy_mem_log(&tsai_gator_log, "tsai_annotate_start() START capture @%s:%d\n", __FILE__, __LINE__);
	tsai_bufinfo_capture_start();
}

void tsai_annotate_stop(void) {
	if (tsai_gator_user_share)
		tsai_gator_user_share->gator_started = 0;

	tsai_spy_mem_log(&tsai_gator_log, "tsai_annotate_stop() STOP capture @%s:%d\n", __FILE__, __LINE__);
	tsai_bufinfo_capture_stop();
}

/*
-000|tsai_annotate_start()
    |
-001|gator_annotate_start()
    |
    |#if TSAI_IOCTL
    |        //__asm("bkpt");
    |        tsai_annotate_start();
-002|gator_start()
    |  cpu = 8
    |  i = 9
    |  gi = 0xFFFFFFBFFC0B9F20
    |
    |        if (gator_annotate_start())
-003|gator_op_start()
    |  err = 0
    |
    |        if (gator_started || gator_start())
-004|enable_write(
-005|vfs_write(
-006|SYSC_write(inline)
-006|sys_write(
-007|ret_fast_syscall(asm)
 */
