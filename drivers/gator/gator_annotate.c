/**
 * Copyright (C) ARM Limited 2010-2015. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/spinlock.h>

#ifdef TSAI
#undef TSAI
#endif
#define TSAI 1

#if TSAI_IRQ_ATOMIC
	extern int tsai_alloc_ds5_irq_workqueue(void);
#endif

/* introduce ioctl handler so that there are extra functionality available,
 * such as take raw image without unnecessary copy */
#define TSAI_IOCTL 1

#define TSAI_SPINLOCK_IRQ 1
#if 0 && TSAI /* -O0 not possible because it will need Unknown symbol ____ilog2_NaN */
	#pragma GCC optimize ("O1")
#endif


#if TSAI
DEFINE_SPINLOCK(annotate_lock);
#else
static DEFINE_SPINLOCK(annotate_lock);
#endif

#if TSAI_SPINLOCK_IRQ
unsigned long annotate_lock_flags;
#endif

#if TSAI
bool collect_annotations;
#else
static bool collect_annotations;
#endif
#if TSAI
static int tsai_signal_pending_msg_print_once;
#endif

static int annotate_copy(struct file *file, char const __user *buf, size_t count)
{
	int cpu = 0;
	int write = per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF];

	if (file == NULL) {
		/* copy from kernel */
		memcpy(&per_cpu(gator_buffer, cpu)[ANNOTATE_BUF][write], buf, count);
	} else {
		/* copy from user space */
		if (copy_from_user(&per_cpu(gator_buffer, cpu)[ANNOTATE_BUF][write], buf, count) != 0)
			return -1;
	}
	per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF] = (write + count) & gator_buffer_mask[ANNOTATE_BUF];

	return 0;
}

#if TSAI

/* timestamp: if not NULL, overwrite timestamp
 * ppid: if not NULL, overwrite pid*/
static ssize_t annotate_write_ts(struct file *file, char const __user *buf, size_t count_orig, loff_t *offset, u64* timestamp, int* ppid);

static ssize_t annotate_write(struct file *file, char const __user *buf, size_t count_orig, loff_t *offset) {
	/* annotate_write() is the place when user side write an annotation
	 * so if collect_annotations==0, return early
	 * */
	if (!collect_annotations) { /* TSAI: use collect_annotations more appropriate*/
		return count_orig;
	}
	return annotate_write_ts(file, buf, count_orig, offset, NULL, NULL);
}

/*TSAI: 20200519, caller has already called spinlock, so skip spinlock in this function */
static ssize_t annotate_write_ts(struct file *file, char const __user *buf, size_t count_orig, loff_t *offset, u64* timestamp, int* ppid)
#else
static ssize_t annotate_write(struct file *file, char const __user *buf, size_t count_orig, loff_t *offset)
#endif
{
	int pid, cpu, header_size, available, contiguous, length1, length2, size, count = count_orig & 0x7fffffff;
	bool interrupt_context;
#if TSAI
	int tsai_preempt_count = preempt_count();
	/* this only examine whether this is a user mode address, not whether it's already on MMU */
	bool is_user_mem = access_ok(VERIFY_READ, buf, sizeof(void*)); 
#endif
	if (*offset) {
		return -EINVAL;
	}

	interrupt_context = in_interrupt();
	/* Annotations are not supported in interrupt context, but may work
	 * if you comment out the the next four lines of code. By doing so,
	 * annotations in interrupt context can result in deadlocks and lost
	 * data.
	 */
	if (interrupt_context) {
#if TSAI_SPINLOCK_IRQ
		/* do nothing, allow interrupt context*/
#else
		pr_warning("gator: Annotations are not supported in interrupt context. Edit gator_annotate.c in the gator driver to enable annotations in interrupt context.\n");
		return -EINVAL;
#endif
	}

#if TSAI
	if (tsai_preempt_count > 1) {
//		__asm("bkpt");
	}
#endif

retry:
#if TSAI 
/* 2020-05-18: once interrupt is disabled, data abort cannot happen , if this is a memory tight embedded system and we try to access user buffer directly
 * now it is the last chance trigger data abort 
 * still not working, so for now use copy_from_user. If going through annotate_ioctl, there will be no struct file *file
 * annotate_copy determine whether this is a kernel/user memory by check file,
 * so making a dummy file for now
 * */
	if(is_user_mem) {
		//tsai_user_mem_temp = *(uint32_t*)(buf);
		file = (struct file*) 0x1;
	}
#endif
	/* synchronize between cores and with collect_annotations */
#if TSAI_SPINLOCK_IRQ
		spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
		spin_lock(&annotate_lock);
#endif

	/* Annotation only uses a single per-cpu buffer as the data must be in order to the engine */
	cpu = 0;

#if TSAI
	if (ppid) {
		pid = *ppid;
	}
	else {
		if (current == NULL)
			pid = 0;
		else
			pid = current->pid;
	}
#else
	if (current == NULL)
		pid = 0;
	else
		pid = current->pid;
#endif


	/* determine total size of the payload */
	header_size = MAXSIZE_PACK32 * 3 + MAXSIZE_PACK64;
	available = buffer_bytes_available(cpu, ANNOTATE_BUF) - header_size;
	size = count < available ? count : available;

	if (size <= 0) {
		/* Buffer is full, wait until space is available */
#if TSAI_SPINLOCK_IRQ
		spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
		spin_unlock(&annotate_lock);
#endif

		/* Drop the annotation as blocking is not allowed in interrupt context */
		if (interrupt_context)
			return -EINVAL;
		/* TSAI comment: wait until a condition is met. wake_up need to be called in other threads to access this condition
		 * */
		wait_event_interruptible(gator_annotate_wait, buffer_bytes_available(cpu, ANNOTATE_BUF) > header_size || !collect_annotations);

		/* Check to see if a signal is pending */
		if (signal_pending(current))
#if TSAI
		{
			if (!tsai_signal_pending_msg_print_once++) {
				/* when coming here, there is no buffer space left, so something must have went wrong */
			    pr_info("TSAI gator: available=%d size=%d signal pending @%d\n", available, size, __LINE__);
			    __asm("hlt #0");
			    return -EINTR;
			}
		}
#else
			return -EINTR;
#endif
		goto retry;
	}

	/* synchronize shared variables annotateBuf and annotatePos */
	if (per_cpu(gator_buffer, cpu)[ANNOTATE_BUF]) {
#if TSAI
		u64 time;
		if (timestamp)
			time = gator_get_time_from_timestamp(*timestamp);
		else
			time = gator_get_time();
#else
		u64 time = gator_get_time();
#endif

		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, get_physical_cpu());
		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, pid);
		gator_buffer_write_packed_int64(cpu, ANNOTATE_BUF, time);
		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, size);

		/* determine the sizes to capture, length1 + length2 will equal size */
		contiguous = contiguous_space_available(cpu, ANNOTATE_BUF);
		if (size < contiguous) {
			length1 = size;
			length2 = 0;
		} else {
			length1 = contiguous;
			length2 = size - contiguous;
		}

		if (annotate_copy(file, buf, length1) != 0) {
			size = -EINVAL;
			goto annotate_write_out;
		}

		if (length2 > 0 && annotate_copy(file, &buf[length1], length2) != 0) {
			size = -EINVAL;
			goto annotate_write_out;
		}

		/* Check and commit; commit is set to occur once buffer is 3/4 full */
		buffer_check(cpu, ANNOTATE_BUF, time);
	}

annotate_write_out:
#if TSAI_SPINLOCK_IRQ
		spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
		spin_unlock(&annotate_lock);
#endif

	/* return the number of bytes written */
	return size;
}

#include "gator_annotate_kernel.c"

static int annotate_release(struct inode *inode, struct file *file)
{
	int cpu = 0;

	/* synchronize between cores */
#if TSAI_SPINLOCK_IRQ
		spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
		spin_lock(&annotate_lock);
#endif

	if (per_cpu(gator_buffer, cpu)[ANNOTATE_BUF] && buffer_check_space(cpu, ANNOTATE_BUF, MAXSIZE_PACK64 + 3 * MAXSIZE_PACK32)) {
		uint32_t pid = current->pid;

		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, get_physical_cpu());
		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, pid);
		/* time */
		gator_buffer_write_packed_int64(cpu, ANNOTATE_BUF, 0);
		/* size */
		gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, 0);
	}

	/* Check and commit; commit is set to occur once buffer is 3/4 full */
	buffer_check(cpu, ANNOTATE_BUF, gator_get_time());

#if TSAI_SPINLOCK_IRQ
		spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
		spin_unlock(&annotate_lock);
#endif

	return 0;
}

#if TSAI_IOCTL
	#include "sruk_gator_annotate_ioctl.h"

const struct file_operations tsai_annotate_fops = {
	.owner = THIS_MODULE,
	#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = annotate_ioctl,
	#else
	.ioctl = annotate_ioctl,
	#endif
	.compat_ioctl = annotate_ioctl,
	.mmap = tsai_annotate_file_mmap,
	.open = tsai_annotate_open,
	.read = tsai_annotate_read,
};

#endif

static const struct file_operations annotate_fops = {
#if TSAI_IOCTL
	#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = annotate_ioctl,
	#else
	.ioctl = annotate_ioctl,
	#endif
	.compat_ioctl = annotate_ioctl,
	.mmap = tsai_annotate_file_mmap,
#endif
	.write = annotate_write,
	.release = annotate_release
};


static int gator_annotate_create_files(struct super_block *sb, struct dentry *root)
{
#if TSAI_IRQ_ATOMIC
	tsai_alloc_ds5_irq_workqueue();
#endif
#if TSAI
	__gatorfs_create_devfile(sb, root, "annotate_tsai", &tsai_annotate_fops, 0666);
#endif
	return gatorfs_create_file_perm(sb, root, "annotate", &annotate_fops, 0666);
}

static int gator_annotate_start(void)
{
	collect_annotations = true;
#if TSAI
	tsai_signal_pending_msg_print_once = 0;
	pr_info("TSAI: gator_annotate_start() @%d\n", __LINE__);
#endif
#if TSAI_IOCTL
	//__asm("bkpt");
	tsai_annotate_start();
#endif
	return 0;
}

static void gator_annotate_stop(void)
{
	/* the spinlock here will ensure that when this function exits, we are not in the middle of an annotation */
#if TSAI_SPINLOCK_IRQ
		spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
		spin_lock(&annotate_lock);
#endif
	collect_annotations = false;
#if TSAI_IOCTL
	tsai_annotate_stop();
#endif

	wake_up(&gator_annotate_wait);
#if TSAI_SPINLOCK_IRQ
		spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
		spin_unlock(&annotate_lock);
#endif
#if TSAI
	pr_info("TSAI: gator_annotate_stop() @%d\n", __LINE__);
#endif
}

