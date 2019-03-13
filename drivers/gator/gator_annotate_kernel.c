/**
 * Copyright (C) ARM Limited 2012-2015. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define ESCAPE_CODE 0x1c
#define STRING_ANNOTATION 0x06
#define NAME_CHANNEL_ANNOTATION 0x07
#define NAME_GROUP_ANNOTATION 0x08
#define VISUAL_ANNOTATION 0x04
#define MARKER_ANNOTATION 0x05

#if TSAI_IRQ_ATOMIC
	#define TSAI_WARPPER_SPINLOCK 1
#else
	#define TSAI_WARPPER_SPINLOCK 0
#endif
/* TSAI:
 * kannotate_write() contains multiple annotate_write
 * would it cause problem if two kannotate_write() are called at the same time
 * and their annotate_write() are interleaved?
 * so far all the clashes appears to be from the same core, so
 *
 * 20171228: spin_lock increase preempt count and may lead to
 * "BUG: scheduling while atomic" if context switch happens in between
 */

#if TSAI_WARPPER_SPINLOCK
	extern void tsai_wait_for_annotate_buffer_space(unsigned int bytes);
	extern int tsai_schedule_ds5_irq_annotate(char const *buf, size_t count_orig, u64* timestamp, int* ppid, unsigned int seq_no);
	extern void tsai_annotate_enter_lock(unsigned int seqno, int cpu_id);
	extern void tsai_annotate_exit_lock(unsigned int seqno, int cpu_id);

	/* NOTE: there is only one annotation buffer, not per CPU core, so the spinlock must be for all cores! */
#if 0
	spinlock_t wrapper_lock[8] = { __SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock"),
			__SPIN_LOCK_UNLOCKED("wrapper_lock")
	} ; /* one for each core */
#endif
	DEFINE_SPINLOCK(wrapper_lock);

	atomic_t tsai_annotate_seqno;

	//unsigned int gator_preempt_count[8];

	#define FLAGS 	int cpu_id = smp_processor_id();\
					unsigned long wrapper_irqflags = 0;\
					int gator_preempt_count=preempt_count();\
					unsigned int interrupt_context = in_interrupt();\
					unsigned int seq_no=0;\
					if (!collect_annotations) return;


	#define ENTER(size) 	if (!gator_preempt_count) {tsai_wait_for_annotate_buffer_space(size+1024);}\
							local_irq_save(wrapper_irqflags);\
							spin_lock(&wrapper_lock);\
							if (interrupt_context) { seq_no = atomic_inc_return(&tsai_annotate_seqno); tsai_annotate_enter_lock(cpu_id, seq_no); }

	#define QUIT	if (interrupt_context) { tsai_annotate_exit_lock(cpu_id, seq_no); }\
					spin_unlock(&wrapper_lock);\
					local_irq_restore(wrapper_irqflags);

	/* used in gator_annotate_tsai.c */
	void tsai_lock_kannotate(unsigned long* pflags) {
		//local_irq_save( (*pflags) );
		spin_lock_irqsave(&wrapper_lock, (*pflags));
	}
	/* used in gator_annotate_tsai.c */
	void tsai_unlock_kannotate(unsigned long* pflags) {
		/*TSAI: local_irq_restore would cause undefined instruction exception, reason unsure, so use spin_unlock_irqrestore instead */
		spin_unlock_irqrestore(&wrapper_lock, (*pflags));
		//local_irq_restore( (*pflags));
	}


#endif

#if TSAI
void kannotate_write_ts(const char *ptr, unsigned int size, u64* timestamp, int* ppid, unsigned int seq_no)
{
	int retval;
	int pos = 0;
	loff_t offset = 0;

#if TSAI_IRQ_ATOMIC
	if (in_interrupt()) {
		tsai_schedule_ds5_irq_annotate(ptr, size, timestamp, ppid, seq_no);
		return;
	}
#endif
	/* TSAI: early out clause */
	if (!collect_annotations)
		return;

	while (pos < size) {
		retval = annotate_write_ts(NULL, &ptr[pos], size - pos, &offset, timestamp, ppid);
		if (retval < 0) {
			pr_warning("gator: kannotate_write_ts failed with return value %d\n", retval);
			return;
		}
		pos += retval;
	}

}
#endif

static void kannotate_write(const char *ptr, unsigned int size)
{
	int retval;
	int pos = 0;

	loff_t offset = 0;
#if TSAI_WARPPER_SPINLOCK && TSAI
	/* TSAI: in such config, kannotate_write becomes a macro and should never eneter here, but should have been in kannotate_write_ts */
	BKPT;
#endif
#if TSAI_IRQ_ATOMIC
	if (in_interrupt()) {
		tsai_schedule_ds5_irq_annotate(ptr, size, NULL, NULL, 0);
		return;
	}
#endif

	while (pos < size) {
		retval = annotate_write(NULL, &ptr[pos], size - pos, &offset);
		if (retval < 0) {
			pr_warning("gator: kannotate_write failed with return value %d\n", retval);
			return;
		}
		pos += retval;
	}
}

static void marshal_u16(char *buf, u16 val)
{
	buf[0] = val & 0xff;
	buf[1] = (val >> 8) & 0xff;
}

static void marshal_u32(char *buf, u32 val)
{
	buf[0] = val & 0xff;
	buf[1] = (val >> 8) & 0xff;
	buf[2] = (val >> 16) & 0xff;
	buf[3] = (val >> 24) & 0xff;
}

#if TSAI_WARPPER_SPINLOCK && TSAI
#define kannotate_write(ptr, size) kannotate_write_ts(ptr, size, NULL, NULL, seq_no)
#endif

void gator_annotate_channel(int channel, const char *str)
{
	const u16 str_size = strlen(str) & 0xffff;
	char header[8];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = STRING_ANNOTATION;
	marshal_u32(header + 2, channel);
	marshal_u16(header + 6, str_size);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif
	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_channel);

void gator_annotate(const char *str)
{
	gator_annotate_channel(0, str);
}
EXPORT_SYMBOL(gator_annotate);

#if TSAI
	void tsai_install_watchpoint(void* address, unsigned int access, const char* label);
	void tsai_remove_watchpoint(void* address);
#endif

void gator_annotate_channel_color(int channel, int color, const char *str)
{
	const u16 str_size = (strlen(str) + 4) & 0xffff;
	char header[12];
#if TSAI_WARPPER_SPINLOCK && TSAI
	struct thread_info* ti = current_thread_info();
#endif
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = STRING_ANNOTATION;
	marshal_u32(header + 2, channel);
	marshal_u16(header + 6, str_size);
	marshal_u32(header + 8, color);

#if 0 && TSAI_WARPPER_SPINLOCK && TSAI
	tsai_install_watchpoint(&ti->preempt_count, 2, "preempt_count" );
#endif
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif
#if 0 && TSAI_WARPPER_SPINLOCK && TSAI
	tsai_remove_watchpoint(&ti->preempt_count);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size - 4);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_channel_color);

void gator_annotate_color(int color, const char *str)
{
	gator_annotate_channel_color(0, color, str);
}
EXPORT_SYMBOL(gator_annotate_color);

void gator_annotate_channel_end(int channel)
{
	char header[8];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = STRING_ANNOTATION;
	marshal_u32(header + 2, channel);
	marshal_u16(header + 6, 0);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_channel_end);

void gator_annotate_end(void)
{
	gator_annotate_channel_end(0);
}
EXPORT_SYMBOL(gator_annotate_end);

void gator_annotate_name_channel(int channel, int group, const char *str)
{
	const u16 str_size = strlen(str) & 0xffff;
	char header[12];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = NAME_CHANNEL_ANNOTATION;
	marshal_u32(header + 2, channel);
	marshal_u32(header + 6, group);
	marshal_u16(header + 10, str_size);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_name_channel);

void gator_annotate_name_group(int group, const char *str)
{
	const u16 str_size = strlen(str) & 0xffff;
	char header[8];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = NAME_GROUP_ANNOTATION;
	marshal_u32(header + 2, group);
	marshal_u16(header + 6, str_size);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_name_group);

void gator_annotate_visual(const char *data, unsigned int length, const char *str)
{
	const u16 str_size = strlen(str) & 0xffff;
	char header[4];
	char header_length[4];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = VISUAL_ANNOTATION;
	marshal_u16(header + 2, str_size);
	marshal_u32(header_length, length);
#if TSAI_WARPPER_SPINLOCK
	ENTER(length);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size);
	kannotate_write(header_length, sizeof(header_length));
	kannotate_write(data, length);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_visual);

void gator_annotate_marker(void)
{
	char header[4];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = MARKER_ANNOTATION;
	marshal_u16(header + 2, 0);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_marker);

void gator_annotate_marker_str(const char *str)
{
	const u16 str_size = strlen(str) & 0xffff;
	char header[4];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = MARKER_ANNOTATION;
	marshal_u16(header + 2, str_size);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_marker_str);

void gator_annotate_marker_color(int color)
{
	char header[8];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = MARKER_ANNOTATION;
	marshal_u16(header + 2, 4);
	marshal_u32(header + 4, color);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_marker_color);

void gator_annotate_marker_color_str(int color, const char *str)
{
	const u16 str_size = (strlen(str) + 4) & 0xffff;
	char header[8];
#if TSAI_WARPPER_SPINLOCK
	FLAGS;
#endif

	header[0] = ESCAPE_CODE;
	header[1] = MARKER_ANNOTATION;
	marshal_u16(header + 2, str_size);
	marshal_u32(header + 4, color);
#if TSAI_WARPPER_SPINLOCK
	ENTER(0);
#endif

	kannotate_write(header, sizeof(header));
	kannotate_write(str, str_size - 4);
#if TSAI_WARPPER_SPINLOCK
	QUIT;
#endif

}
EXPORT_SYMBOL(gator_annotate_marker_color_str);

#if TSAI_WARPPER_SPINLOCK && TSAI
#undef kannotate_write
#endif


#if TSAI /* timestamped version */
	u64 gator_annotate_get_ts(void) {
		struct timespec ts;
		u64 timestamp;
		getrawmonotonic(&ts);
		timestamp = timespec_to_ns(&ts);
		return timestamp;
	}
	EXPORT_SYMBOL(gator_annotate_get_ts);

	void gator_annotate_channel_end_ts_pid(int channel, u64* ts, int* ppid)
	{
		char header[8];
	#if TSAI_WARPPER_SPINLOCK
		FLAGS;
	#endif

		header[0] = ESCAPE_CODE;
		header[1] = STRING_ANNOTATION;
		marshal_u32(header + 2, channel);
		marshal_u16(header + 6, 0);
	#if TSAI_WARPPER_SPINLOCK
		ENTER(0);
	#endif

		kannotate_write_ts(header, sizeof(header), ts, ppid, seq_no);
	#if TSAI_WARPPER_SPINLOCK
		QUIT;
	#endif

	}
	EXPORT_SYMBOL(gator_annotate_channel_end_ts_pid);

	void gator_annotate_channel_color_ts(int channel, int color, const char *str, u64* ts, int* ppid)
	{
		const u16 str_size = (strlen(str) + 4) & 0xffff;
		char header[12];
	#if TSAI_WARPPER_SPINLOCK
		FLAGS;
	#endif

		header[0] = ESCAPE_CODE;
		header[1] = STRING_ANNOTATION;
		marshal_u32(header + 2, channel);
		marshal_u16(header + 6, str_size);
		marshal_u32(header + 8, color);
	#if TSAI_WARPPER_SPINLOCK
		ENTER(0);
	#endif

		kannotate_write_ts(header, sizeof(header), ts, ppid, seq_no);
		kannotate_write_ts(str, str_size - 4, ts, ppid, seq_no);
	#if TSAI_WARPPER_SPINLOCK
		QUIT;
	#endif

	}
	EXPORT_SYMBOL(gator_annotate_channel_color_ts);

	void gator_annotate_marker_color_str_ts(int color, const char *str, u64* ts)
	{
		const u16 str_size = (strlen(str) + 4) & 0xffff;
		char header[8];
	#if TSAI_WARPPER_SPINLOCK
		FLAGS;
	#endif

		header[0] = ESCAPE_CODE;
		header[1] = MARKER_ANNOTATION;
		marshal_u16(header + 2, str_size);
		marshal_u32(header + 4, color);
	#if TSAI_WARPPER_SPINLOCK
		ENTER(0);
	#endif

		kannotate_write_ts(header, sizeof(header), ts, NULL, seq_no);
		kannotate_write_ts(str, str_size - 4, ts, NULL, seq_no);
	#if TSAI_WARPPER_SPINLOCK
		QUIT;
	#endif

	}
	EXPORT_SYMBOL(gator_annotate_marker_color_str_ts);

	void gator_annotate_name_group_pid(int group, const char *str, int* ppid)
	{
		const u16 str_size = strlen(str) & 0xffff;
		char header[8];
	#if TSAI_WARPPER_SPINLOCK
		FLAGS;
	#endif

		header[0] = ESCAPE_CODE;
		header[1] = NAME_GROUP_ANNOTATION;
		marshal_u32(header + 2, group);
		marshal_u16(header + 6, str_size);
	#if TSAI_WARPPER_SPINLOCK
		ENTER(0);
	#endif

		kannotate_write_ts(header, sizeof(header), NULL, ppid, seq_no);
		kannotate_write_ts(str, str_size, NULL, ppid, seq_no);
	#if TSAI_WARPPER_SPINLOCK
		QUIT;
	#endif

	}
	EXPORT_SYMBOL(gator_annotate_name_group_pid);

	void gator_annotate_name_channel_pid(int channel, int group, const char *str, int* ppid)
	{
		const u16 str_size = strlen(str) & 0xffff;
		char header[12];
	#if TSAI_WARPPER_SPINLOCK
		FLAGS;
	#endif

		header[0] = ESCAPE_CODE;
		header[1] = NAME_CHANNEL_ANNOTATION;
		marshal_u32(header + 2, channel);
		marshal_u32(header + 6, group);
		marshal_u16(header + 10, str_size);
	#if TSAI_WARPPER_SPINLOCK
		ENTER(0);
	#endif

		kannotate_write_ts(header, sizeof(header), NULL, ppid, seq_no);
		kannotate_write_ts(str, str_size, NULL, ppid, seq_no);
	#if TSAI_WARPPER_SPINLOCK
		QUIT;
	#endif

	}
	EXPORT_SYMBOL(gator_annotate_name_channel_pid);
#endif
