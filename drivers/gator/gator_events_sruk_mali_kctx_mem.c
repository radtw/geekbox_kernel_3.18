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

#include "gator.h"

#define sruk_COUNTERS_NUM 3

static int sruk_global_enabled;

static struct {
	unsigned long enabled;
	unsigned long key;
} sruk_counters[sruk_COUNTERS_NUM];

static int sruk_buffer[sruk_COUNTERS_NUM * 2];

/* export symbols so that gator can retrieve memory infomation as well */

/* export symbols so that gator can retrieve memory infomation as well */
struct sruk_mali_kctx_mem_prof_streamline {
	unsigned int version; /* version of this structure */
	unsigned int size; /* size of this structure */
	unsigned int mali_kctx_used_page_byte; /* current mali used memory */
	unsigned int mali_histogram_byte; /* current mali limitation */
	unsigned int mali_hoard_byte;
};

/* streamline may call this function to retrieve memory statistics info */
typedef void (*ptr_sruk_mali_kctxmem_prof_streamline_read) (struct sruk_mali_kctx_mem_prof_streamline* info);
static ptr_sruk_mali_kctxmem_prof_streamline_read sruk_mali_kctxmem_prof_streamline_read;

/* Adds sruk_cntX directories and enabled, event, and key files to /dev/gator/events */
static int gator_events_sruk_create_files(struct super_block *sb,
					     struct dentry *root)
{
	int i;

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

	return 0;
}

static int gator_events_sruk_start(void)
{
	int i;

	sruk_global_enabled = 0;
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		if (sruk_counters[i].enabled) {
			sruk_global_enabled = 1;
			break;
		}
	}

	/* obtain function pointer address */
	if (!sruk_mali_kctxmem_prof_streamline_read) {
		sruk_mali_kctxmem_prof_streamline_read = (ptr_sruk_mali_kctxmem_prof_streamline_read)symbol_get(sruk_mali_kctxmem_prof_streamline_read);
	}

	return 0;
}

static void gator_events_sruk_stop(void)
{
	sruk_global_enabled = 0;
}

static int gator_events_sruk_read(int **buffer, bool sched_switch)
{
	int len = 0;
	struct sruk_mali_kctx_mem_prof_streamline mali_info;

	/* System wide counters - read from one core only */
	if (!on_primary_core() || !sruk_global_enabled)
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

#if 0
	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		if (sruk_counters[i].enabled) {
			sruk_buffer[len++] = sruk_counters[i].key;
			sruk_buffer[len++] =
			    sruk_simulate(i, delta_in_us);
		}
	}
#endif

	if (buffer)
		*buffer = sruk_buffer;

Leave:
	return len;
}

static struct gator_interface gator_events_sruk_interface = {
	.create_files = gator_events_sruk_create_files,
	.start = gator_events_sruk_start,
	.stop = gator_events_sruk_stop,
	.read = gator_events_sruk_read,
};

/* Must not be static! */
/* TSAI: don't put init keyword here */
int gator_events_sruk_malikctxmem_init(void)
{
	int i;

	for (i = 0; i < sruk_COUNTERS_NUM; i++) {
		sruk_counters[i].enabled = 0;
		sruk_counters[i].key = gator_events_get_key();
	}

	return gator_events_install(&gator_events_sruk_interface);
}
