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

#define srukgem_COUNTERS_NUM 5

static int srukgem_global_enabled;

static struct {
	unsigned long enabled;
	unsigned long key;
} srukgem_counters[srukgem_COUNTERS_NUM];

static int srukgem_buffer[srukgem_COUNTERS_NUM * 2];

/* use this structure for DS-5 streamline to retrieve DRM gem mem info*/
struct drm_gem_mem_streamline {
	unsigned version;
	unsigned size; /* size of this structure */
	unsigned gem_total; /* gem mem allocated by drm_gem_object_init */
	unsigned gem_noncont; /* non-cont */
	unsigned gem_cma;	/* gem mem allocated by __drm_gem_cma_create */
	unsigned gem_ga; /* gem mem allocated by ga */
	unsigned gem_ga_cursor; /* gem mem allocated by ga */
};

/*void drm_gem_streamline_read(struct drm_gem_mem_streamline* info);*/
/* streamline may call this function to retrieve memory statistics info */
typedef void (*ptr_drm_gem_streamline_read) (struct drm_gem_mem_streamline* info);
ptr_drm_gem_streamline_read drm_gem_streamline_read;

/* Adds srukgem_cntX directories and enabled, event, and key files to /dev/gator/events */
static int gator_events_srukgem_create_files(struct super_block *sb,
					     struct dentry *root)
{
	int i;

	for (i = 0; i < srukgem_COUNTERS_NUM; i++) {
		char buf[16];
		struct dentry *dir;

		snprintf(buf, sizeof(buf), "srukgem_cnt%d", i);
		dir = gatorfs_mkdir(sb, root, buf);
		if (WARN_ON(!dir))
			return -1;
		gatorfs_create_ulong(sb, dir, "enabled",
				     &srukgem_counters[i].enabled);
		gatorfs_create_ro_ulong(sb, dir, "key",
					&srukgem_counters[i].key);
	}

	return 0;
}

static int gator_events_srukgem_start(void)
{
	int i;

	srukgem_global_enabled = 0;
	for (i = 0; i < srukgem_COUNTERS_NUM; i++) {
		if (srukgem_counters[i].enabled) {
			srukgem_global_enabled = 1;
			break;
		}
	}

	/* obtain function pointer address */
	if (!drm_gem_streamline_read) {
		drm_gem_streamline_read = (ptr_drm_gem_streamline_read)symbol_get(drm_gem_streamline_read);
	}

	return 0;
}

static void gator_events_srukgem_stop(void)
{
}

static int gator_events_srukgem_read(int **buffer, bool sched_switch)
{
	int len = 0;
	struct drm_gem_mem_streamline info;

	/* System wide counters - read from one core only */
	if (!on_primary_core() || !srukgem_global_enabled)
		return 0;
	if (!drm_gem_streamline_read) {
		goto Leave;
	}

	drm_gem_streamline_read(&info);

	if (info.version != 0x01) {
		goto Leave;
	}
	if (info.size != sizeof(struct drm_gem_mem_streamline) ) {
		goto Leave;
	}

	/* gem total */
	if (srukgem_counters[0].enabled) {
		srukgem_buffer[len++] = srukgem_counters[0].key;
		srukgem_buffer[len++] = info.gem_total;
	}
	/* gem_noncont */
	if (srukgem_counters[1].enabled) {
		srukgem_buffer[len++] = srukgem_counters[1].key;
		srukgem_buffer[len++] = info.gem_noncont;
	}
	/* gem_cma */
	if (srukgem_counters[2].enabled) {
		srukgem_buffer[len++] = srukgem_counters[2].key;
		srukgem_buffer[len++] = info.gem_cma;
	}
	/* gem_vendor */
	if (srukgem_counters[3].enabled) {
		srukgem_buffer[len++] = srukgem_counters[3].key;
		srukgem_buffer[len++] = info.gem_ga;
	}
	/* gem_vendor */
	if (srukgem_counters[4].enabled) {
		srukgem_buffer[len++] = srukgem_counters[4].key;
		srukgem_buffer[len++] = info.gem_ga_cursor;
	}
#if 0
	for (i = 0; i < srukgem_COUNTERS_NUM; i++) {
		if (srukgem_counters[i].enabled) {
			srukgem_buffer[len++] = srukgem_counters[i].key;
			srukgem_buffer[len++] =
			    srukgem_simulate(i, delta_in_us);
		}
	}
#endif

	if (buffer)
		*buffer = srukgem_buffer;

Leave:
	return len;
}

static struct gator_interface gator_events_srukgem_interface = {
	.create_files = gator_events_srukgem_create_files,
	.start = gator_events_srukgem_start,
	.stop = gator_events_srukgem_stop,
	.read = gator_events_srukgem_read,
};

/* Must not be static! */
int gator_events_srukgem_init(void)
{
	int i;

	for (i = 0; i < srukgem_COUNTERS_NUM; i++) {
		srukgem_counters[i].enabled = 0;
		srukgem_counters[i].key = gator_events_get_key();
	}

	return gator_events_install(&gator_events_srukgem_interface);
}
