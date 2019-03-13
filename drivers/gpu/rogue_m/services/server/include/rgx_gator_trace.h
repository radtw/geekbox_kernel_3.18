/*
 * rgx_gator_trace.h
 *
 *  Created on: 3 Mar 2017
 *      Author: cheng.tsai
 */
#include <linux/version.h>

#if !defined(RGX_GATOR_TRACE_H_) || defined (TRACE_HEADER_MULTI_READ)
#define RGX_GATOR_TRACE_H_

#include <linux/types.h>

#include <linux/stringify.h>
#include <linux/tracepoint.h>

#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE rgx_gator_trace


TRACE_EVENT(mali_timeline_event_timestamp,

	    TP_PROTO(unsigned int event_id, unsigned int d0, unsigned int d1,
		     unsigned int d2, unsigned int d3, unsigned int d4),

	    TP_ARGS(event_id, d0, d1, d2, d3, d4),

	    TP_STRUCT__entry(
		    __field(unsigned int, event_id)
		    __field(unsigned int, d0)
		    __field(unsigned int, d1)
		    __field(unsigned int, d2)
		    __field(unsigned int, d3)
		    __field(unsigned int, d4)
	    ),

	    TP_fast_assign(
		    __entry->event_id = event_id;
		    __entry->d0 = d0;
		    __entry->d1 = d1;
		    __entry->d2 = d2;
		    __entry->d3 = d3;
		    __entry->d4 = d4;
	    ),

	    TP_printk("event=%d", __entry->event_id)
	   );


TRACE_EVENT(mali_hw_counter,

	    TP_PROTO(unsigned int counter_id, unsigned int value),

	    TP_ARGS(counter_id, value),

	    TP_STRUCT__entry(
		    __field(unsigned int, counter_id)
		    __field(unsigned int, value)
	    ),

	    TP_fast_assign(
		    __entry->counter_id = counter_id;
	    ),

	    TP_printk("event %d = %d", __entry->counter_id, __entry->value)
	   );

TRACE_EVENT(mali_sw_counters,

	    TP_PROTO(pid_t pid, pid_t tid, void *surface_id, unsigned int *counters),

	    TP_ARGS(pid, tid, surface_id, counters),

	    TP_STRUCT__entry(
		    __field(pid_t, pid)
		    __field(pid_t, tid)
		    __field(void *, surface_id)
		    __field(unsigned int *, counters)
	    ),

	    TP_fast_assign(
		    __entry->pid = pid;
		    __entry->tid = tid;
		    __entry->surface_id = surface_id;
		    __entry->counters = counters;
	    ),

	    TP_printk("counters were %s", __entry->counters == NULL ? "NULL" : "not NULL")
	   );


#endif /* RGX_GATOR_TRACE_H_ */

/* This part must exist outside the header guard. */
#include <trace/define_trace.h>
