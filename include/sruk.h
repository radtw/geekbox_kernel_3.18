/*
 * sruk.h
 *
 *  Created on: 18 May 2015
 *      Author: cheng.tsai
 */

#ifndef SRUK_20150518H_
#define SRUK_20150518H_

#include "linux/slab.h"

/*====================================================================================================*/
struct key_record {
	struct list_head list; /* must be first one in this data struct */
	unsigned key;
};

/* Note, kzalloc may sleep if not specified with GFP_ATOMIC.
 * If the calling thread is holding a spinlock and fell into sleep, deadlock may happen.
 *
 * */
static inline struct key_record* get_key_record(struct list_head* head, int struct_size, unsigned key) {
	struct list_head* existing = NULL;
	/* find existing record */
	{
		struct list_head* list;
		for (list = (head->next); list && list != head; list=list->next ) {
			if ( ((struct key_record*)list)->key == key) {
				existing = list;
			}
		}
	}

	if (!existing) {
		struct key_record* rec;
		rec = kzalloc(struct_size, GFP_ATOMIC);
		if (rec) {
			rec->key = key;
			list_add( &(rec->list), head );
		}
		existing = (struct list_head*) rec;
	}
	return (struct key_record*)existing;
}

/*=====================================================================================================*/
#include <linux/hardirq.h>
#define HIT_COUNT_ELEMENTS (128)
/* to use, declare this variable
 * struct code_hit_count_set funchit;
 *
 * */

/* to record how many times this place has been hit */
struct code_hit_count {
	void* address;
	u32 count;
};

struct code_hit_count_set {
	struct code_hit_count nonin[HIT_COUNT_ELEMENTS];
	struct code_hit_count in[HIT_COUNT_ELEMENTS];
};

static inline void code_hit_take_sampe(void* address, struct code_hit_count_set* f ) {
	int i;
	/* check whether it is in interrupt context */
	int intr = in_interrupt();
	struct code_hit_count* array;

	array = (intr) ? f->in : f->nonin ;
	for (i=0; i<HIT_COUNT_ELEMENTS; i++ ) {
		if ( array[i].address ) {
			if (array[i].address == address) {
				array[i].count++;
				break;
			}
		}
		else {
			array[i].address = address;
			array[i].count++;
			break;
		}
	}
}

#endif /* SRUK_20150518H_ */
