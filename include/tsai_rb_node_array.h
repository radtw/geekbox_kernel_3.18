/*
 * tsai_rb_node_array.h
 *
 *  Created on: 1 Mar 2019
 *      Author: cheng.tsai
 */

#ifndef TSAI_RB_NODE_ARRAY_H_
#define TSAI_RB_NODE_ARRAY_H_

#include <linux/rbtree.h>
#include <linux/spinlock.h>

struct ts_rba {
	struct rb_node n;
	uint64_t key; /* key could be a 64bit pointer */
	unsigned int idx; /* idx in array */
};

static struct ts_rba* ts_rba_find(struct rb_root* root, uint64_t key);
static void ts_rba_insert(struct rb_root* root, struct ts_rba* n);
static void ts_rba_remove(struct rb_root* root, struct ts_rba* n);

static __attribute__((unused)) struct ts_rba* ts_rba_find(struct rb_root* root, uint64_t key) {
	struct ts_rba* ret = 0;
	struct ts_rba* n = (struct ts_rba*)root->rb_node;
	while(n) {
		if (key > n->key)
			n = (struct ts_rba*)n->n.rb_right;
		else if (key < n->key)
			n = (struct ts_rba*)n->n.rb_left;
		else {
			ret = n;
			break;
		}
	}
	return ret;
}

static __attribute__((unused)) void ts_rba_insert(struct rb_root* root, struct ts_rba* n) {
	struct rb_node **pnew = &root->rb_node;
	struct ts_rba* parent = NULL;
	while (*pnew) {
		parent = (struct ts_rba*)*pnew;
		if (n->key < parent->key)
			pnew = &parent->n.rb_left;
		else
			pnew = &parent->n.rb_right;
	}
	rb_link_node(&n->n, &parent->n, pnew);
	rb_insert_color(&n->n, root); /* insert is already done, change color, or rotate if necessary */
}

/* remove n from the RB tree root, but caller still need to kfree(n) */
static __attribute__((unused)) void ts_rba_remove(struct rb_root* root, struct ts_rba* n) {
	rb_erase(&n->n, root);
}

struct TSAI_RBA {
	struct rb_root root;
	int count;
	spinlock_t lock;

	struct ts_rba** pRBAptr;
    int max_count;
};

static __attribute__((unused)) void TSAI_RBA_insert(struct TSAI_RBA* rba, struct ts_rba* n) {
	unsigned long irqflags;
	spin_lock_irqsave(&rba->lock, irqflags);
		ts_rba_insert(&rba->root, n);
		n->idx = rba->count;
		rba->pRBAptr[rba->count++] = n;
	spin_unlock_irqrestore(&rba->lock, irqflags);
}

/* the rb node will be freed here */
static __attribute__((unused)) int TSAI_RBA_remove_by_key(struct TSAI_RBA* rba, uint64_t key) {
	int ret;
	unsigned long irqflags;
	struct ts_rba* n;
	spin_lock_irqsave(&rba->lock, irqflags);
		n = ts_rba_find(&rba->root, key);
		if (n) {
			int old_idx = n->idx;
			ts_rba_remove(&rba->root, n);
			rba->pRBAptr[old_idx] = rba->pRBAptr[rba->count-1];
			rba->pRBAptr[old_idx]->idx = old_idx;
			rba->count--;
			rba->pRBAptr[rba->count] = 0;
			kfree(n);
			ret = 1;
		}
		else {
			ret = 0;
		}
	spin_unlock_irqrestore(&rba->lock, irqflags);
	return ret;
}

/* the rb node will be freed here */
static __attribute__((unused)) struct ts_rba* TSAI_RBA_find_by_key(struct TSAI_RBA* rba, uint64_t key) {
	unsigned long irqflags;
	struct ts_rba* n;
	spin_lock_irqsave(&rba->lock, irqflags);
		n = ts_rba_find(&rba->root, key);
	spin_unlock_irqrestore(&rba->lock, irqflags);
	return n;
}

#endif /* TSAI_RB_NODE_ARRAY_H_ */
