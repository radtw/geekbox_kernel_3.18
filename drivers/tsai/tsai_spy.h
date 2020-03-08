/*
 * 
 *
 *  Created on: 15 Jul 2019
 *      Author: cheng-shiun.tsai
 */

#ifndef TSAI_SPY_HEADER_H_
#define TSAI_SPY_HEADER_H_

#include <linux/rbtree.h>

void tsai_printk_stack_trace_current(void);
void tsai_print_vma_for_address(void* pc);

#endif /* TSAI_SPY_HEADER_H_ */
