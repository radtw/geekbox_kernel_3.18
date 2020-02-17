/*
 * gator_annotate_tsai.h
 *
 *  Created on: 17 Feb 2020
 *      Author: julian
 */

#ifndef DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_
#define DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_

/* use this structure to share data with user mode directly through memory pointer */
struct GATOR_DATA_USER_SHARE {
	unsigned int id;
	int gator_started;
};

#endif /* DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_ */
