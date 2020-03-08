/*
 * gator_annotate_tsai.h
 *
 *  Created on: 17 Feb 2020
 *  Author:
 */

#ifndef DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_
#define DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_

/* use this structure to share data with user mode directly through memory pointer */
struct GATOR_DATA_USER_SHARE {
	unsigned int id;
	int gator_started;
};

//uint32_t owner; /* owner of this buffer, must be a value from enum TSAI_BUF_OWNDER */
//uint32_t buf; /* buffer identifier, eg. Android ION seqno, or DRM GEM name */
//uint32_t on_off; /* 0=stop owner, 1=start owning */
extern void tsai_bufinfo_owner(uint32_t owner, uint32_t buf, uint32_t on_off);

#endif /* DRIVERS_GATOR_GATOR_ANNOTATE_TSAI_H_ */
