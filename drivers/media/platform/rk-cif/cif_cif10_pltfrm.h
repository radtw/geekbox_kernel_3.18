/*
**************************************************************************
 * Rockchip driver for CIF CIF 1.0
 * (Based on Intel driver for sofiaxxx)
 *
 * Copyright (C) 2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016 Fuzhou Rockchip Electronics Co., Ltd.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
**************************************************************************
 */

#ifndef _CIF_CIF10_PLTFRM_H
#define _CIF_CIF10_PLTFRM_H

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <linux/platform_data/rk_cif10_platform.h>

struct cif_cif10_strm_fmt;
struct cif_cif10_csi_config;
struct cif_cif10_device;
struct cif_cif10_img_src;
struct pltfrm_cam_itf;
enum cif_cif10_pinctrl_state;
enum cif_cif10_inp;
enum cif_cif10_pm_state;


#define CIF_CIF10_PLTFRM_DEVICE struct device *
#define CIF_CIF10_PLTFRM_MEM_IO_ADDR void __iomem *
#define CIF_CIF10_PLTFRM_EVENT wait_queue_head_t

extern spinlock_t iowrite32_verify_lock;
#ifdef CONFIG_CIF_CIF10_REG_TRACE
int
cif_cif10_pltfrm_rtrace_printf(
	struct device *dev,
	const char *fmt,
	...);

int
cif_cif10_pltfrm_ftrace_printf(
	struct device *dev,
	const char *fmt,
	...);

#else
#define cif_cif10_pltfrm_rtrace_printf(dev, str, ...)
#define cif_cif10_pltfrm_ftrace_printf(dev, str, ...)
#endif

#define cif_cif10_pltfrm_pr_dbg(dev, fmt, arg...) \
	do { \
		pr_debug("CIF %s: " fmt, \
			__func__, ## arg); \
		cif_cif10_pltfrm_ftrace_printf(dev, "%s: " fmt, \
			__func__, ## arg); \
	} while (0)
#define cif_cif10_pltfrm_pr_info(dev, fmt, arg...) \
	do { \
		pr_info("CIF %s: " fmt, \
			__func__, ## arg); \
		cif_cif10_pltfrm_ftrace_printf(dev, "%s: " fmt, \
			__func__, ## arg); \
	} while (0)
#define cif_cif10_pltfrm_pr_warn(dev, fmt, arg...) \
	do { \
		pr_warn("CIF %s WARN: " fmt, \
			__func__, ## arg); \
		cif_cif10_pltfrm_ftrace_printf(dev, "%s WARN: " fmt, \
			__func__, ## arg); \
	} while (0)
#define cif_cif10_pltfrm_pr_err(dev, fmt, arg...) \
	do { \
		pr_err("CIF %s(%d) ERR: " fmt, \
			__func__, __LINE__, ## arg); \
		cif_cif10_pltfrm_ftrace_printf(dev, "%s(%d) ERR: " fmt, \
			__func__, __LINE__, ## arg); \
	} while (0)

void cif_cif10_pltfrm_write_reg(
	struct device *dev,
	u32 data,
	CIF_CIF10_PLTFRM_MEM_IO_ADDR addr);

void cif_cif10_pltfrm_write_reg_OR(
	struct device *dev,
	u32 data,
	CIF_CIF10_PLTFRM_MEM_IO_ADDR addr);

void cif_cif10_pltfrm_write_reg_AND(
	struct device *dev,
	u32 data,
	CIF_CIF10_PLTFRM_MEM_IO_ADDR addr);

u32 cif_cif10_pltfrm_read_reg(
	struct device *dev,
	CIF_CIF10_PLTFRM_MEM_IO_ADDR addr);

#define cif_iowrite32(d, a) \
	cif_cif10_pltfrm_write_reg(NULL, d, a)
#define cif_ioread32(a) \
	cif_cif10_pltfrm_read_reg(NULL, a)
#define cif_iowrite32OR(d, a) \
	cif_cif10_pltfrm_write_reg_OR(NULL, d, a)
#define cif_iowrite32AND(d, a) \
	cif_cif10_pltfrm_write_reg_AND(NULL, d, a)

#define cif_cif10_pltfrm_event_init(_dev, _event) \
	init_waitqueue_head(_event)

#define cif_cif10_pltfrm_event_clear(_dev, _event)

#define cif_cif10_pltfrm_event_signal(_dev, _event) \
	wake_up_interruptible(_event)

#define cif_cif10_pltfrm_event_wait_timeout( \
	_dev, _event, _condition, _timeout_us) \
	wait_event_interruptible_timeout( \
		*(_event), _condition, (_timeout_us * HZ) / 1000000)

void
cif_cif10_pltfrm_debug_register_print_cb(
	struct device *dev,
	void (*print)(void *cntxt, const char *block_name),
	void *cntxt);

int cif_cif10_pltfrm_dev_init(
	struct cif_cif10_device *cif_cif_dev,
	struct device **dev,
	void __iomem **reg_base_addr);

void cif_cif10_pltfrm_dev_release(
	struct device *dev);

int cif_cif10_pltfrm_pm_set_state(
	struct device *dev,
	enum cif_cif10_pm_state state);

int cif_cif10_pltfrm_write_cif_ana_bandgap_bias(
	struct device *dev,
	u32 val);

int cif_cif10_pltfrm_pinctrl_set_state(
	struct device *dev,
	enum cif_cif10_pinctrl_state pinctrl_state);

int cif_cif10_pltfrm_get_img_src_device(
	struct device *dev,
	struct cif_cif10_img_src **img_src_array,
	unsigned int array_len);

int cif_cif10_pltfrm_g_interface_config(
	struct cif_cif10_img_src *img_src,
	struct pltfrm_cam_itf *cam_itf);

int cif_cif10_pltfrm_irq_register_isr(
	struct device *dev,
	unsigned int mis,
	int (*isr)(unsigned int mis, void *cntxt),
	void *cntxt);

const char *cif_cif10_pltfrm_get_device_type(
	struct device *dev);

const char *cif_cif10_pltfrm_dev_string(
	struct device *dev);

int cif_cif10_pltfrm_soc_init(
	struct cif_cif10_device *cif_cif10_dev,
	struct pltfrm_soc_cfg *soc_cfg);

int cif_cif10_pltfrm_mipi_dphy_config(
	struct cif_cif10_device *cif_cif10_dev);

#endif
