#
# Makefile for rockchip camsys driver
#
obj-$(CONFIG_CAMSYS_DRV) += camsys_drv.o 
obj-$(CONFIG_CAMSYS_MRV) += camsys_marvin.o camsys_mipicsi_phy.o camsys_soc_priv.o camsys_soc_rk3288.o camsys_soc_rk3368.o
obj-$(CONFIG_CAMSYS_CIF) += camsys_cif.o
obj-y					 += ext_flashled_drv/

ifeq ($(TSAI_OPT),1) 
	CFLAGS_camsys_drv.o += -O0
	CFLAGS_camsys_marvin.o += -O0
	CFLAGS_camsys_mipicsi_phy.o += -O0
	CFLAGS_camsys_soc_priv.o += -O0
	CFLAGS_camsys_soc_rk3368.o += -O0
	CFLAGS_camsys_cif.o += -O0	
endif