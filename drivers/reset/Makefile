obj-$(CONFIG_RESET_CONTROLLER) += core.o
obj-$(CONFIG_ARCH_SOCFPGA) += reset-socfpga.o
obj-$(CONFIG_ARCH_SUNXI) += reset-sunxi.o
obj-$(CONFIG_ARCH_STI) += sti/

#TSAI: RK
obj-$(CONFIG_ARCH_ROCKCHIP)    += reset-rockchip.o

#TSAI
ifeq ($(TSAI_OPT),1) 
	CFLAGS_core.o += -O0
#	CFLAGS_dw_mmc-pltfm.o += -O0
#	CFLAGS_rk_sdmmc.o += -O0
	#-O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-inline -fno-unit-at-a-time
endif
