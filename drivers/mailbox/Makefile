# Generic MAILBOX API

obj-$(CONFIG_MAILBOX)		+= mailbox.o

obj-$(CONFIG_PL320_MBOX)	+= pl320-ipc.o

obj-$(CONFIG_OMAP2PLUS_MBOX)	+= omap-mailbox.o

#TSAI: the next two are copied from geekbox kernel 3.10
obj-$(CONFIG_ROCKCHIP_MAILBOX)	+= rockchip_mailbox.o
obj-$(CONFIG_SCPI_PROTOCOL)	+= scpi_protocol.o

ifeq ($(TSAI_OPT),1) 
	CFLAGS_rockchip_mailbox.o += -O0
	CFLAGS_scpi_protocol.o += -O0
#CFLAGS_ddr_freq.o += -O0
endif
