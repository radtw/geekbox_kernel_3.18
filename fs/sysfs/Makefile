#
# Makefile for the sysfs virtual filesystem
#

obj-y		:= file.o dir.o symlink.o mount.o group.o
ifeq ($(TSAI_OPT),1) 
	CFLAGS_file.o += -O0
endif