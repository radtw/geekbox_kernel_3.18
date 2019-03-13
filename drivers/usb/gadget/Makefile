#
# USB peripheral controller drivers
#
subdir-ccflags-$(CONFIG_USB_GADGET_DEBUG)	:= -DDEBUG
subdir-ccflags-$(CONFIG_USB_GADGET_VERBOSE)	+= -DVERBOSE_DEBUG
ccflags-y				+= -I$(srctree)/drivers/usb/gadget/udc

#TSAI, to keep compiler going
#ccflags-y				+= -I$(srctree)/drivers/usb/gadget/function
#ccflags-y				+= -I$(srctree)/drivers/usb/gadget


obj-$(CONFIG_USB_LIBCOMPOSITE)	+= libcomposite.o
libcomposite-y			:= usbstring.o config.o epautoconf.o
libcomposite-y			+= composite.o functions.o configfs.o u_f.o

g_android-y			:= android.o

obj-$(CONFIG_USB_GADGET)	+= udc/ function/ legacy/

obj-$(CONFIG_USB_G_ANDROID)	+= g_android.o

#TSAI
#ln -sf function/f_audio_source.c f_audio_source.c
#ln -sf function/f_fs.c f_fs.c
#ln -sf function/u_fs.c u_fs.c
#ln -sf function/u_fs.h u_fs.h
#ln -sf function/f_mass_storage.c f_mass_storage.c
#ln -sf function/storage_common.h storage_common.h
#ln -sf function/f_mass_storage.h f_mass_storage.h
#etc....

#TSAI: disable CONFIG_USB_G_ANDROID for now, don't know how to fix or whether if it's needed or not?




