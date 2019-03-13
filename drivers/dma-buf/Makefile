obj-y := dma-buf.o fence.o reservation.o seqno-fence.o

ifeq ($(TSAI_OPT),1)
	CFLAGS_dma-buf.o += -O0
	CFLAGS_fence.o += -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-inline -fno-unit-at-a-time
	CFLAGS_reservation.o += -O0
	CFLAGS_seqno-fence.o += -O0
endif

