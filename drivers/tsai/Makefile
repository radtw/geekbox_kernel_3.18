#
#TSAI: my own profiling experiment
obj-y	+= tsai_spy.o tsai_spy_mem_log.o tsai_breakpoint.o tsai_callstack_cache.o

#TSAI: work around for pixel3a kernel
#ccflags-y += -Wno-parentheses-equality -Wno-section
#TSAI: for gcc toolchain
ccflags-y += -Wno-unused-variable

ifeq ($(TSAI_OPT),1) 
	CFLAGS_tsai_spy_mem_log.o += -O0
	CFLAGS_tsai_spy.o += -O0
	CFLAGS_tsai_breakpoint.o += -O0
endif 

