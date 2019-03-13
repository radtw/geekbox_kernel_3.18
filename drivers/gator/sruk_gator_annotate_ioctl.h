/*
 * sruk_gator_annotate_ioctl.h
 *
 *  Created on: 1 Mar 2016
 *      Author: cheng.tsai
 */

#ifndef SRUK_GATOR_ANNOTATE_IOCTL_H_
#define SRUK_GATOR_ANNOTATE_IOCTL_H_

void gator_annotate_visual(const char *data, unsigned int length, const char *str);
#pragma pack(push,1)
	typedef struct tagBITMAPFILEHEADER {
	  uint16_t  bfType;
	  uint32_t bfSize;
	  uint16_t  bfReserved1;
	  uint16_t  bfReserved2;
	  uint32_t bfOffBits;
	} BITMAPFILEHEADER, *PBITMAPFILEHEADER;

	typedef struct tagBITMAPINFOHEADER {
	  uint32_t biSize;
	  int32_t  biWidth;
	  int32_t  biHeight;
	  uint16_t  biPlanes;
	  uint16_t  biBitCount;
	  uint32_t biCompression;
	  uint32_t biSizeImage;
	  int32_t  biXPelsPerMeter;
	  int32_t  biYPelsPerMeter;
	  uint32_t biClrUsed;
	  uint32_t biClrImportant;
	} BITMAPINFOHEADER, *PBITMAPINFOHEADER;

	struct BM_HEADER{
		BITMAPFILEHEADER bfh;
		BITMAPINFOHEADER bmi;
	} bm;

#pragma pack(pop)

struct tsai_gator_common_parameter {
	uint32_t channel;
	uint32_t color;
	uint64_t str;
	uint64_t ts;
	uint32_t pid;
};

struct tsai_os_vsync_param {
	uint64_t ts;
	uint32_t seqno; /* opt: OS V-Sync number */
};

struct tsai_gator_get_ts {
	uint64_t ts; /* [out], for use mode to receive a timestamp */
};

enum SRUK_GATOR_IOCTL {
	SRUK_GATOR_IOCTL_INVALID = 0,
	SRUK_GATOR_IOCTL_BASE = 0x100,
	SRUK_GATOR_IOCTL_ANNOTATE_RAW_IMAGE,
	SRUK_GATOR_IOCTL_IN_CAPTURE, /* 0x102: return 1 if gator is currently in capturing */
	SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_COLOR,
	SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_END,
	SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_COLOR_TS,
	SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_COLOR_TS_PID,
	SRUK_GATOR_IOCTL_ANNOTATE_GET_TS = 0x1FF,
	SRUK_GATOR_IOCTL_OS_VSYNC = 0x200,
	SRUK_GATOR_IOCTL_END
};

struct gator_annotate_raw_image_param {
	unsigned ori_width;
	unsigned ori_height;
	unsigned crop_x;
	unsigned crop_y;
	unsigned crop_width;
	unsigned crop_height;
	unsigned shrink_factor; /* 1 unchanged, 2 means shrink to half width/height */
	void* ori_data;
	unsigned ori_length;
	char* user_msg;
};

#if 1
	static int gator_op_setup(void);
	static int gator_annotate_start(void);
#endif

int gator_annotate_raw_image(struct gator_annotate_raw_image_param* param) {
	int copy_width = param->crop_width / param->shrink_factor;
	int copy_height = param->crop_height / param->shrink_factor;
	int copy_pitch = ((copy_width*4) + 3) & ~0x3;
	int ori_pitch = ((param->ori_width*4) + 3) & ~0x3; /* in the future may be provided by caller */
	int copy_image_size = copy_pitch * copy_height;
	int filesize = copy_image_size + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	void* mem;
	BITMAPFILEHEADER* bfh;
	BITMAPINFOHEADER* bmi;
	void* bits;

	int shrink_factor_shift;
	int src_pixel_incre;
	int dst_pixel_incre;
	int src_pitch_incre;

#if 0 /* temp debug purpose */
	if (!collect_annotations) {
		gator_op_setup();
		gator_annotate_start();
	}
#endif
	if (!collect_annotations) { /* exit early if no client is receiving data */
		goto Leave;
	}

	mem = vmalloc(filesize);
	bfh = (BITMAPFILEHEADER*) mem;
	bmi = (BITMAPINFOHEADER*) (mem + sizeof(BITMAPFILEHEADER));
	bits = mem +  sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);


	switch(param->shrink_factor) {
	case 1:
		shrink_factor_shift = 0; break;
	case 2:
		shrink_factor_shift = 1; break;
	default:
		BKPT; /* not implemented yet */
	}

	src_pixel_incre = 4 << (shrink_factor_shift);
	dst_pixel_incre = 4;
	src_pitch_incre = ori_pitch << (shrink_factor_shift);

	bfh->bfType = 0x4D42;
	bfh->bfSize = filesize;
	bfh->bfReserved1 = 0;
	bfh->bfReserved2 = 0;
	bfh->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	bmi->biSize = sizeof(BITMAPINFOHEADER);
	bmi->biWidth = copy_width;
	bmi->biHeight = -copy_height;
	bmi->biPlanes = 1;
	bmi->biBitCount = 32;
	bmi->biCompression = 0;
	bmi->biSizeImage = copy_image_size;
	bmi->biXPelsPerMeter = 3000;
	bmi->biYPelsPerMeter = 3000;
	bmi->biClrUsed = 0;
	bmi->biClrImportant = 0;

	//memcpy(bits, data, length);
	/* copy one pixel for each 4x4 block */
	{
		//int src_x = crop_x;
		//int src_y = crop_y;
		int dst_x = 0;
		int dst_y = 0;
		void* pSrcRow = param->ori_data + (param->crop_y * ori_pitch);
		void* pDstRow = bits;
		for (;dst_y < copy_height; dst_y++) {
			void* pSrcPixel = pSrcRow + (param->crop_x << 2);
			void* pDstPixel = pDstRow;

			for (dst_x=0; dst_x < copy_width; dst_x++) {

				*(unsigned long*)pDstPixel = *(unsigned long*) pSrcPixel;

				pSrcPixel += src_pixel_incre;
				pDstPixel += dst_pixel_incre;
			}

			pSrcRow += src_pitch_incre; /* move on by 2 rows */
			pDstRow += copy_pitch;
		}
	}

	gator_annotate_visual(mem, filesize, param->user_msg );

	vfree (mem);
Leave:
	return 0;
}

static void marshal_u16(char *buf, u16 val);
static void marshal_u32(char *buf, u32 val);

/* wait until read cursor matches to write cursor, and whole buffer is empty */
bool raw_image_onthefly_wake_up_condition(int cpu) {
	bool ret;
	unsigned bytes_available;
	unsigned read_cursor;
	unsigned write_cursor;
	unsigned long annotate_lock_flags;
	unsigned contiguous;
#if TSAI_SPINLOCK_IRQ
						spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
						spin_lock(&annotate_lock);
#endif

	bytes_available = buffer_bytes_available(cpu, ANNOTATE_BUF);
	read_cursor = per_cpu(gator_buffer_read, cpu)[ANNOTATE_BUF];
	write_cursor = per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF];
	contiguous = contiguous_space_available(cpu, ANNOTATE_BUF);

	if (contiguous >= 4096 ) {
		ret = 1;
	}
	else {
		ret = !collect_annotations;
	}

#if TSAI_SPINLOCK_IRQ
						spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
						spin_unlock(&annotate_lock);
#endif
	printk("raw_image_onthefly wake_up_condition available %u rd %u wt %u cont %d collect_annotations %d ret %d \n",
			bytes_available, read_cursor, write_cursor, contiguous, collect_annotations, ret);
	return ret;
}

/* without creating intermediate buffer to store the resized bitmap,
 * instead, writing to gator buffer one pixel by one pixel
 *
 * */
int gator_annotate_raw_image_onthefly(struct gator_annotate_raw_image_param* param) {
	int retval = 0;
	int pid; struct BM_HEADER bm; int shrink_factor_shift;
	int src_pixel_incre; int dst_pixel_incre; int src_pitch_incre; int copy_width; int copy_height;
	int copy_pitch; int ori_pitch; int copy_image_size; int filesize;
	BITMAPFILEHEADER* bfh; BITMAPINFOHEADER* bmi;

#if 0 /* temp debug purpose */
	if (!collect_annotations) {
		gator_op_setup();
		gator_annotate_start();
	}
#endif
	if (!collect_annotations) { /* exit early if no client is receiving data */
		goto Leave;
	}

	copy_width = param->crop_width / param->shrink_factor;
	copy_height = param->crop_height / param->shrink_factor;
	copy_pitch = ((copy_width*4) + 3) & ~0x3;
	ori_pitch = ((param->ori_width*4) + 3) & ~0x3; /* in the future may be provided by caller */
	copy_image_size = copy_pitch * copy_height;
	filesize = copy_image_size + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	bfh = (BITMAPFILEHEADER*) &bm.bfh;
	bmi = (BITMAPINFOHEADER*) &bm.bmi;



	switch(param->shrink_factor) {
	case 1:
		shrink_factor_shift = 0; break;
	case 2:
		shrink_factor_shift = 1; break;
	default:
		BKPT; /* not implemented yet */
	}

	src_pixel_incre = 4 << (shrink_factor_shift);
	dst_pixel_incre = 4;
	src_pitch_incre = ori_pitch << (shrink_factor_shift);

	bfh->bfType = 0x4D42;
	bfh->bfSize = filesize;
	bfh->bfReserved1 = 0;
	bfh->bfReserved2 = 0;
	bfh->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	bmi->biSize = sizeof(BITMAPINFOHEADER);
	bmi->biWidth = copy_width;
	bmi->biHeight = -copy_height;
	bmi->biPlanes = 1;
	bmi->biBitCount = 32;
	bmi->biCompression = 0;
	bmi->biSizeImage = copy_image_size;
	bmi->biXPelsPerMeter = 3000;
	bmi->biYPelsPerMeter = 3000;
	bmi->biClrUsed = 0;
	bmi->biClrImportant = 0;

	/* write annotate visual header, and the bitmap header*/
	{
		const u16 str_size = strlen(param->user_msg) & 0xffff;
		char header[4];
		char header_length[4];
		header[0] = ESCAPE_CODE;
		header[1] = VISUAL_ANNOTATION;
		marshal_u16(header + 2, str_size);
		marshal_u32(header_length, filesize);
		kannotate_write(header, sizeof(header));
		kannotate_write(param->user_msg, str_size);
		kannotate_write(header_length, sizeof(header_length));

		kannotate_write((const char*)&bm, sizeof(bm));

		if (current == NULL)
			pid = 0;
		else
			pid = current->pid;
	}

	/* write the bitmap body*/

	/* copy one pixel for each 4x4 block */
	{
		//int src_x = crop_x;
		//int src_y = crop_y;
		u64 time;
		int gator_header_written = 0;
		int cpu = 0;
		int contiguous = 0;
		int total_bytes_written = 0;
		int pack_bytes_written = 0;

		int dst_x = 0;
		int dst_y = 0;
		void* pSrcRow = param->ori_data + (param->crop_y * ori_pitch);
		//void* pDstRow = bits;
		void* write_ptr = NULL;

#if TSAI_SPINLOCK_IRQ
		spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
		spin_lock(&annotate_lock);
#endif


		for (;dst_y < copy_height; dst_y++) {
			void* pSrcPixel = pSrcRow + (param->crop_x << 2);
			//void* pDstPixel = pDstRow;

			for (dst_x=0; dst_x < copy_width; dst_x++) {
				int write;
HeaderCheck:
				if (!gator_header_written) {

					int bytes_remaning = copy_image_size - total_bytes_written;
HeaderRetry:
					contiguous = contiguous_space_available(cpu, ANNOTATE_BUF);
					if (contiguous < (MAXSIZE_PACK32 * 3 + MAXSIZE_PACK64) ) {
						/* too small, get some space */
						time = gator_get_time();
						buffer_check(cpu, ANNOTATE_BUF, time);

						printk("raw_image_onthefly written %u/%u conti %u",
								total_bytes_written, copy_image_size, contiguous);

						/* give other thread a chance to do something*/
#if TSAI_SPINLOCK_IRQ
						spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
						spin_unlock(&annotate_lock);
#endif
						wait_event_interruptible(gator_annotate_wait, raw_image_onthefly_wake_up_condition(cpu) );

						/* Check to see if a signal is pending */
						if (signal_pending(current)) {
							retval = -EINTR; goto Leave;
						}

						if (!collect_annotations) {
							goto Leave;
						}
#if TSAI_SPINLOCK_IRQ
						spin_lock_irqsave(&annotate_lock, annotate_lock_flags);
#else
						spin_lock(&annotate_lock);
#endif
						goto HeaderRetry;
					}
					/* reserve necessary space for packet headers, and then align to 4byte boundary */
					contiguous -= (MAXSIZE_PACK32 * 3 + MAXSIZE_PACK64);
					contiguous &= ~(unsigned)0x03;

					if (contiguous > bytes_remaning) {
						contiguous = bytes_remaning;
					}
					{
						u64 time = gator_get_time();
						gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, get_physical_cpu());
						gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, pid);
						gator_buffer_write_packed_int64(cpu, ANNOTATE_BUF, time);
						gator_buffer_write_packed_int(cpu, ANNOTATE_BUF, contiguous);
					}

					write = per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF];
					write_ptr = &per_cpu(gator_buffer, cpu)[ANNOTATE_BUF][write];
					pack_bytes_written = 0;
					gator_header_written = 1;

				}
				if ( (pack_bytes_written + dst_pixel_incre) > contiguous) {
					/* start another packet */
					total_bytes_written += pack_bytes_written;

					write = per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF];
					per_cpu(gator_buffer_write, cpu)[ANNOTATE_BUF] = (write + pack_bytes_written) & gator_buffer_mask[ANNOTATE_BUF];

					time = gator_get_time();
					buffer_check(cpu, ANNOTATE_BUF, time);
					gator_header_written = 0;
					goto HeaderCheck;
				}

				/* *(unsigned long*)pDstPixel = *(unsigned long*) pSrcPixel; */
				/* write one pixel */
				*(unsigned long*)write_ptr = *(unsigned long*) pSrcPixel;

				write_ptr += dst_pixel_incre;
				pack_bytes_written += dst_pixel_incre;
				pSrcPixel += src_pixel_incre;
				/* pDstPixel += dst_pixel_incre; */

			}

			pSrcRow += src_pitch_incre; /* move on by 2 rows */
			//pDstRow += copy_pitch;
		}

#if TSAI_SPINLOCK_IRQ
		spin_unlock_irqrestore(&annotate_lock, annotate_lock_flags);
#else
		spin_unlock(&annotate_lock);
#endif
	}
Leave:
	return retval;
}

extern void tsai_bufinfo_os_vsync(uint64_t os_ts, u32 seqno);
extern void gator_annotate_channel_color_ts(int channel, int color, const char *str, u64* ts, int* ppid);

#ifdef HAVE_UNLOCKED_IOCTL
	static long annotate_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#else
	static int annotate_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
	int err = 0;
	switch (cmd) {
	case SRUK_GATOR_IOCTL_ANNOTATE_RAW_IMAGE:
		{
			struct gator_annotate_raw_image_param* param;
			param = (struct gator_annotate_raw_image_param*) arg;
			//__asm("bkpt");
			//err = gator_annotate_raw_image_onthefly(param); /* still testing */
			err = gator_annotate_raw_image(param);
		}
		break;
	case SRUK_GATOR_IOCTL_IN_CAPTURE:
			err = gator_started?1:0;
		break;
	case SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_COLOR:
		{
			struct tsai_gator_common_parameter* p = (struct tsai_gator_common_parameter*)arg;
			const char* str;
#if defined(__LP64__) && __LP64__
			str = (const char*)p->str;
#else
			str = (const char*)(u32)p->str;
#endif
			gator_annotate_channel_color(p->channel, p->color, str);
		}
		break;
	case SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_COLOR_TS:
		{
			struct tsai_gator_common_parameter* p = (struct tsai_gator_common_parameter*)arg;
			const char* str;
#if defined(__LP64__) && __LP64__
			str = (const char*)p->str;
#else
			str = (const char*)(u32)p->str;
#endif
			gator_annotate_channel_color_ts(p->channel, p->color, str, &p->ts, 0);
		}
		break;
	case SRUK_GATOR_IOCTL_ANNOTATE_CHANNEL_END:
		{
			struct tsai_gator_common_parameter* p = (struct tsai_gator_common_parameter*)arg;
			gator_annotate_channel_end(p->channel);
		}
		break;
	case SRUK_GATOR_IOCTL_OS_VSYNC:
		{
			struct tsai_os_vsync_param* p = (struct tsai_os_vsync_param*)arg;
			tsai_bufinfo_os_vsync(p->ts, p->seqno);
		}
		break;
	case SRUK_GATOR_IOCTL_ANNOTATE_GET_TS:
		{
			struct tsai_gator_get_ts* p = (struct tsai_gator_get_ts*)arg;
			p->ts = gator_annotate_get_ts();
					//u64 gator_annotate_get_ts(void)
		}
		break;
	default:
		BKPT;
	}

	return err;
}

/* use this structure to share data with user mode directly through memory pointer */
struct GATOR_DATA_USER_SHARE {
	unsigned int id;
	int gator_started;
};

static struct GATOR_DATA_USER_SHARE* tsai_gator_user_share;
static unsigned long long tsai_gator_user_share_paddr;

struct tsai_debug_mmap_log {
	unsigned int pid;
	const char* comm_p;
	const char* comm_t;
	void* vaddr;
};

struct tsai_debug_mmap_log tsai_mmap_log[128];
unsigned tsai_debug_mmap_log_cnt;

#if defined(__aarch64__)
/* 20190204: likely the same have been included through kernel/arch/arm64/include/asm/io.h*/
#else
	#include <asm-generic/io.h>
#endif

int tsai_spy_monitor_mmu_change(void* virtual_addr, struct mm_struct* mm);

static int tsai_annotate_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	unsigned long vaddr;
	unsigned long pfn;
	int ret;
	vaddr = (unsigned long)tsai_gator_user_share;
	pfn = __phys_to_pfn(tsai_gator_user_share_paddr);
	ret = remap_pfn_range(vma, vma->vm_start, pfn,
			vma->vm_end - vma->vm_start, vma->vm_page_prot);

#if 1
	{
		struct task_struct* p;
		struct tsai_debug_mmap_log* l = &tsai_mmap_log[tsai_debug_mmap_log_cnt];
		tsai_debug_mmap_log_cnt = (tsai_debug_mmap_log_cnt+1) % 128;
		p = pid_task(find_vpid(current->tgid), PIDTYPE_PID);

		l->pid = current->pid;
		l->comm_p = p->comm;
		l->comm_t = current->comm;
		l->vaddr = (void*)vma->vm_start;
	}
#endif
#if 0
	tsai_spy_monitor_mmu_change((void*)vma->vm_start, NULL);
#endif
	return ret;
}

static int tsai_annotate_open(struct inode *inode, struct file *file) {
	/* since I want to use mmap, O_TRUCATE will get in the way and whenever it is open,
	 * previous mmap will be affected and map to zero page, so get rid of unwanted flags here! */
	//file->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	inode->i_mode &= ~S_IFREG;

	return 0;
}

static int tsai_annotate_init(void) {
	struct page* pg;
	tsai_gator_user_share = (struct GATOR_DATA_USER_SHARE*)vmalloc_user(4096);

	pg = vmalloc_to_page( (const void *) tsai_gator_user_share);
	tsai_gator_user_share_paddr = page_to_phys(pg);

	tsai_gator_user_share->id = 'G' | 'A'<<8 | 'T'<<16 | 'R' <<24;

	return 0;
}

extern void tsai_bufinfo_capture_start(void);
extern void tsai_bufinfo_capture_stop(void);

static void tsai_annotate_start(void) {
	if (tsai_gator_user_share)
		tsai_gator_user_share->gator_started = 1;

	tsai_bufinfo_capture_start();
}

static void tsai_annotate_stop(void) {
	if (tsai_gator_user_share)
		tsai_gator_user_share->gator_started = 0;

	tsai_bufinfo_capture_stop();
}

/*
-000|tsai_annotate_start()
    |
-001|gator_annotate_start()
    |
    |#if TSAI_IOCTL
    |        //__asm("bkpt");
    |        tsai_annotate_start();
-002|gator_start()
    |  cpu = 8
    |  i = 9
    |  gi = 0xFFFFFFBFFC0B9F20
    |
    |        if (gator_annotate_start())
-003|gator_op_start()
    |  err = 0
    |
    |        if (gator_started || gator_start())
-004|enable_write(
-005|vfs_write(
-006|SYSC_write(inline)
-006|sys_write(
-007|ret_fast_syscall(asm)
 */

#endif /* SRUK_GATOR_ANNOTATE_IOCTL_H_ */
