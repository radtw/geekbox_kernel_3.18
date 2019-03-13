/*************************************************************************/ /*!
@File
@Title          RGX HW Performance implementation
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Description    RGX HW Performance implementation
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

//#define PVR_DPF_FUNCTION_TRACE_ON 1
#undef PVR_DPF_FUNCTION_TRACE_ON

#include "pvr_debug.h"
#include "osfunc.h"
#include "allocmem.h"

#include "pvrsrv.h"
#include "tlclient.h"
#include "tlstream.h"

#include "rgx_hwperf_km.h"
#include "rgxhwperf.h"
#include "rgxapi_km.h"
#include "rgxfwutils.h"
#if TSAI
#include "rgxtimecorr.h"
#endif
#include "devicemem_pdump.h"

#if defined(SUPPORT_GPUTRACE_EVENTS)
#include "pvr_gputrace.h"
#endif

#if TSAI
	#include "tsai_macro.h"
#endif
#if TSAI_DS5
	#include "streamline_annotate.h"
	IMG_UINT64 OSClockns64(void);
#endif
#if TSAI
	extern int tsai_PPJobToGem(int job_id);
#endif

#define HWPERF_TL_STREAM_NAME  "hwperf"

/* Defined to ensure HWPerf packets are not delayed */
#define SUPPORT_TL_PROODUCER_CALLBACK 1


/******************************************************************************
 *
 *****************************************************************************/


/*
	RGXHWPerfCopyDataL1toL2
*/
static IMG_UINT32 RGXHWPerfCopyDataL1toL2(IMG_HANDLE hHWPerfStream,
										  IMG_BYTE   *pbFwBuffer, 
										  IMG_UINT32 ui32BytesExp)
{
  	IMG_BYTE 	 *pbL2Buffer;
	IMG_UINT32   ui32L2BufFree;
	IMG_UINT32   ui32BytesCopied = 0;
	IMG_UINT32   ui32BytesExpMin = RGX_HWPERF_GET_SIZE(RGX_HWPERF_GET_PACKET(pbFwBuffer));
	PVRSRV_ERROR eError;

/* HWPERF_MISR_FUNC_DEBUG enables debug code for investigating HWPerf issues */
#ifdef HWPERF_MISR_FUNC_DEBUG
	static IMG_UINT32 gui32Ordinal = IMG_UINT32_MAX;
#endif

	PVR_DPF_ENTERED;

#ifdef HWPERF_MISR_FUNC_DEBUG
	PVR_DPF((PVR_DBG_VERBOSE, "EVENTS to copy from 0x%p length:%05d",
							  pbFwBuffer, ui32BytesExp));
#endif

#ifdef HWPERF_MISR_FUNC_DEBUG
	{
		/* Check the incoming buffer of data has not lost any packets */
 	 	IMG_BYTE *pbFwBufferIter = pbFwBuffer;
 	 	IMG_BYTE *pbFwBufferEnd = pbFwBuffer+ui32BytesExp;
	 	do
		{
			RGX_HWPERF_V2_PACKET_HDR *asCurPos = RGX_HWPERF_GET_PACKET(pbFwBufferIter);
			IMG_UINT32 ui32CurOrdinal = asCurPos->ui32Ordinal;
			if (gui32Ordinal != IMG_UINT32_MAX)
			{
				if ((gui32Ordinal+1) != ui32CurOrdinal)
				{
					if (gui32Ordinal < ui32CurOrdinal)
					{
						PVR_DPF((PVR_DBG_WARNING,
								 "HWPerf [%p] packets lost (%u packets) between ordinal %u...%u",
								 pbFwBufferIter,
								 ui32CurOrdinal - gui32Ordinal - 1,
								 gui32Ordinal,
								 ui32CurOrdinal));
					}
					else
					{
						PVR_DPF((PVR_DBG_WARNING,
								 "HWPerf [%p] packet ordinal out of sequence last: %u, current: %u",
								  pbFwBufferIter,
								  gui32Ordinal,
								  ui32CurOrdinal));
					}
				}
			}
			gui32Ordinal = asCurPos->ui32Ordinal;
			pbFwBufferIter += RGX_HWPERF_GET_SIZE(asCurPos);
		} while( pbFwBufferIter < pbFwBufferEnd );
	}
#endif

	/* Try submitting all data in one TL packet. */
	eError = TLStreamReserve2( hHWPerfStream, 
							   &pbL2Buffer, 
							   (IMG_SIZE_T)ui32BytesExp, ui32BytesExpMin,
							   &ui32L2BufFree);
	if ( eError == PVRSRV_OK )
	{
		OSMemCopy( pbL2Buffer, pbFwBuffer, (IMG_SIZE_T)ui32BytesExp );
		eError = TLStreamCommit(hHWPerfStream, (IMG_SIZE_T)ui32BytesExp);
		if ( eError != PVRSRV_OK )
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "TLStreamCommit() failed (%d) in %s(), unable to copy packet from L1 to L2 buffer",
					 eError, __func__));
			goto e0;
		}
		/* Data were successfully written */
		ui32BytesCopied = ui32BytesExp;
	}
	else if (eError == PVRSRV_ERROR_STREAM_FULL)
	{
		/* There was not enough space for all data, copy as much as possible */
		IMG_UINT32                sizeSum  = 0;
		RGX_PHWPERF_V2_PACKET_HDR psCurPkt = RGX_HWPERF_GET_PACKET(pbFwBuffer);

		PVR_DPF((PVR_DBG_MESSAGE, "Unable to reserve space (%d) in host buffer on first attempt, remaining free space: %d", ui32BytesExp, ui32L2BufFree));

		/* Traverse the array to find how many packets will fit in the available space. */
		while ( sizeSum < ui32BytesExp  &&
				sizeSum + RGX_HWPERF_GET_SIZE(psCurPkt) < ui32L2BufFree )
		{
			sizeSum += RGX_HWPERF_GET_SIZE(psCurPkt);
			psCurPkt = RGX_HWPERF_GET_NEXT_PACKET(psCurPkt);
		}

		if ( 0 != sizeSum )
		{
			eError = TLStreamReserve( hHWPerfStream, &pbL2Buffer, (IMG_SIZE_T)sizeSum);

			if ( eError == PVRSRV_OK )
			{
				OSMemCopy( pbL2Buffer, pbFwBuffer, (IMG_SIZE_T)sizeSum );
				eError = TLStreamCommit(hHWPerfStream, (IMG_SIZE_T)sizeSum);
				if ( eError != PVRSRV_OK )
				{
					PVR_DPF((PVR_DBG_ERROR,
							 "TLStreamCommit() failed (%d) in %s(), unable to copy packet from L1 to L2 buffer",
							 eError, __func__));
					goto e0;
				}
				/* sizeSum bytes of hwperf packets have been successfully written */
				ui32BytesCopied = sizeSum;
			}
			else if ( PVRSRV_ERROR_STREAM_FULL == eError )
			{
				PVR_DPF((PVR_DBG_WARNING, "Can not write HWPerf packet into host buffer, check data in case of packet loss, remaining free space: %d", ui32L2BufFree));
			}
		}
		else
		{
			PVR_DPF((PVR_DBG_MESSAGE, "Can not find space in host buffer, check data in case of packet loss, remaining free space: %d", ui32L2BufFree));
		}
	}
	if ( PVRSRV_OK != eError && /*  Some other error occurred */
	     PVRSRV_ERROR_STREAM_FULL != eError ) /* Full error handled by caller, we returning the copied bytes count to caller*/
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "HWPerf enabled: Unexpected Error ( %d ) while copying FW buffer to TL buffer.",
				 eError));
	}

e0:
	/* Return the remaining packets left to be transported. */
	PVR_DPF_RETURN_VAL(ui32BytesCopied);
}


static INLINE IMG_UINT32 RGXHWPerfAdvanceRIdx(
		const IMG_UINT32 ui32BufSize,
		const IMG_UINT32 ui32Pos,
		const IMG_UINT32 ui32Size)
{
	return (  ui32Pos + ui32Size < ui32BufSize ? ui32Pos + ui32Size : 0 );
}

#ifdef TSAI_GATOR
	/* save this variable, so that tlstream.c can use it, an array of 8 for 8 cores */
	PVRSRV_RGXDEV_INFO* tsai_psDevInfo[8];
#endif

/*
	RGXHWPerfDataStore
*/
static IMG_UINT32 RGXHWPerfDataStore(PVRSRV_RGXDEV_INFO	*psDevInfo)
{
	RGXFWIF_TRACEBUF    *psRGXFWIfTraceBufCtl = psDevInfo->psRGXFWIfTraceBuf;
	IMG_BYTE*           psHwPerfInfo = psDevInfo->psRGXFWIfHWPerfBuf;
	IMG_UINT32			ui32SrcRIdx, ui32SrcWIdx, ui32SrcWrapCount;
	IMG_UINT32			ui32BytesExp = 0, ui32BytesCopied = 0, ui32BytesCopiedSum = 0;
#ifdef HWPERF_MISR_FUNC_DEBUG
	IMG_UINT32			ui32BytesExpSum = 0;
#endif
#if 0 && TSAI_GATOR
	IMG_BYTE* pBuf = psHwPerfInfo + psRGXFWIfTraceBufCtl->ui32HWPerfRIdx;
	IMG_UINT32 len;
#endif
	
	PVR_DPF_ENTERED;

#ifdef TSAI_GATOR
	{
		int cpu = smp_processor_id();
		tsai_psDevInfo[cpu] = psDevInfo;
	}
#endif
	/* Caller should check this member is valid before calling */
	PVR_ASSERT(psDevInfo->hHWPerfStream);
	
 	/* Get a copy of the current
	 *   read (first packet to read) 
	 *   write (empty location for the next write to be inserted) 
	 *   WrapCount (size in bytes of the buffer at or past end)
	 * indexes of the FW buffer */
	ui32SrcRIdx = psRGXFWIfTraceBufCtl->ui32HWPerfRIdx;
	ui32SrcWIdx = psRGXFWIfTraceBufCtl->ui32HWPerfWIdx;
	OSMemoryBarrier();
	ui32SrcWrapCount = psRGXFWIfTraceBufCtl->ui32HWPerfWrapCount;

	/* Is there any data in the buffer not yet retrieved? */
	if ( ui32SrcRIdx != ui32SrcWIdx )
	{
		PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfDataStore EVENTS found srcRIdx:%d srcWIdx: %d ", ui32SrcRIdx, ui32SrcWIdx));

		/* Is the write position higher than the read position? */
		if ( ui32SrcWIdx > ui32SrcRIdx )
		{
			/* Yes, buffer has not wrapped */
			ui32BytesExp  = ui32SrcWIdx - ui32SrcRIdx;
#ifdef HWPERF_MISR_FUNC_DEBUG
			ui32BytesExpSum += ui32BytesExp;
#endif
			ui32BytesCopied = RGXHWPerfCopyDataL1toL2(psDevInfo->hHWPerfStream,
													  psHwPerfInfo + ui32SrcRIdx,
													  ui32BytesExp);
			ui32BytesCopiedSum += ui32BytesCopied;

			/* Advance the read index and the free bytes counter by the number
			 * of bytes transported. Items will be left in buffer if not all data
			 * could be transported. Exit to allow buffer to drain. */
			psRGXFWIfTraceBufCtl->ui32HWPerfRIdx = RGXHWPerfAdvanceRIdx(
					psDevInfo->ui32RGXFWIfHWPerfBufSize, ui32SrcRIdx,
					ui32BytesCopied);
		}
		/* No, buffer has wrapped and write position is behind read position */
		else
		{
			/* Byte count equal to 
			 *     number of bytes from read position to the end of the buffer, 
			 *   + data in the extra space in the end of the buffer. */
			ui32BytesExp = ui32SrcWrapCount - ui32SrcRIdx;

#ifdef HWPERF_MISR_FUNC_DEBUG
			ui32BytesExpSum += ui32BytesExp;
#endif
			/* Attempt to transfer the packets to the TL stream buffer */
			ui32BytesCopied = RGXHWPerfCopyDataL1toL2(psDevInfo->hHWPerfStream,
													  psHwPerfInfo + ui32SrcRIdx,
													  ui32BytesExp);
			ui32BytesCopiedSum += ui32BytesCopied;

			/* Advance read index as before and Update the local copy of the
			 * read index as it might be used in the last if branch*/
			ui32SrcRIdx = RGXHWPerfAdvanceRIdx(
					psDevInfo->ui32RGXFWIfHWPerfBufSize, ui32SrcRIdx,
					ui32BytesCopied);

			/* Update Wrap Count */
			if ( ui32SrcRIdx == 0)
			{
				psRGXFWIfTraceBufCtl->ui32HWPerfWrapCount = psDevInfo->ui32RGXFWIfHWPerfBufSize;
			}
			psRGXFWIfTraceBufCtl->ui32HWPerfRIdx = ui32SrcRIdx;
			
			/* If all the data in the end of the array was copied, try copying
			 * wrapped data in the beginning of the array, assuming there is
			 * any and the RIdx was wrapped. */
			if (   (ui32BytesCopied == ui32BytesExp)
			    && (ui32SrcWIdx > 0) 
				&& (ui32SrcRIdx == 0) )
			{
				ui32BytesExp = ui32SrcWIdx;
#ifdef HWPERF_MISR_FUNC_DEBUG
				ui32BytesExpSum += ui32BytesExp;
#endif
				ui32BytesCopied = RGXHWPerfCopyDataL1toL2(psDevInfo->hHWPerfStream,
														  psHwPerfInfo,
														  ui32BytesExp);
				ui32BytesCopiedSum += ui32BytesCopied;
				/* Advance the FW buffer read position. */
				psRGXFWIfTraceBufCtl->ui32HWPerfRIdx = RGXHWPerfAdvanceRIdx(
						psDevInfo->ui32RGXFWIfHWPerfBufSize, ui32SrcRIdx,
						ui32BytesCopied);
			}
		}
#if 0 && TSAI_GATOR /* if this is a better place to process packets? */
		{
			len = ui32BytesCopiedSum;
			BKPT;
			RGXHWPerfFTraceGPUProcessPackets(psDevInfo, pBuf, len );
		}
#endif
#ifdef HWPERF_MISR_FUNC_DEBUG
		if (ui32BytesCopiedSum != ui32BytesExpSum)
		{
			PVR_DPF((PVR_DBG_WARNING, "RGXHWPerfDataStore: FW L1 RIdx:%u. Not all bytes copied to L2: %u bytes out of %u expected", psRGXFWIfTraceBufCtl->ui32HWPerfRIdx, ui32BytesCopiedSum, ui32BytesExpSum));
		}
#endif

	}
	else
	{
		PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfDataStore NO EVENTS to transport"));
	}

	PVR_DPF_RETURN_VAL(ui32BytesCopiedSum);
}


PVRSRV_ERROR RGXHWPerfDataStoreCB(PVRSRV_DEVICE_NODE *psDevInfo)
{
	PVRSRV_ERROR		eError = PVRSRV_OK;
	PVRSRV_RGXDEV_INFO* psRgxDevInfo;
	IMG_UINT32          ui32BytesCopied;


	PVR_DPF_ENTERED;

	PVR_ASSERT(psDevInfo);
	psRgxDevInfo = psDevInfo->pvDevice;
#if 0 && TSAI_DS5
	ANNOTATE_CHANNEL_COLOR(4, ANNOTATE_RED, "RGXHWPerfDataStoreCB");
#endif

	if (psRgxDevInfo->hHWPerfStream != 0)
	{
		OSLockAcquire(psRgxDevInfo->hLockHWPerfStream);
		ui32BytesCopied = RGXHWPerfDataStore(psRgxDevInfo);
		OSLockRelease(psRgxDevInfo->hLockHWPerfStream);

		if ( ui32BytesCopied )
		{	/* Signal consumers that packets may be available to read when
		     * running from a HW kick, not when called by client APP thread
			 * via the transport layer CB as this can lead to stream
			 * corruption.*/
			eError = TLStreamSync(psRgxDevInfo->hHWPerfStream);
			PVR_ASSERT(eError == PVRSRV_OK);
		}
        else
        {
            PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfDataStoreCB: Zero bytes copied from FW L1 to L2."));
        }
	}

#if 0 && TSAI_DS5
	ANNOTATE_CHANNEL_END(4);
#endif
	PVR_DPF_RETURN_OK;
}


/* Not currently supported by default */
#if defined(SUPPORT_TL_PROODUCER_CALLBACK)
static PVRSRV_ERROR RGXHWPerfTLCB(IMG_HANDLE hStream,
		IMG_UINT32 ui32ReqOp, IMG_UINT32* ui32Resp, IMG_VOID* pvUser)
{
	PVRSRV_ERROR eError = PVRSRV_OK;
	PVRSRV_RGXDEV_INFO* psRgxDevInfo = (PVRSRV_RGXDEV_INFO*)pvUser;

	PVR_UNREFERENCED_PARAMETER(hStream);
	PVR_UNREFERENCED_PARAMETER(ui32Resp);

	PVR_ASSERT(psRgxDevInfo);

	switch (ui32ReqOp)
	{
	case TL_SOURCECB_OP_CLIENT_EOS:
		if (psRgxDevInfo->hHWPerfStream != 0)
		{
			OSLockAcquire(psRgxDevInfo->hLockHWPerfStream);
			(void) RGXHWPerfDataStore(psRgxDevInfo);
			OSLockRelease(psRgxDevInfo->hLockHWPerfStream);
		}
		break;

	default:
		break;
	}

	return eError;
}
#endif


/* References to key objects to allow kernel-side behaviour to function
 * e.g. FTrace and KM interface to HWPerf.
 */
static PVRSRV_DEVICE_NODE* gpsRgxDevNode = IMG_NULL;
static PVRSRV_RGXDEV_INFO* gpsRgxDevInfo = IMG_NULL;


PVRSRV_ERROR RGXHWPerfInit(PVRSRV_DEVICE_NODE *psRgxDevNode, IMG_BOOL bEnable)
{
	PVRSRV_ERROR eError;
	IMG_UINT32 ui32L2BufferSize;

	PVR_DPF_ENTERED;

	/* On first call at driver initialisation we get the RGX device,
	 * in later on-demand calls this parameter is optional. */
	if (psRgxDevNode)
	{
		gpsRgxDevNode = psRgxDevNode;
		gpsRgxDevInfo = psRgxDevNode->pvDevice;
	}

	/* Before proper initialisation make sure we have a valid RGX device. */
	if (!gpsRgxDevInfo)
	{
		PVR_DPF((PVR_DBG_ERROR, "HWPerf module not initialised"));
		PVR_DPF_RETURN_RC(PVRSRV_ERROR_INVALID_DEVICE);
	}

	/* Initialise first in case of an error condition or if it is not enabled
	 */
	gpsRgxDevInfo->hLockHWPerfStream = IMG_NULL;
	gpsRgxDevInfo->hHWPerfStream = IMG_NULL;

	/* Does the caller want to enable data collection resources? */
	if (!bEnable)
	{
		PVR_DPF_RETURN_OK;
	}

	/* Create the HWPerf stream lock used for multiple stream writers when
	 * configured e.g. TL producer callback
	 */
	eError = OSLockCreate(&gpsRgxDevInfo->hLockHWPerfStream, LOCK_TYPE_PASSIVE);
	PVR_LOGR_IF_ERROR(eError, "OSLockCreate");

	/* Host L2 HWPERF buffer size in bytes must be bigger than the L1 buffer
	 * accessed by the FW. The MISR may try to write one packet the size of the L1
	 * buffer in some scenarios. When logging is enabled in the MISR, it can be seen
	 * if the L2 buffer hits a full condition. The closer in size the L2 and L1 buffers
	 * are the more chance of this happening.
	 * Size chosen to allow MISR to write an L1 sized packet and for the client
	 * application/daemon to drain a L1 sized packet e.g. ~ 2xL1+64 working space.
	 * 
	 * However in the case of NO_HARDWARE the L2 buffer will not be used.
	 * By reducing the size of the L2 buffer we can support a larger L1 buffer size
	 * since on a 32-bit system, vmalloc memory is limited.
	 */
#if defined(NO_HARDWARE)
	ui32L2BufferSize = 0;
#else
	ui32L2BufferSize = gpsRgxDevInfo->ui32RGXFWIfHWPerfBufSize<<1;
#endif
	eError = TLStreamCreate(&gpsRgxDevInfo->hHWPerfStream, HWPERF_TL_STREAM_NAME,
					ui32L2BufferSize+RGXFW_HWPERF_L1_PADDING_DEFAULT,
					TL_FLAG_DROP_DATA | TL_FLAG_NO_SIGNAL_ON_COMMIT,
#if !defined(SUPPORT_TL_PROODUCER_CALLBACK)
					IMG_NULL, IMG_NULL
#else
                    /* Not enabled  by default */
					RGXHWPerfTLCB, gpsRgxDevInfo
#endif
					);

	PVR_LOGG_IF_ERROR(eError, "TLStreamCreate", e1);

	PVR_DPF_RETURN_OK;

e1:
	OSLockDestroy(gpsRgxDevInfo->hLockHWPerfStream);
	gpsRgxDevInfo->hLockHWPerfStream = IMG_NULL;
	gpsRgxDevInfo->hHWPerfStream = IMG_NULL;
/* e0: */
	PVR_DPF_RETURN_RC(eError);
}


IMG_VOID RGXHWPerfDeinit(void)
{
	PVR_DPF_ENTERED;

	/* Clean up the stream and lock objects if allocated
	 */
	if (gpsRgxDevInfo && gpsRgxDevInfo->hHWPerfStream)
	{
		TLStreamClose(gpsRgxDevInfo->hHWPerfStream);
		gpsRgxDevInfo->hHWPerfStream = IMG_NULL;
	}
	if (gpsRgxDevInfo && gpsRgxDevInfo->hLockHWPerfStream)
	{
		OSLockDestroy(gpsRgxDevInfo->hLockHWPerfStream);
		gpsRgxDevInfo->hLockHWPerfStream = IMG_NULL;
	}

	/* Clear global RGX device reference
	 */
	gpsRgxDevInfo = IMG_NULL;
	gpsRgxDevNode = IMG_NULL;

	PVR_DPF_RETURN;
}


/******************************************************************************
 * RGX HW Performance Profiling Server API(s)
 *****************************************************************************/
/*
	PVRSRVRGXCtrlHWPerfKM
*/
PVRSRV_ERROR PVRSRVRGXCtrlHWPerfKM(
		PVRSRV_DEVICE_NODE*	psDeviceNode,
		IMG_BOOL			bToggle,
		IMG_UINT64 			ui64Mask)
{
	PVRSRV_ERROR 		eError = PVRSRV_OK;
	PVRSRV_RGXDEV_INFO* psDevice;
	RGXFWIF_KCCB_CMD 	sKccbCmd;

	PVR_DPF_ENTERED;
	PVR_ASSERT(psDeviceNode);
	psDevice = psDeviceNode->pvDevice;

	/* If this method is being used whether to enable or disable
	 * then the hwperf stream is likely to be needed eventually so create it,
	 * also helps unit testing.
	 * Stream allocated on demand to reduce RAM foot print on systems not
	 * needing HWPerf resources.
	 */
	if (psDevice->hHWPerfStream == IMG_NULL)
	{
		eError = RGXHWPerfInit(psDeviceNode, IMG_TRUE);
		PVR_LOGR_IF_ERROR(eError, "RGXHWPerfInit");
	}

	/* Prepare command parameters ...
	 */
	sKccbCmd.eCmdType = RGXFWIF_KCCB_CMD_HWPERF_CTRL_EVENTS;
	sKccbCmd.uCmdData.sHWPerfCtrl.bToggle = bToggle;
	sKccbCmd.uCmdData.sHWPerfCtrl.ui64Mask = ui64Mask;

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfKM parameters set, calling FW")); */

	/* Ask the FW to carry out the HWPerf configuration command
	 */
	eError = RGXScheduleCommand(psDeviceNode->pvDevice,	RGXFWIF_DM_GP, 
								&sKccbCmd, sizeof(sKccbCmd), IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGR_IF_ERROR(eError, "RGXScheduleCommand");
	}

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfKM command scheduled for FW")); */

	/* Wait for FW to complete
	 */
	eError = RGXWaitForFWOp(psDeviceNode->pvDevice, RGXFWIF_DM_GP, psDeviceNode->psSyncPrim, IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGR_IF_ERROR(eError, "RGXWaitForFWOp");
	}

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfKM firmware completed")); */

	/* If it was being asked to disable then don't delete the stream as the FW
	 * will continue to generate events during the disabling phase. Clean up
	 * will be done when the driver is unloaded.
	 * The increase in extra memory used by the stream would only occur on a
	 * developer system and not a production device as a user would never
	 * enable HWPerf. If this is not the case then a deferred clean system will
	 * need to be implemented.
	 */
	/*if ((!bEnable) && (psDevice->hHWPerfStream))
	{
		TLStreamDestroy(psDevice->hHWPerfStream);
		psDevice->hHWPerfStream = 0;
	}*/

#if defined(DEBUG)
	if (bToggle)
	{
		PVR_DPF((PVR_DBG_WARNING, "HWPerf events (%llx) have been TOGGLED", ui64Mask));
	}
	else
	{
		PVR_DPF((PVR_DBG_WARNING, "HWPerf mask has been SET to (%llx)", ui64Mask));
	}
#endif

	PVR_DPF_RETURN_OK;
}


/*
	PVRSRVRGXEnableHWPerfCountersKM
*/
PVRSRV_ERROR PVRSRVRGXConfigEnableHWPerfCountersKM(
		PVRSRV_DEVICE_NODE* 		psDeviceNode,
		IMG_UINT32 					ui32ArrayLen,
		RGX_HWPERF_CONFIG_CNTBLK* 	psBlockConfigs)
{
	PVRSRV_ERROR 		eError = PVRSRV_OK;
	RGXFWIF_KCCB_CMD 	sKccbCmd;
	DEVMEM_MEMDESC*		psFwBlkConfigsMemDesc;
	RGX_HWPERF_CONFIG_CNTBLK* psFwArray;

	PVR_DPF_ENTERED;

	PVR_ASSERT(psDeviceNode);
	PVR_ASSERT(ui32ArrayLen>0);
	PVR_ASSERT(psBlockConfigs);

	/* Fill in the command structure with the parameters needed
	 */
	sKccbCmd.eCmdType = RGXFWIF_KCCB_CMD_HWPERF_CONFIG_ENABLE_BLKS;
	sKccbCmd.uCmdData.sHWPerfCfgEnableBlks.ui32NumBlocks = ui32ArrayLen;

	eError = DevmemFwAllocate(psDeviceNode->pvDevice,
			sizeof(RGX_HWPERF_CONFIG_CNTBLK)*ui32ArrayLen, 
			PVRSRV_MEMALLOCFLAG_DEVICE_FLAG(PMMETA_PROTECT) |
									  PVRSRV_MEMALLOCFLAG_GPU_READABLE | 
					                  PVRSRV_MEMALLOCFLAG_GPU_WRITEABLE |
									  PVRSRV_MEMALLOCFLAG_CPU_READABLE |
									  PVRSRV_MEMALLOCFLAG_KERNEL_CPU_MAPPABLE | 
									  PVRSRV_MEMALLOCFLAG_UNCACHED |
									  PVRSRV_MEMALLOCFLAG_ZERO_ON_ALLOC,
			"HWPerfCountersConfigBlock",
			&psFwBlkConfigsMemDesc);
	if (eError != PVRSRV_OK)
		PVR_LOGR_IF_ERROR(eError, "DevmemFwAllocate");

	RGXSetFirmwareAddress(&sKccbCmd.uCmdData.sHWPerfCfgEnableBlks.pasBlockConfigs,
			psFwBlkConfigsMemDesc, 0, 0);

	eError = DevmemAcquireCpuVirtAddr(psFwBlkConfigsMemDesc, (IMG_VOID **)&psFwArray);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGG_IF_ERROR(eError, "DevmemAcquireCpuVirtAddr", fail1);
	}

	OSMemCopy(psFwArray, psBlockConfigs, sizeof(RGX_HWPERF_CONFIG_CNTBLK)*ui32ArrayLen);
	DevmemPDumpLoadMem(psFwBlkConfigsMemDesc,
						0,
						sizeof(RGX_HWPERF_CONFIG_CNTBLK)*ui32ArrayLen,
						0);

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXConfigEnableHWPerfCountersKM parameters set, calling FW")); */

	/* Ask the FW to carry out the HWPerf configuration command
	 */
	eError = RGXScheduleCommand(psDeviceNode->pvDevice,
			RGXFWIF_DM_GP, &sKccbCmd, sizeof(sKccbCmd), IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGG_IF_ERROR(eError, "RGXScheduleCommand", fail2);
	}

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXConfigEnableHWPerfCountersKM command scheduled for FW")); */

	/* Wait for FW to complete */
	eError = RGXWaitForFWOp(psDeviceNode->pvDevice, RGXFWIF_DM_GP, psDeviceNode->psSyncPrim, IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGG_IF_ERROR(eError, "RGXWaitForFWOp", fail2);
	}

	/* Release temporary memory used for block configuration
	 */
	RGXUnsetFirmwareAddress(psFwBlkConfigsMemDesc);
	DevmemReleaseCpuVirtAddr(psFwBlkConfigsMemDesc);
	DevmemFwFree(psFwBlkConfigsMemDesc);

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXConfigEnableHWPerfCountersKM firmware completed")); */

	PVR_DPF((PVR_DBG_WARNING, "HWPerf %d counter blocks configured and ENABLED",  ui32ArrayLen));

	PVR_DPF_RETURN_OK;

fail2:
	DevmemReleaseCpuVirtAddr(psFwBlkConfigsMemDesc);
fail1:
	RGXUnsetFirmwareAddress(psFwBlkConfigsMemDesc);
	DevmemFwFree(psFwBlkConfigsMemDesc);

	PVR_DPF_RETURN_RC(eError);
}


/*
	PVRSRVRGXConfigCustomCountersReadingHWPerfKM
 */
PVRSRV_ERROR PVRSRVRGXConfigCustomCountersKM(
		PVRSRV_DEVICE_NODE*     psDeviceNode,
		IMG_UINT16              ui16CustomBlockID,
		IMG_UINT16              ui16NumCustomCounters,
		IMG_UINT32*             pui32CustomCounterIDs)
{
	PVRSRV_ERROR        eError = PVRSRV_OK;
	RGXFWIF_KCCB_CMD    sKccbCmd;
	DEVMEM_MEMDESC*     psFwSelectCntrsMemDesc = IMG_NULL;
	IMG_UINT32*         psFwArray;

	PVR_DPF_ENTERED;

	PVR_ASSERT(psDeviceNode);

	PVR_DPF((PVR_DBG_MESSAGE, "PVRSRVRGXSelectCustomCountersKM: configure block %u to read %u counters", ui16CustomBlockID, ui16NumCustomCounters));

	/* Fill in the command structure with the parameters needed */
	sKccbCmd.eCmdType = RGXFWIF_KCCB_CMD_HWPERF_SELECT_CUSTOM_CNTRS;
	sKccbCmd.uCmdData.sHWPerfSelectCstmCntrs.ui16NumCounters = ui16NumCustomCounters;
	sKccbCmd.uCmdData.sHWPerfSelectCstmCntrs.ui16CustomBlock = ui16CustomBlockID;

	if (ui16NumCustomCounters > 0)
	{
		PVR_ASSERT(pui32CustomCounterIDs);

		eError = DevmemFwAllocate(psDeviceNode->pvDevice,
				sizeof(IMG_UINT32) * ui16NumCustomCounters,
				PVRSRV_MEMALLOCFLAG_DEVICE_FLAG(PMMETA_PROTECT) |
				PVRSRV_MEMALLOCFLAG_GPU_READABLE |
				PVRSRV_MEMALLOCFLAG_GPU_WRITEABLE |
				PVRSRV_MEMALLOCFLAG_CPU_READABLE |
				PVRSRV_MEMALLOCFLAG_KERNEL_CPU_MAPPABLE |
				PVRSRV_MEMALLOCFLAG_UNCACHED |
				PVRSRV_MEMALLOCFLAG_ZERO_ON_ALLOC,
				"HWPerfConfigCustomCounters",
				&psFwSelectCntrsMemDesc);
		if (eError != PVRSRV_OK)
			PVR_LOGR_IF_ERROR(eError, "DevmemFwAllocate");

		RGXSetFirmwareAddress(&sKccbCmd.uCmdData.sHWPerfSelectCstmCntrs.pui32CustomCounterIDs,
				psFwSelectCntrsMemDesc, 0, 0);

		eError = DevmemAcquireCpuVirtAddr(psFwSelectCntrsMemDesc, (IMG_VOID **)&psFwArray);
		if (eError != PVRSRV_OK)
		{
			PVR_LOGG_IF_ERROR(eError, "DevmemAcquireCpuVirtAddr", fail1);
		}

		OSMemCopy(psFwArray, pui32CustomCounterIDs, sizeof(IMG_UINT32) * ui16NumCustomCounters);
		DevmemPDumpLoadMem(psFwSelectCntrsMemDesc,
				0,
				sizeof(IMG_UINT32) * ui16NumCustomCounters,
				0);
	}

	/* Push in the KCCB the command to configure the custom counters block */
	eError = RGXScheduleCommand(psDeviceNode->pvDevice,
			RGXFWIF_DM_GP, &sKccbCmd, sizeof(sKccbCmd), IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGG_IF_ERROR(eError, "RGXScheduleCommand", fail2);
	}
	PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXSelectCustomCountersKM: Command scheduled"));

	/* Wait for FW to complete */
	eError = RGXWaitForFWOp(psDeviceNode->pvDevice, RGXFWIF_DM_GP, psDeviceNode->psSyncPrim, IMG_TRUE);
	if (eError != PVRSRV_OK)
	{
		PVR_LOGG_IF_ERROR(eError, "RGXWaitForFWOp", fail2);
	}
	PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXSelectCustomCountersKM: FW operation completed"));

	if (ui16NumCustomCounters > 0)
	{
		/* Release temporary memory used for block configuration */
		RGXUnsetFirmwareAddress(psFwSelectCntrsMemDesc);
		DevmemReleaseCpuVirtAddr(psFwSelectCntrsMemDesc);
		DevmemFwFree(psFwSelectCntrsMemDesc);
	}

	PVR_DPF((PVR_DBG_MESSAGE, "HWPerf custom counters %u reading will be sent with the next HW events", ui16NumCustomCounters));

	PVR_DPF_RETURN_OK;

	fail2:
	if (psFwSelectCntrsMemDesc) DevmemReleaseCpuVirtAddr(psFwSelectCntrsMemDesc);

	fail1:
	if (psFwSelectCntrsMemDesc) 
	{
		RGXUnsetFirmwareAddress(psFwSelectCntrsMemDesc);
		DevmemFwFree(psFwSelectCntrsMemDesc);
	}
	
	PVR_DPF_RETURN_RC(eError);
}
/*
	PVRSRVRGXDisableHWPerfcountersKM
*/
PVRSRV_ERROR PVRSRVRGXCtrlHWPerfCountersKM(
		PVRSRV_DEVICE_NODE*		psDeviceNode,
		IMG_BOOL				bEnable,
	    IMG_UINT32 				ui32ArrayLen,
	    IMG_UINT16*				psBlockIDs)
{
	PVRSRV_ERROR 		eError = PVRSRV_OK;
	RGXFWIF_KCCB_CMD 	sKccbCmd;

	PVR_DPF_ENTERED;

	PVR_ASSERT(psDeviceNode);
	PVR_ASSERT(ui32ArrayLen>0);
	PVR_ASSERT(ui32ArrayLen<=RGXFWIF_HWPERF_CTRL_BLKS_MAX);
	PVR_ASSERT(psBlockIDs);

	/* Fill in the command structure with the parameters needed
	 */
	sKccbCmd.eCmdType = RGXFWIF_KCCB_CMD_HWPERF_CTRL_BLKS;
	sKccbCmd.uCmdData.sHWPerfCtrlBlks.bEnable = bEnable;
	sKccbCmd.uCmdData.sHWPerfCtrlBlks.ui32NumBlocks = ui32ArrayLen;
	OSMemCopy(sKccbCmd.uCmdData.sHWPerfCtrlBlks.aeBlockIDs, psBlockIDs, sizeof(IMG_UINT16)*ui32ArrayLen);

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfCountersKM parameters set, calling FW")); */

	/* Ask the FW to carry out the HWPerf configuration command
	 */
	eError = RGXScheduleCommand(psDeviceNode->pvDevice,
			RGXFWIF_DM_GP, &sKccbCmd, sizeof(sKccbCmd), IMG_TRUE);
	if (eError != PVRSRV_OK)
		PVR_LOGR_IF_ERROR(eError, "RGXScheduleCommand");

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfCountersKM command scheduled for FW")); */

	/* Wait for FW to complete */
	eError = RGXWaitForFWOp(psDeviceNode->pvDevice, RGXFWIF_DM_GP, psDeviceNode->psSyncPrim, IMG_TRUE);
	if (eError != PVRSRV_OK)
		PVR_LOGR_IF_ERROR(eError, "RGXWaitForFWOp");

	/* PVR_DPF((PVR_DBG_VERBOSE, "PVRSRVRGXCtrlHWPerfCountersKM firmware completed")); */

#if defined(DEBUG)
	if (bEnable)
		PVR_DPF((PVR_DBG_WARNING, "HWPerf %d counter blocks have been ENABLED",  ui32ArrayLen));
	else
		PVR_DPF((PVR_DBG_WARNING, "HWPerf %d counter blocks have been DISABLED",  ui32ArrayLen));
#endif

	PVR_DPF_RETURN_OK;
}


/******************************************************************************
 * SUPPORT_GPUTRACE_EVENTS
 *
 * Currently only implemented on Linux and Android. Feature can be enabled on
 * Android builds but can also be enabled on Linux builds for testing
 * but requires the gpu.h FTrace event header file to be present.
 *****************************************************************************/
#if defined(SUPPORT_GPUTRACE_EVENTS)


static POS_LOCK hFTraceLock;
static IMG_VOID RGXHWPerfFTraceCmdCompleteNotify(PVRSRV_CMDCOMP_HANDLE);

#ifdef TSAI_GATOR
extern IMG_BOOL gator_enable_gpu_trace;
#endif

static PVRSRV_ERROR RGXHWPerfFTraceGPUEnable(void)
{
	PVRSRV_ERROR eError = PVRSRV_OK;

	PVR_DPF_ENTERED;

	PVR_ASSERT(gpsRgxDevNode && gpsRgxDevInfo);

	/* In the case where the AppHint has not been set we need to
	 * initialise the host driver HWPerf resources here. Allocated on
	 * demand to reduce RAM foot print on systems not needing HWPerf.
	 * Signal FW to enable event generation.
	 */
	if (gpsRgxDevNode->psSyncPrim)
	{
		eError = PVRSRVRGXCtrlHWPerfKM(gpsRgxDevNode, IMG_FALSE, RGX_HWPERF_EVENT_MASK_HW_KICKFINISH);
		PVR_LOGG_IF_ERROR(eError, "PVRSRVRGXCtrlHWPerfKM", err_out);
	}

	/* Connect to the TL Stream for HWPerf data consumption */
	eError = TLClientConnect(&gpsRgxDevInfo->hGPUTraceTLConnection);
	PVR_LOGG_IF_ERROR(eError, "TLClientConnect", err_out);

	eError = TLClientOpenStream(gpsRgxDevInfo->hGPUTraceTLConnection,
								HWPERF_TL_STREAM_NAME,
								PVRSRV_STREAM_FLAG_ACQUIRE_NONBLOCKING,
								&gpsRgxDevInfo->hGPUTraceTLStream);
	PVR_LOGG_IF_ERROR(eError, "TLClientOpenStream", err_disconnect);

	/* Register a notifier to collect HWPerf data whenever the HW completes
	 * an operation.
	 */
	eError = PVRSRVRegisterCmdCompleteNotify(
		&gpsRgxDevInfo->hGPUTraceCmdCompleteHandle,
		&RGXHWPerfFTraceCmdCompleteNotify,
		gpsRgxDevInfo);
	PVR_LOGG_IF_ERROR(eError, "PVRSRVRegisterCmdCompleteNotify", err_close_stream);

	/* Reset the OS timestamp coming from the timer correlation data
	 * associated with the latest HWPerf event we processed.
	 */
	gpsRgxDevInfo->ui64LastSampledTimeCorrOSTimeStamp = 0;

	gpsRgxDevInfo->bFTraceGPUEventsEnabled = IMG_TRUE;

err_out:
    PVR_DPF_RETURN_RC(eError);

err_close_stream:
	TLClientCloseStream(gpsRgxDevInfo->hGPUTraceTLConnection,
						gpsRgxDevInfo->hGPUTraceTLStream);
err_disconnect:
	TLClientDisconnect(gpsRgxDevInfo->hGPUTraceTLConnection);
	goto err_out;
}

static PVRSRV_ERROR RGXHWPerfFTraceGPUDisable(IMG_BOOL bDeInit)
{
    PVRSRV_ERROR eError = PVRSRV_OK;

	PVR_DPF_ENTERED;

	PVR_ASSERT(gpsRgxDevNode && gpsRgxDevInfo);

	OSLockAcquire(hFTraceLock);

	if (!bDeInit)
	{
		eError = PVRSRVRGXCtrlHWPerfKM(gpsRgxDevNode, IMG_FALSE, (RGX_HWPERF_EVENT_MASK_NONE));
		PVR_LOG_IF_ERROR(eError, "PVRSRVRGXCtrlHWPerfKM");
	}


	if (gpsRgxDevInfo->hGPUTraceCmdCompleteHandle)
	{
		/* Tracing is being turned off. Unregister the notifier. */
		eError = PVRSRVUnregisterCmdCompleteNotify(
				gpsRgxDevInfo->hGPUTraceCmdCompleteHandle);
		PVR_LOG_IF_ERROR(eError, "PVRSRVUnregisterCmdCompleteNotify");
		gpsRgxDevInfo->hGPUTraceCmdCompleteHandle = IMG_NULL;
	}

	if (gpsRgxDevInfo->hGPUTraceTLStream)
	{
		IMG_PBYTE pbTmp = NULL;
		IMG_UINT32 ui32Tmp = 0;

		/* We have to flush both the L1 (FW) and L2 (Host) buffers in case there
		 * are some events left unprocessed in this FTrace/systrace "session"
		 * (note that even if we have just disabled HWPerf on the FW some packets
		 * could have been generated and already copied to L2 by the MISR handler).
		 *
		 * With the following calls we will both copy new data to the Host buffer
		 * (done by the producer callback in TLClientAcquireData) and advance
		 * the read offset in the buffer to catch up with the latest events.
		 */
		eError = TLClientAcquireData(gpsRgxDevInfo->hGPUTraceTLConnection,
		                             gpsRgxDevInfo->hGPUTraceTLStream,
		                             &pbTmp, &ui32Tmp);
		PVR_LOG_IF_ERROR(eError, "TLClientCloseStream");

		/* Let close stream perform the release data on the outstanding acquired data */
		eError = TLClientCloseStream(gpsRgxDevInfo->hGPUTraceTLConnection,
		                             gpsRgxDevInfo->hGPUTraceTLStream);
		PVR_LOG_IF_ERROR(eError, "TLClientCloseStream");

		gpsRgxDevInfo->hGPUTraceTLStream = IMG_NULL;
	}

	if (gpsRgxDevInfo->hGPUTraceTLConnection)
	{
		eError = TLClientDisconnect(gpsRgxDevInfo->hGPUTraceTLConnection);
		PVR_LOG_IF_ERROR(eError, "TLClientDisconnect");
		gpsRgxDevInfo->hGPUTraceTLConnection = IMG_NULL;
	}

	gpsRgxDevInfo->bFTraceGPUEventsEnabled = IMG_FALSE;

	OSLockRelease(hFTraceLock);

    PVR_DPF_RETURN_RC(eError);
}

PVRSRV_ERROR RGXHWPerfFTraceGPUEventsEnabledSet(IMG_BOOL bNewValue)
{
	IMG_BOOL bOldValue;
    PVRSRV_ERROR eError = PVRSRV_OK;

	PVR_DPF_ENTERED;

	if (!gpsRgxDevInfo)
	{
		/* RGXHWPerfFTraceGPUInit hasn't been called yet -- it's too early
		 * to enable tracing.
		 */
        eError = PVRSRV_ERROR_NO_DEVICEDATA_FOUND;
        PVR_DPF_RETURN_RC(eError);
    }

	bOldValue = gpsRgxDevInfo->bFTraceGPUEventsEnabled;

	if (bOldValue != bNewValue)
	{
		if (bNewValue)
		{
            eError = RGXHWPerfFTraceGPUEnable();
		}
		else
		{
            eError = RGXHWPerfFTraceGPUDisable(IMG_FALSE);
		}
	}

    PVR_DPF_RETURN_RC(eError);
}

PVRSRV_ERROR PVRGpuTraceEnabledSet(IMG_BOOL bNewValue)
{
    PVRSRV_ERROR eError = PVRSRV_OK;

	/* Lock down because we need to protect
	 * RGXHWPerfFTraceGPUDisable()/RGXHWPerfFTraceGPUEnable()
	 */
	OSAcquireBridgeLock();
    eError = RGXHWPerfFTraceGPUEventsEnabledSet(bNewValue);
	OSReleaseBridgeLock();

    PVR_DPF_RETURN_RC(eError);
}

IMG_BOOL RGXHWPerfFTraceGPUEventsEnabled(IMG_VOID)
{
	return(gpsRgxDevInfo->bFTraceGPUEventsEnabled);
}

IMG_BOOL PVRGpuTraceEnabled(IMG_VOID)
{
	return (RGXHWPerfFTraceGPUEventsEnabled());
}

IMG_VOID RGXHWPerfFTraceGPUEnqueueEvent(PVRSRV_RGXDEV_INFO *psDevInfo,
		IMG_UINT32 ui32ExternalJobRef, IMG_UINT32 ui32InternalJobRef,
		const IMG_CHAR* pszJobType)
{
	IMG_UINT32   ui32PID = OSGetCurrentProcessID();

	PVR_DPF_ENTERED;

	PVR_ASSERT(pszJobType);

	PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfFTraceGPUEnqueueEvent: PID %u, external jobRef %u, internal jobRef %u", ui32PID, ui32ExternalJobRef, ui32InternalJobRef));

	PVRGpuTraceClientWork(ui32PID, ui32ExternalJobRef, ui32InternalJobRef, pszJobType);

	PVR_DPF_RETURN;
}

#ifdef TSAI_GATOR
#include <linux/pid.h>
#include <linux/sched.h>

	/* 32bit value is enough */
	signed long gator_timestamp_shift = 0;
	void gator_trace_mali_timeline_event_timestamp(unsigned int event_id, unsigned int d0, unsigned int d1, unsigned int d2, unsigned int d3, unsigned int d4);

	typedef enum {
		MALI_PROFILING_EVENT_TYPE_SINGLE  = 0 << 24,
		MALI_PROFILING_EVENT_TYPE_START   = 1 << 24,
		MALI_PROFILING_EVENT_TYPE_STOP    = 2 << 24,
		MALI_PROFILING_EVENT_TYPE_SUSPEND = 3 << 24,
		MALI_PROFILING_EVENT_TYPE_RESUME  = 4 << 24,
	} cinstr_profiling_event_type_t;


	/**
	 * Secifies the channel/source of the event
	 */
	typedef enum {
		MALI_PROFILING_EVENT_CHANNEL_SOFTWARE =  0 << 16,
		MALI_PROFILING_EVENT_CHANNEL_GP0      =  1 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP0      =  5 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP1      =  6 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP2      =  7 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP3      =  8 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP4      =  9 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP5      = 10 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP6      = 11 << 16,
		MALI_PROFILING_EVENT_CHANNEL_PP7      = 12 << 16,
		MALI_PROFILING_EVENT_CHANNEL_GPU      = 21 << 16,
	} cinstr_profiling_event_channel_t;

	#define MALI_PROFILING_MAKE_EVENT_CHANNEL_GP(num) (((MALI_PROFILING_EVENT_CHANNEL_GP0 >> 16) + (num)) << 16)
	#define MALI_PROFILING_MAKE_EVENT_CHANNEL_PP(num) (((MALI_PROFILING_EVENT_CHANNEL_PP0 >> 16) + (num)) << 16)

	typedef u64 (*PFN_gator_get_time_from_timestamp)(u64 timestamp);
	PFN_gator_get_time_from_timestamp pfn_gator_get_time_from_timestamp;
#endif

#if TSAI_DS5
	#include <linux/sched.h>
	static IMG_UINT64 tsai_ta_begin;
	static IMG_UINT64 tsai_3d_begin;
	static IMG_UINT64 tsai_tq3d_begin;
	static uint32_t tsai_ta_begin_cycle;
	static uint32_t tsai_3d_begin_cycle;
	static uint32_t tsai_tq3d_begin_cycle;
#endif

static IMG_VOID RGXHWPerfFTraceGPUSwitchEvent(PVRSRV_RGXDEV_INFO *psDevInfo,
		RGX_HWPERF_V2_PACKET_HDR* psHWPerfPkt, const IMG_CHAR* pszWorkName,
		PVR_GPUTRACE_SWITCH_TYPE eSwType)
{
	IMG_UINT64 ui64Timestamp;
	RGX_HWPERF_HW_DATA_FIELDS* psHWPerfPktData;
	RGXFWIF_GPU_UTIL_FWCB *psGpuUtilFWCB = psDevInfo->psRGXFWIfGpuUtilFWCb;
	RGXFWIF_TIME_CORR *psTimeCorr;
	IMG_UINT32 ui32CRDeltaToOSDeltaKNs;
	IMG_UINT64 ui64CRTimeStamp;
	IMG_UINT64 ui64OSTimeStamp;
#if TSAI_DS5
	char msg[256];
#endif
	PVR_DPF_ENTERED;

	PVR_ASSERT(psHWPerfPkt);
	PVR_ASSERT(pszWorkName);

	psHWPerfPktData = (RGX_HWPERF_HW_DATA_FIELDS*) RGX_HWPERF_GET_PACKET_DATA_BYTES(psHWPerfPkt);

	/* Filter out 3DFINISH events for 3DTQKICKs which have already been
	 * filtered by ValidFTraceEvent() */

	/* Calculate the OS timestamp given an RGX timestamp in the HWPerf event */
	psTimeCorr              = &psGpuUtilFWCB->sTimeCorr[psHWPerfPktData->ui32TimeCorrIndex];
	ui64CRTimeStamp         = psTimeCorr->ui64CRTimeStamp;
	ui64OSTimeStamp         = psTimeCorr->ui64OSTimeStamp;
	ui32CRDeltaToOSDeltaKNs = psTimeCorr->ui32CRDeltaToOSDeltaKNs;

	if(psDevInfo->ui64LastSampledTimeCorrOSTimeStamp > ui64OSTimeStamp)
	{
		/* The previous packet had a time reference (time correlation data) more recent
		 * than the one in the current packet, it means the timer correlation array wrapped
		 * too quickly (buffer too small) and in the previous call to RGXHWPerfFTraceGPUSwitchEvent
		 * we read one of the newest timer correlations rather than one of the oldest ones.
		 */
		PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfFTraceGPUSwitchEvent: The timestamps computed so far could be wrong! "
		                        "The time correlation array size should be increased to avoid this."));
	}
	psDevInfo->ui64LastSampledTimeCorrOSTimeStamp = ui64OSTimeStamp;

	{
		IMG_UINT64 deltaRgxTimer = psHWPerfPkt->ui64RGXTimer - ui64CRTimeStamp;  /* RGX CR timer ticks delta */
		IMG_UINT64 delta_nS =
		    RGXFWIF_GET_DELTA_OSTIME_NS(deltaRgxTimer, ui32CRDeltaToOSDeltaKNs); /* RGX time delta in nS */
		ui64Timestamp = ui64OSTimeStamp + delta_nS;                              /* Calculate OS time of HWPerf event */

		PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfFTraceGPUSwitchEvent: psCurrentDvfs RGX %llu, OS %llu, DVFSCLK %u",
		         ui64CRTimeStamp, ui64OSTimeStamp, psTimeCorr->ui32CoreClockSpeed ));
	}
#ifdef TSAI_GATOR
	/* this ko may change IMG clock source after booting, need to have most up to dated value */
	{
		struct timespec ts;
		u64 timestamp;
		u64 timestamp_IMG;
		getrawmonotonic(&ts);
		timestamp = timespec_to_ns(&ts);
		timestamp_IMG = RGXGPUFreqCalibrateClockns64();
		/* */
		gator_timestamp_shift = (signed long)(timestamp - timestamp_IMG);
		//BKPT;
		//register_trace_mali_timeline_event_timestamp(probe_mali_timeline_event_timestamp, NULL);
	}
#endif
#if 0 && TSAI_DS5
	{
#if 0
		struct timespec ts;
		u64 timestamp;
		u64 timestamp_IMG;
		getrawmonotonic(&ts);
		timestamp = timespec_to_ns(&ts);
		timestamp_IMG = OSClockns64();
#endif
		/* ui32IntJobRef is job id */
	SRUK_ANNOTATE_CHANNEL_COLOR_END(10, ANNOTATE_LTGRAY,
			"HWEVENT %s %d ts %llu pid %d frm %d cy %d ctx %x RT %x Ex %x (jobid) %d",
			pszWorkName, eSwType, ui64Timestamp, psHWPerfPktData->ui32PID, psHWPerfPktData->ui32FrameNum,
			psHWPerfPktData->ui32DMCyc, psHWPerfPktData->ui32DMContext, psHWPerfPktData->ui32WorkTarget,
			psHWPerfPktData->ui32ExtJobRef, psHWPerfPktData->ui32IntJobRef);
	}
#endif
#if defined(TSAI_GATOR)
	{
		unsigned int is_pp = 0; /* indicates PP rendering job */
		unsigned int is_tq3d = 0;
		unsigned int event_id = 0;
		unsigned int pid;
		unsigned int tgid;
		IMG_UINT64 gator_ts = ui64Timestamp;
		IMG_UINT64 gator_relts;
		unsigned int gator_ts_microsec;

		IMG_UINT64 gpu_duration;
		uint32_t gpu_cycle;

		if (eSwType==PVR_GPUTRACE_SWITCH_TYPE_BEGIN) {
			event_id |= MALI_PROFILING_EVENT_TYPE_START;
			if (psHWPerfPkt->eTypeId == 8) {
				tsai_ta_begin = ui64Timestamp;
				tsai_ta_begin_cycle = psHWPerfPktData->ui32DMCyc;
			}
			else if (psHWPerfPkt->eTypeId == 11) {
				tsai_3d_begin = ui64Timestamp;
				tsai_3d_begin_cycle = psHWPerfPktData->ui32DMCyc;
			}
			else if (psHWPerfPkt->eTypeId == 0x0A) {
				/* TSAI: 3D / TQ3D actually use the same counter */
				tsai_tq3d_begin = ui64Timestamp;
				tsai_tq3d_begin_cycle = psHWPerfPktData->ui32DMCyc;
			}
		}
		else if (eSwType==PVR_GPUTRACE_SWITCH_TYPE_END) {
			event_id |= MALI_PROFILING_EVENT_TYPE_STOP;
			if (psHWPerfPkt->eTypeId == 9) {
				gpu_duration = ui64Timestamp - tsai_ta_begin;
				gpu_cycle = psHWPerfPktData->ui32DMCyc - tsai_ta_begin_cycle;
			}
			else if (psHWPerfPkt->eTypeId == 12) {
				gpu_duration = ui64Timestamp - tsai_3d_begin;
				gpu_cycle = psHWPerfPktData->ui32DMCyc - tsai_3d_begin_cycle;
			}
			else if (psHWPerfPkt->eTypeId == 0x17) {
				gpu_duration = ui64Timestamp - tsai_tq3d_begin;
				gpu_cycle = psHWPerfPktData->ui32DMCyc - tsai_tq3d_begin_cycle;
			}
		}

		if (psHWPerfPkt->eTypeId == 8 || psHWPerfPkt->eTypeId == 9) { /* GP, vertex */
			event_id |= MALI_PROFILING_MAKE_EVENT_CHANNEL_GP(0);
		}
		else if (psHWPerfPkt->eTypeId == 11 || psHWPerfPkt->eTypeId == 12) { /* PP, fragment */
			is_pp = 1;
			event_id |= MALI_PROFILING_MAKE_EVENT_CHANNEL_PP(0);
		}
		else if (psHWPerfPkt->eTypeId == 0x0A || psHWPerfPkt->eTypeId == 0x17) { /* TQ3D, something like bitblt to transfer texture ? */
			is_tq3d = 1;
			event_id |= (13 << 16);
		}

		pid = psHWPerfPktData->ui32PID;

		{
			struct task_struct* tgid_task = pid_task(find_vpid(pid), PIDTYPE_PID);
			if (tgid_task)
			tgid = tgid_task->tgid;
			else {
				tgid = 0;
#if TSAI_DS5
				SRUK_ANNOTATE_CHANNEL_COLOR_END(10, ANNOTATE_RED, "PID %d INVALID?", pid);
#endif
			}
		}

		gator_ts += gator_timestamp_shift;
		gator_relts = pfn_gator_get_time_from_timestamp(gator_ts);
		gator_ts_microsec = (u32)div_u64(gator_relts, 1000);

#if 0
		/* check whether it's "nop" , use this clause when tracepoint is not working as expected */
		{
			u32 inst = *(u32*)((void*)gator_trace_mali_timeline_event_timestamp + 0x20);
			if (inst==0xE320F000)
				SRUK_ANNOTATE_CHANNEL_COLOR_END(0, ANNOTATE_WHITE, "gator_trace_mali_timeline_event_timestamp inst %x NOP", inst);
			else
				SRUK_ANNOTATE_CHANNEL_COLOR_END(0, ANNOTATE_BLACK, "gator_trace_mali_timeline_event_timestamp inst %x", inst);
		}
#endif

		gator_trace_mali_timeline_event_timestamp(event_id, pid, tgid, (u32)(gator_ts >> 32), (u32)(gator_ts & 0xFFFFFFFF),0);

#if TSAI_DS5
		{
			u64 timestamp_now = RGXGPUFreqCalibrateClockns64();
			s64 delay_ns = (s64)timestamp_now - (s64)ui64Timestamp;
			s32 delay_micros = (s32)div_s64(delay_ns, 1000);
			u32 duration_micros = 0; /* duration in ms for this GPU activity */
			int pid = 0;

#if 1
			(void)delay_micros;

			sprintf(msg, "HWEVENT %s %d pkcoridx %d pkts %llu osts %llu, nowos %llu now-osts %lld (jobid) %d ",
					pszWorkName, eSwType, psHWPerfPktData->ui32TimeCorrIndex, psHWPerfPkt->ui64RGXTimer, ui64Timestamp, timestamp_now,
					(timestamp_now - ui64Timestamp),
					psHWPerfPktData->ui32IntJobRef);

			ANNOTATE_CHANNEL_COLOR_TS_PID(110, ANNOTATE_LTGRAY, msg, 0, &pid);
			/*
			printk("HWEVENT %s %d pkcoridx %d pkts %llu osts %llu, nowos %llu now-osts %lld (jobid) %d \n",
								pszWorkName, eSwType, psHWPerfPktData->ui32TimeCorrIndex, psHWPerfPkt->ui64Timestamp, ui64Timestamp, timestamp_now,
								(timestamp_now - ui64Timestamp),
								psHWPerfPktData->ui32IntJobRef);
			*/
			sprintf(msg, "HWEVENT %s %d ts %llu ds5 %u delay %d pid %d frm %d cy %d ctx %x RT %x Ex %x (jobid) %d",
					pszWorkName, eSwType, ui64Timestamp, gator_ts_microsec, delay_micros,
					psHWPerfPktData->ui32PID, psHWPerfPktData->ui32FrameNum,
					psHWPerfPktData->ui32DMCyc, psHWPerfPktData->ui32DMContext, psHWPerfPktData->ui32RenderTarget,
					psHWPerfPktData->ui32ExtJobRef, psHWPerfPktData->ui32IntJobRef);
			ANNOTATE_CHANNEL_COLOR_TS_PID(110, ANNOTATE_LTGRAY, msg, 0, &pid);

			if (eSwType==PVR_GPUTRACE_SWITCH_TYPE_END) {
				duration_micros = (u32)div_u64(gpu_duration, 1000);
				sprintf(msg, "HWEVENT %s duration=%u us cycle=%u",
						pszWorkName, (uint32_t)duration_micros, gpu_cycle);
				ANNOTATE_CHANNEL_COLOR_TS_PID(110, ANNOTATE_BLACK, msg, 0, &pid);

			}
			ANNOTATE_CHANNEL_END_TS_PID(110, 0, &pid);
#else
		SRUK_ANNOTATE_CHANNEL_COLOR_END(110, ANNOTATE_LTGRAY,
				"HWEVENT %s %d ts %llu ds5 %u delay %d pid %d frm %d cy %d ctx %x Ex %x (jobid) %d RT %x",
				pszWorkName, eSwType, ui64Timestamp, gator_ts_microsec, delay_micros,
				psHWPerfPktData->ui32PID, psHWPerfPktData->ui32FrameNum,
				psHWPerfPktData->ui32DMCyc, psHWPerfPktData->ui32DMContext,
				psHWPerfPktData->ui32ExtJobRef, psHWPerfPktData->ui32IntJobRef, psHWPerfPktData->ui32RenderTarget);
#endif

			if (is_pp )
			{
				int gem_id = 0; //tsai_PPJobToGem(psHWPerfPktData->ui32IntJobRef);
				u64 begin_timestamp = tsai_3d_begin + gator_timestamp_shift;
				char msg[256];
				if (strcmp(pszWorkName, "TA")==0) {
					BKPT;
				}

				if (eSwType==PVR_GPUTRACE_SWITCH_TYPE_BEGIN) {
					SRUK_ANNOTATE_CHANNEL_COLOR_END(0, ANNOTATE_RED, "PP %d on G%d gator_time_shift %d",
							psHWPerfPktData->ui32IntJobRef, gem_id, (unsigned int)gator_timestamp_shift);
				}
				else if (eSwType==PVR_GPUTRACE_SWITCH_TYPE_END) {
					if (gem_id > 0) {

						sprintf(msg, "PP %d G%d %dus", psHWPerfPktData->ui32IntJobRef, gem_id, duration_micros);
						ANNOTATE_MARKER_COLOR_STR_TS(ANNOTATE_BLACK, msg, &begin_timestamp);
						//ANNOTATE_MARKER_COLOR_STR(ANNOTATE_GREEN, msg);
					}
					else {
						sprintf(msg, "PP %d %x %dus", psHWPerfPktData->ui32IntJobRef,
								psHWPerfPktData->ui32RenderTarget, duration_micros);
						ANNOTATE_MARKER_COLOR_STR_TS(ANNOTATE_DKGRAY, msg, &begin_timestamp);
					}
				}
			}
			else if (is_tq3d && (eSwType==PVR_GPUTRACE_SWITCH_TYPE_BEGIN)) {
				//ANNOTATE_MARKER_COLOR_STR_TS(ANNOTATE_DKGRAY, "TQ3D", &gator_ts);
			}

		}
#endif
	}
#endif

	PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfFTraceGPUSwitchEvent: %s ui32ExtJobRef=%d, ui32IntJobRef=%d, eSwType=%d",
			pszWorkName, psHWPerfPktData->ui32ExtJobRef, psHWPerfPktData->ui32IntJobRef, eSwType));

	PVRGpuTraceWorkSwitch(ui64Timestamp, psHWPerfPktData->ui32PID,
			psHWPerfPktData->ui32ExtJobRef, psHWPerfPktData->ui32IntJobRef,
			pszWorkName, eSwType);

	PVR_DPF_RETURN;
}


static IMG_BOOL ValidFTraceEvent(RGX_HWPERF_V2_PACKET_HDR* psHWPerfPkt,
		IMG_PCHAR* ppszWorkName, PVR_GPUTRACE_SWITCH_TYPE* peSwType)
{
	RGX_HWPERF_EVENT_TYPE eType;
	static const struct {
		IMG_CHAR* pszName;
		PVR_GPUTRACE_SWITCH_TYPE eSwType;
	} aszEventTypeMap[] = {
			{ /* RGX_HWPERF_HW_TAKICK */       "TA",     PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_TAFINISHED */   "TA",     PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_3DTQKICK */     "TQ3D",   PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_3DKICK */       "3D",     PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_3DFINISHED */   "3D",     PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_CDMKICK */      "CDM",    PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_CDMFINISHED */  "CDM",    PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_TLAKICK */      "TQ2D",   PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_TLAFINISHED */  "TQ2D",   PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_3DSPMKICK */    "3DSPM",  PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_PERIODIC */     IMG_NULL, 0 }, /* PERIODIC not supported */
			{ /* RGX_HWPERF_HW_RTUKICK */      "RTU",    PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_RTUFINISHED */  "RTU",    PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_SHGKICK */      "SHG",    PVR_GPUTRACE_SWITCH_TYPE_BEGIN },
			{ /* RGX_HWPERF_HW_SHGFINISHED */  "SHG",    PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_3DTQFINISHED */ "TQ3D",   PVR_GPUTRACE_SWITCH_TYPE_END },
			{ /* RGX_HWPERF_HW_3DSPMFINISHED */ "3DSPM", PVR_GPUTRACE_SWITCH_TYPE_END },
	};

	PVR_ASSERT(psHWPerfPkt);

	eType = RGX_HWPERF_GET_TYPE(psHWPerfPkt);
	if ((eType < RGX_HWPERF_HW_TAKICK) || (eType > RGX_HWPERF_HW_3DSPMFINISHED))
	{
		/* No map entry, ignore event */
		PVR_DPF((PVR_DBG_VERBOSE, "ValidFTraceEvent: Unsupported event type %d %02d",
			eType, eType+RGX_HWPERF_HW_TAKICK)); 
		return IMG_FALSE;
	}
	eType-=RGX_HWPERF_HW_TAKICK;

	if (aszEventTypeMap[eType].pszName == IMG_NULL)
	{
		/* Not supported map entry, ignore event */
		PVR_DPF((PVR_DBG_VERBOSE, "ValidFTraceEventl: Unsupported event type %d %02d",
			eType, eType+RGX_HWPERF_HW_TAKICK)); 
		return IMG_FALSE;
	}

	*ppszWorkName = aszEventTypeMap[eType].pszName;
	*peSwType = aszEventTypeMap[eType].eSwType;
#if 0 && TSAI_DS5
	SRUK_ANNOTATE_CHANNEL_COLOR_END(10, ANNOTATE_LTGRAY, "HWEVENT %s %d ",
			aszHwEventTypeMap[ui32HwEventTypeIndex].pszName,
			aszHwEventTypeMap[ui32HwEventTypeIndex].eSwType	);
#endif

	return IMG_TRUE;
}


#ifdef SDP_GATOR

struct TSAI_HdrLog {
	void* psHDRptr;
};

struct TSAI_HdrLog tsai_hdrlog[1024];
int tsai_hdrlog_cursor;

#define INCRE_HDRLOG_CURSOR(c) c = (c + 1) & 1023

int GatorProcessPackets(PVRSRV_RGXDEV_INFO *psDevInfo,
		IMG_PBYTE pBuffer, IMG_UINT32 ui32ReadLen);

int GatorProcessPackets(PVRSRV_RGXDEV_INFO *psDevInfo,
		IMG_PBYTE pBuffer, IMG_UINT32 ui32ReadLen)
{
	IMG_INT32 ret = 0;
	IMG_UINT32			ui32TlPackets = 0;
	IMG_UINT32			ui32HWPerfPackets = 0;
	IMG_UINT32			ui32HWPerfPacketsSent = 0;

	IMG_PBYTE			pBufferEnd;
	PVRSRVTL_PPACKETHDR psHDRptr;
	PVRSRVTL_PACKETTYPE ui16TlType;

	pBufferEnd = pBuffer+ui32ReadLen;
	psHDRptr = GET_PACKET_HDR(pBuffer);

	while ( psHDRptr < (PVRSRVTL_PPACKETHDR)pBufferEnd )
	{
		struct TSAI_HdrLog* ptsai_hdrlog = &tsai_hdrlog[tsai_hdrlog_cursor];
		INCRE_HDRLOG_CURSOR(tsai_hdrlog_cursor);
		tsai_hdrlog[tsai_hdrlog_cursor].psHDRptr = NULL;
		ptsai_hdrlog->psHDRptr = psHDRptr;

		ui16TlType = GET_PACKET_TYPE(psHDRptr);
		if (ui16TlType == PVRSRVTL_PACKETTYPE_DATA)
		{
			IMG_UINT16 ui16DataLen = GET_PACKET_DATA_LEN(psHDRptr);
			if (0 == ui16DataLen)
			{
				PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfFTraceGPUProcessPackets: ZERO Data in TL data packet: %p", psHDRptr));
				BKPT;
			}
			else
			{
				RGX_HWPERF_V2_PACKET_HDR* psHWPerfPkt;
				RGX_HWPERF_V2_PACKET_HDR* psHWPerfEnd;

				/* Check for lost hwperf data packets */
				psHWPerfEnd = RGX_HWPERF_GET_PACKET(GET_PACKET_DATA_PTR(psHDRptr)+ui16DataLen);
				psHWPerfPkt = RGX_HWPERF_GET_PACKET(GET_PACKET_DATA_PTR(psHDRptr));

				if ((IMG_PBYTE)psHWPerfEnd > pBufferEnd) { /* TSAI: incomplete buffer, check why?*/
					BKPT;
				}

				do
				{
					if (ValidAndEmitFTraceEvent(psDevInfo, psHWPerfPkt))
					{
						ui32HWPerfPacketsSent++;
					}
					ui32HWPerfPackets++;
					psHWPerfPkt = RGX_HWPERF_GET_NEXT_PACKET(psHWPerfPkt);
				}
				while (psHWPerfPkt < psHWPerfEnd);

				ret = (IMG_PBYTE)psHWPerfEnd - pBuffer;
				goto Leave;
			}
		}
		else if (ui16TlType == PVRSRVTL_PACKETTYPE_MOST_RECENT_WRITE_FAILED)
		{
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfFTraceGPUProcessPackets: Indication that the transport buffer was full"));
			BKPT;
		}
		else if (ui16TlType == PVRSRVTL_PACKETTYPE_PADDING) { /* TSAI: padding, likely to reach the end of buffer and start a new loop */
			PVRSRVTL_PPACKETHDR pNextHDR;
			pNextHDR = GET_NEXT_PACKET_ADDR(psHDRptr);
			if ((IMG_PBYTE)pNextHDR - pBuffer == ui32ReadLen) {
				ret = ui32ReadLen;
				goto Leave;
			}
		}
		else
		{
			/* else Ignore padding packet type and others */
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfFTraceGPUProcessPackets: Ignoring TL packet, type %d", ui16TlType ));
			BKPT;
		}

		if (psHDRptr->uiTypeSize == 0) {
			BKPT;
		}
		psHDRptr = GET_NEXT_PACKET_ADDR(psHDRptr);
		ui32TlPackets++;

	}

	/* for cases other than useful packet, return */
	BKPT;
	ret = (IMG_PBYTE)psHDRptr - pBuffer;

Leave:
	return ret;
}


#endif

#if TSAI
int proc_packet_busy;
int proc_packet_seqno;

static int tsai_diff_microsec(struct timeval* first, struct timeval* second)
 {
 	 int retval;
 	 int sec;
 	   /* Perform the carry for the later subtraction by updating y. */
 	 //first->tv_sec;
 	 //first->tv_nsec;

 	 retval = second->tv_usec - first->tv_usec;	//retval might be negative at this point
 	 for (sec = (second->tv_sec - first->tv_sec); sec>0; sec-- ) {
 		 retval += 1000000 ;
 	 }

 	 return retval;
}

#endif

static IMG_VOID RGXHWPerfFTraceGPUThreadProcessPackets(PVRSRV_RGXDEV_INFO *psDevInfo,
		IMG_PBYTE pBuffer, IMG_UINT32 ui32ReadLen)
{
	IMG_UINT32			ui32TlPackets = 0;
	IMG_UINT32          ui32HWPerfPackets = 0;
	IMG_UINT32          ui32HWPerfPacketsSent = 0;
	IMG_PBYTE			pBufferEnd;
	PVRSRVTL_PPACKETHDR psHDRptr;
	PVRSRVTL_PACKETTYPE ui16TlType;
#if TSAI
	struct timeval tv_1;
	struct timeval tv_2;
	int time_micro;
#endif
//BKPT;

	PVR_DPF_ENTERED;

	PVR_ASSERT(psDevInfo);
	PVR_ASSERT(pBuffer);
	PVR_ASSERT(ui32ReadLen);
#if 1 && TSAI_DS5
	do_gettimeofday(&tv_1);
	proc_packet_seqno++;
	SRUK_ANNOTATE_CHANNEL_COLOR(4, ANNOTATE_RED, "RGXHWPerfFTraceGPUProcessPackets %d proc_packet_busy %p %d",
			proc_packet_seqno, &proc_packet_busy, proc_packet_busy);
#endif
#if TSAI
	if (proc_packet_busy) {
		BKPT;
	}
	proc_packet_busy = 1;
#endif

	/* Process the TL Packets
	 */
	pBufferEnd = pBuffer+ui32ReadLen;
	psHDRptr = GET_PACKET_HDR(pBuffer);
	while ( psHDRptr < (PVRSRVTL_PPACKETHDR)pBufferEnd )
	{
		ui16TlType = GET_PACKET_TYPE(psHDRptr);
		if (ui16TlType == PVRSRVTL_PACKETTYPE_DATA)
		{
			IMG_UINT16 ui16DataLen = GET_PACKET_DATA_LEN(psHDRptr);
			if (0 == ui16DataLen)
			{
				PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfFTraceGPUThreadProcessPackets: ZERO Data in TL data packet: %p", psHDRptr));
			}
			else
			{
				RGX_HWPERF_V2_PACKET_HDR* psHWPerfPkt;
				RGX_HWPERF_V2_PACKET_HDR* psHWPerfEnd;
				IMG_CHAR* pszWorkName;
				PVR_GPUTRACE_SWITCH_TYPE eSwType;

				/* Check for lost hwperf data packets */
				psHWPerfEnd = RGX_HWPERF_GET_PACKET(GET_PACKET_DATA_PTR(psHDRptr)+ui16DataLen);
				psHWPerfPkt = RGX_HWPERF_GET_PACKET(GET_PACKET_DATA_PTR(psHDRptr));
				do
				{
					if (ValidFTraceEvent(psHWPerfPkt, &pszWorkName, &eSwType))
					{
						RGXHWPerfFTraceGPUSwitchEvent(psDevInfo, psHWPerfPkt, pszWorkName, eSwType);
						ui32HWPerfPacketsSent++;
					}
					ui32HWPerfPackets++;
					psHWPerfPkt = RGX_HWPERF_GET_NEXT_PACKET(psHWPerfPkt);
				}
				while (psHWPerfPkt < psHWPerfEnd);
			}
		}
		else if (ui16TlType == PVRSRVTL_PACKETTYPE_MOST_RECENT_WRITE_FAILED)
		{
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfFTraceGPUThreadProcessPackets: Indication that the transport buffer was full"));
		}
		else
		{
			/* else Ignore padding packet type and others */
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfFTraceGPUThreadProcessPackets: Ignoring TL packet, type %d", ui16TlType ));
		}

		psHDRptr = GET_NEXT_PACKET_ADDR(psHDRptr);
		ui32TlPackets++;
	}

	PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfFTraceGPUThreadProcessPackets: TL "
	 		"Packets processed %03d, HWPerf packets %03d, sent %03d",
	 		ui32TlPackets, ui32HWPerfPackets, ui32HWPerfPacketsSent));

#if 1 && TSAI_DS5
	do_gettimeofday(&tv_2);
	time_micro = tsai_diff_microsec(&tv_1, &tv_2);

	SRUK_ANNOTATE_CHANNEL_COLOR(4, ANNOTATE_RED, "buf %p pkts %d hwp %d hws %d duration %d", pBuffer,
			ui32TlPackets, ui32HWPerfPackets, ui32HWPerfPacketsSent, time_micro );
	ANNOTATE_CHANNEL_END(4);
#endif
#if TSAI
	proc_packet_busy = 0;
#endif
	PVR_DPF_RETURN;
}

#if TSAI
	atomic_t hwperf_notify_busy;
	int hwperf_notify_busy_2;
#endif

static
IMG_VOID RGXHWPerfFTraceCmdCompleteNotify(PVRSRV_CMDCOMP_HANDLE hCmdCompHandle)
{
	PVRSRV_DATA*        psPVRSRVData = PVRSRVGetPVRSRVData();
	PVRSRV_RGXDEV_INFO* psDeviceInfo = hCmdCompHandle;
	IMG_HANDLE			hUnusedByTL;
	PVRSRV_ERROR        eError;
	IMG_HANDLE          hStream;
	IMG_PBYTE           pBuffer;
	IMG_UINT32          ui32ReadLen;
#if TSAI
	int busy_flag;
#endif

	PVR_DPF_ENTERED;

	/* Command-complete notifiers can run concurrently. If this is
	 * happening, just bail out and let the previous call finish.
	 * This is ok because we can process the queued packets on the next call.
	 */
	if (!(OSTryLockAcquire(hFTraceLock)))
	{
		PVR_DPF_RETURN;
	}
#if TSAI
	busy_flag = atomic_read(&hwperf_notify_busy);
	if (busy_flag != hwperf_notify_busy_2) {
		BKPT;
	}

	if (busy_flag) {
		goto out;
	}
	else {
		atomic_set(&hwperf_notify_busy,1);
		hwperf_notify_busy_2 = 1;
	}
#endif
#if TSAI_DS5
	SRUK_ANNOTATE_CHANNEL_COLOR(8, ANNOTATE_BLUE, "RGXHWPerfFTraceCmdCompleteNotify busy on enter %d now %d nonatom %d", busy_flag,
			atomic_read(&hwperf_notify_busy), hwperf_notify_busy_2 );
#endif

	/* Exit if no HWPerf enabled device exits */
	PVR_ASSERT(psDeviceInfo != IMG_NULL &&
	           psPVRSRVData != IMG_NULL &&
	           gpsRgxDevInfo != NULL);


	hUnusedByTL = psDeviceInfo->hGPUTraceTLConnection;
	hStream = psDeviceInfo->hGPUTraceTLStream;

	if (hStream)
	{
		/* If we have a valid stream attempt to acquire some data */
		eError = TLClientAcquireData(hUnusedByTL, hStream, &pBuffer, &ui32ReadLen);
		if (eError == PVRSRV_OK)
		{
			/* Process the HWPerf packets and release the data */
			if (ui32ReadLen > 0)
			{
				PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfFTraceGPUThread: DATA AVAILABLE offset=%p, length=%d", pBuffer, ui32ReadLen));

				/* Process the transport layer data for HWPerf packets... */
				RGXHWPerfFTraceGPUThreadProcessPackets (psDeviceInfo, pBuffer, ui32ReadLen);

				eError = TLClientReleaseData(hUnusedByTL, hStream);
				if (eError != PVRSRV_OK)
				{
					PVR_LOG_ERROR(eError, "TLClientReleaseData");

					/* Serious error, disable FTrace GPU events */

					/* Release TraceLock so we always have the locking
					 * order BridgeLock->TraceLock to prevent AB-BA deadlocks*/
					OSLockRelease(hFTraceLock);
					OSAcquireBridgeLock();
					RGXHWPerfFTraceGPUDisable(IMG_FALSE);
					OSReleaseBridgeLock();
					goto out;

				}
			} /* else no data, ignore */
		}
		else if (eError != PVRSRV_ERROR_TIMEOUT)
		{
			PVR_LOG_ERROR(eError, "TLClientAcquireData");
		}
	}

	OSLockRelease(hFTraceLock);
#if TSAI
	atomic_set(&hwperf_notify_busy,0);
	hwperf_notify_busy_2 = 0;
#endif
out:
#if TSAI_DS5
	ANNOTATE_CHANNEL_END(8);
#endif
	PVR_DPF_RETURN;
}


PVRSRV_ERROR RGXHWPerfFTraceGPUInit(PVRSRV_RGXDEV_INFO *psDevInfo)
{
	PVRSRV_ERROR eError = PVRSRV_OK;

	PVR_DPF_ENTERED;

    /* Must be setup already by the general HWPerf module initialisation.
	 * DevInfo object needed by FTrace event generation code */
	PVR_ASSERT(gpsRgxDevInfo);
	gpsRgxDevInfo->bFTraceGPUEventsEnabled = IMG_FALSE;

	eError = OSLockCreate(&hFTraceLock, LOCK_TYPE_DISPATCH);

	PVR_DPF_RETURN_RC(eError);
}


IMG_VOID RGXHWPerfFTraceGPUDeInit(PVRSRV_RGXDEV_INFO *psDevInfo)
{
	PVR_DPF_ENTERED;

	if (gpsRgxDevInfo->bFTraceGPUEventsEnabled)
	{
		RGXHWPerfFTraceGPUDisable(IMG_TRUE);
		gpsRgxDevInfo->bFTraceGPUEventsEnabled = IMG_FALSE;
	}

	OSLockDestroy(hFTraceLock);

	PVR_DPF_RETURN;
}


#endif /* SUPPORT_GPUTRACE_EVENTS */


/******************************************************************************
 * SUPPORT_KERNEL_HWPERF
 *
 * Currently only implemented on Linux. Feature can be enabled on Linux builds
 * to provide an interface to 3rd-party kernel modules that wish to access the
 * HWPerf data. The API is documented in the rgxapi_km.h header and
 * the rgx_hwperf* headers.
 *****************************************************************************/
#if defined(SUPPORT_KERNEL_HWPERF)

/* Internal HWPerf kernel connection/device data object to track the state
 * of a client session.
 */
typedef struct
{
	PVRSRV_DEVICE_NODE* psRgxDevNode;

	/* TL Connect/disconnect state */
	IMG_HANDLE          hTLConnection;

	/* TL Open/close state */
	IMG_HANDLE          hSD;

	/* TL Acquire/release state */
	IMG_PBYTE			pHwpBuf;
	IMG_UINT32          ui32HwpBufLen;

} RGX_KM_HWPERF_DEVDATA;


PVRSRV_ERROR RGXHWPerfConnect(
		IMG_HANDLE* phDevData)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData;

	/* Valid input argument values supplied by the caller */
	if (!phDevData)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* Clear the handle to aid error checking by caller */
	*phDevData = IMG_NULL;

	/* Check the HWPerf module is initialised before we allow a connection */
	if (!gpsRgxDevNode || !gpsRgxDevInfo)
	{
		return PVRSRV_ERROR_INVALID_DEVICE;
	}

	/* In the case where the AppHint has not been set we need to
	 * initialise the host driver HWPerf resources here. Allocated on
	 * demand to reduce RAM foot print on systems not needing HWPerf.
	 */
	if (gpsRgxDevInfo->hHWPerfStream == IMG_NULL)
	{
		eError = RGXHWPerfInit(IMG_NULL, IMG_TRUE);
		PVR_LOGR_IF_ERROR(eError, "RGXHWPerfInit");
	}

	/* Allocation the session object for this connection */
	psDevData = OSAllocZMem(sizeof(*psDevData));
	if (psDevData == IMG_NULL)
	{
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}
	psDevData->psRgxDevNode = gpsRgxDevNode;


	/* Open a TL connection and store it in the session object */
	eError = TLClientConnect(&psDevData->hTLConnection);
	if (eError != PVRSRV_OK)
	{
		goto e1;
	}

	/* Open the 'hwperf' TL stream for reading in this session */
	eError = TLClientOpenStream(psDevData->hTLConnection,
			                    HWPERF_TL_STREAM_NAME,
			                    PVRSRV_STREAM_FLAG_ACQUIRE_NONBLOCKING,
			                    &psDevData->hSD);
	if (eError != PVRSRV_OK)
	{
		goto e2;
	}

	*phDevData = psDevData;
	return PVRSRV_OK;

	/* Error path... */
e2:
	TLClientDisconnect(psDevData->hTLConnection);
e1:
	OSFREEMEM(psDevData);
// e0:
	return eError;
}



PVRSRV_ERROR RGXHWPerfControl(
		IMG_HANDLE  hDevData,
		IMG_BOOL    bToggle,
		IMG_UINT64  ui64Mask)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;

	/* Valid input argument values supplied by the caller */
	if (!psDevData)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* Ensure we are initialised and have a valid device node */
	if (!psDevData->psRgxDevNode)
	{
		return PVRSRV_ERROR_INVALID_DEVICE;
	}

	/* Call the internal server API */
	eError = PVRSRVRGXCtrlHWPerfKM(psDevData->psRgxDevNode, bToggle, ui64Mask);
	return eError;
}


PVRSRV_ERROR RGXHWPerfConfigureAndEnableCounters(
		IMG_HANDLE                 hDevData,
		IMG_UINT32                 ui32NumBlocks,
		RGX_HWPERF_CONFIG_CNTBLK*  asBlockConfigs)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;

	/* Valid input argument values supplied by the caller */
	if (!psDevData || ui32NumBlocks==0 || !asBlockConfigs)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	if (ui32NumBlocks > RGXFWIF_HWPERF_CTRL_BLKS_MAX)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* Ensure we are initialised and have a valid device node */
	if (!psDevData->psRgxDevNode)
	{
		return PVRSRV_ERROR_INVALID_DEVICE;
	}

	/* Call the internal server API */
	eError = PVRSRVRGXConfigEnableHWPerfCountersKM(
			psDevData->psRgxDevNode, ui32NumBlocks, asBlockConfigs);
	return eError;
}


PVRSRV_ERROR RGXHWPerfDisableCounters(
		IMG_HANDLE   hDevData,
		IMG_UINT32   ui32NumBlocks,
		IMG_UINT16*   aeBlockIDs)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;

	/* Valid input argument values supplied by the caller */
	if (!psDevData || ui32NumBlocks==0 || !aeBlockIDs)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	if (ui32NumBlocks > RGXFWIF_HWPERF_CTRL_BLKS_MAX)
    {
        return PVRSRV_ERROR_INVALID_PARAMS;
    }

	/* Ensure we are initialised and have a valid device node */
	if (!psDevData->psRgxDevNode)
	{
		return PVRSRV_ERROR_INVALID_DEVICE;
	}

	/* Call the internal server API */
	eError = PVRSRVRGXCtrlHWPerfCountersKM(
			psDevData->psRgxDevNode, IMG_FALSE, ui32NumBlocks, aeBlockIDs);
	return eError;
}


PVRSRV_ERROR RGXHWPerfAcquireData(
		IMG_HANDLE  hDevData,
		IMG_PBYTE*  ppBuf,
		IMG_UINT32* pui32BufLen)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;
	IMG_PBYTE              pTlBuf = IMG_NULL;
	IMG_UINT32             ui32TlBufLen = 0;
	IMG_PBYTE              pDataDest;
	IMG_UINT32			ui32TlPackets = 0;
	IMG_PBYTE			pBufferEnd;
	PVRSRVTL_PPACKETHDR psHDRptr;
	PVRSRVTL_PACKETTYPE ui16TlType;

	/* Reset the output arguments in case we discover an error */
	*ppBuf = IMG_NULL;
	*pui32BufLen = 0;

	/* Valid input argument values supplied by the caller */
	if (!psDevData)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* Acquire some data to read from the HWPerf TL stream */
	eError = TLClientAcquireData(psDevData->hTLConnection,
	                             psDevData->hSD,
	                             &pTlBuf,
	                             &ui32TlBufLen);
	PVR_LOGR_IF_ERROR(eError, "TLClientAcquireData");

	/* TL indicates no data exists so return OK and zero. */
	if ((pTlBuf == IMG_NULL) || (ui32TlBufLen == 0))
	{
		return PVRSRV_OK;
	}

	/* Is the client buffer allocated and too small? */
	if (psDevData->pHwpBuf && (psDevData->ui32HwpBufLen < ui32TlBufLen))
	{
		OSFREEMEM(psDevData->pHwpBuf);
	}

	/* Do we need to allocate a new client buffer? */
	if (!psDevData->pHwpBuf)
	{
		psDevData->pHwpBuf = OSAllocMem(ui32TlBufLen);
		if (psDevData->pHwpBuf  == IMG_NULL)
		{
			(void) TLClientReleaseData(psDevData->hTLConnection, psDevData->hSD);
			return PVRSRV_ERROR_OUT_OF_MEMORY;
		}
		psDevData->ui32HwpBufLen = ui32TlBufLen;
	}

	/* Process each TL packet in the data buffer we have acquired */
	pBufferEnd = pTlBuf+ui32TlBufLen;
	pDataDest = psDevData->pHwpBuf;
	psHDRptr = GET_PACKET_HDR(pTlBuf);
	while ( psHDRptr < (PVRSRVTL_PPACKETHDR)pBufferEnd )
	{
		ui16TlType = GET_PACKET_TYPE(psHDRptr);
		if (ui16TlType == PVRSRVTL_PACKETTYPE_DATA)
		{
			IMG_UINT16 ui16DataLen = GET_PACKET_DATA_LEN(psHDRptr);
			if (0 == ui16DataLen)
			{
				PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfAcquireData: ZERO Data in TL data packet: %p", psHDRptr));
			}
			else
			{
				/* For valid data copy it into the client buffer and move
				 * the write position on */
				OSMemCopy(pDataDest, GET_PACKET_DATA_PTR(psHDRptr), ui16DataLen);
				pDataDest += ui16DataLen;
			}
		}
		else if (ui16TlType == PVRSRVTL_PACKETTYPE_MOST_RECENT_WRITE_FAILED)
		{
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfAcquireData: Indication that the transport buffer was full"));
		}
		else
		{
			/* else Ignore padding packet type and others */
			PVR_DPF((PVR_DBG_MESSAGE, "RGXHWPerfAcquireData: Ignoring TL packet, type %d", ui16TlType ));
		}

		/* Update loop variable to the next packet and increment counts */
		psHDRptr = GET_NEXT_PACKET_ADDR(psHDRptr);
		ui32TlPackets++;
	}

	PVR_DPF((PVR_DBG_VERBOSE, "RGXHWPerfAcquireData: TL Packets processed %03d", ui32TlPackets));

	/* Update output arguments with client buffer details and true length */
	*ppBuf = psDevData->pHwpBuf;
	*pui32BufLen = pDataDest - psDevData->pHwpBuf;

	return PVRSRV_OK;
}


PVRSRV_ERROR RGXHWPerfReleaseData(
		IMG_HANDLE hDevData)
{
	PVRSRV_ERROR           eError;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;

	/* Valid input argument values supplied by the caller */
	if (!psDevData)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* Free the client buffer if allocated and reset length */
	if (psDevData->pHwpBuf)
	{
		OSFREEMEM(psDevData->pHwpBuf);
	}
	psDevData->ui32HwpBufLen = 0;

	/* Inform the TL that we are done with reading the data. Could perform this
	 * in the acquire call but felt it worth keeping it symmetrical */
	eError = TLClientReleaseData(psDevData->hTLConnection, psDevData->hSD);
	return eError;
}


PVRSRV_ERROR RGXHWPerfDisconnect(
		IMG_HANDLE hDevData)
{
	PVRSRV_ERROR           eError = PVRSRV_OK;
	RGX_KM_HWPERF_DEVDATA* psDevData = (RGX_KM_HWPERF_DEVDATA*)hDevData;

	/* Check session handle is not zero */
	if (!psDevData)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* If the client buffer exists they have not called ReleaseData
	 * before disconnecting so clean it up */
	if (psDevData->pHwpBuf)
	{
		eError = RGXHWPerfReleaseData(hDevData);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfDisconnect: Failed to release data (%d)", eError));
		}
		/* RGXHWPerfReleaseData call above will null out the buffer 
		 * fields and length */
	}

	/* Close the TL stream, ignore the error if it occurs as we
	 * are disconnecting */
	if (psDevData->hSD)
	{
		eError = TLClientCloseStream(psDevData->hTLConnection,
									 psDevData->hSD);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfDisconnect: Failed to close handle on HWPerf stream (%d)", eError));
		}
		psDevData->hSD = IMG_NULL;
	}

	/* End the TL connection as we don't require it anymore */
	if (psDevData->hTLConnection)
	{
		eError = TLClientDisconnect(psDevData->hTLConnection);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR, "RGXHWPerfDisconnect: Failed to disconnect from the Transport (%d)", eError));
		}
		psDevData->hTLConnection = IMG_NULL;
	}

	/* Free the session memory */
	psDevData->psRgxDevNode = IMG_NULL;
	OSFREEMEM(psDevData);
	return eError;
}


#endif /* SUPPORT_KERNEL_HWPERF */


#ifdef TSAI_GATOR
	/* I isolate a function which needs to include tracepoint header file here,
	 * because it requires compiler option with optimisation */
	#pragma GCC optimize ("O1")
	#include "rgx_gator_trace.h"

	typedef void(*PFNGATOR_TIMELINE_TIMESTAMP)(void* data, unsigned int event_id, unsigned int d0, unsigned int d1, unsigned int d2, unsigned int d3, unsigned int d4);
	PFNGATOR_TIMELINE_TIMESTAMP pfnGTLTS;

	/* right now tracepoint doesn't work as expected, so for the timebeing, just directly make the function call to gator code
	 *
	 * */

	void gator_trace_mali_timeline_event_timestamp(unsigned int event_id, unsigned int d0, unsigned int d1, unsigned int d2, unsigned int d3, unsigned int d4)
	{
#if 0
		if (!pfnGTLTS) {
			pfnGTLTS = (PFNGATOR_TIMELINE_TIMESTAMP)__symbol_get("probe_mali_timeline_event_timestamp");
		}

		if (pfnGTLTS)
			pfnGTLTS(NULL, event_id, d0, d1, d2, d3, d4);
#else
		trace_mali_timeline_event_timestamp(event_id, d0, d1, d2, d3, d4);
#endif
	}

#endif
/******************************************************************************
 End of file (rgxdebug.c)
******************************************************************************/
