/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#ifndef _XENNET_ADAPTER_H_
#define _XENNET_ADAPTER_H_

#include <ndis.h>

#define XENNET_INTERFACE_TYPE           NdisInterfaceInternal

#define XENNET_MEDIA_TYPE               NdisMedium802_3

#define XENNET_MAC_OPTIONS              (NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |  \
                                         NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |   \
                                         NDIS_MAC_OPTION_NO_LOOPBACK |          \
                                         NDIS_MAC_OPTION_8021P_PRIORITY |       \
                                         NDIS_MAC_OPTION_SUPPORTS_MAC_ADDRESS_OVERWRITE)

#define XENNET_MEDIA_MAX_SPEED          1000000000ull

#define XENNET_SUPPORTED_PACKET_FILTERS (NDIS_PACKET_TYPE_DIRECTED |        \
                                         NDIS_PACKET_TYPE_MULTICAST |       \
                                         NDIS_PACKET_TYPE_ALL_MULTICAST |   \
                                         NDIS_PACKET_TYPE_BROADCAST |       \
                                         NDIS_PACKET_TYPE_PROMISCUOUS)

typedef struct _XENNET_ADAPTER XENNET_ADAPTER, *PXENNET_ADAPTER;

extern NDIS_STATUS
AdapterInitialize(
    _In_ NDIS_HANDLE            Handle,
    _Outptr_ PXENNET_ADAPTER    *Adapter
    );

extern VOID
AdapterTeardown(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern NDIS_HANDLE
AdapterGetHandle(
    _In_ PXENNET_ADAPTER    Adapter
    );

#include <vif_interface.h>
extern PXENVIF_VIF_INTERFACE
AdapterGetVifInterface(
    _In_ PXENNET_ADAPTER    Adapter
    );

#include "transmitter.h"
extern PXENNET_TRANSMITTER
AdapterGetTransmitter(
    _In_ PXENNET_ADAPTER    Adapter
    );

#include "receiver.h"
extern PXENNET_RECEIVER
AdapterGetReceiver(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern PWCHAR
AdapterGetLocation(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern NDIS_STATUS
AdapterEnable(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern VOID
AdapterDisable(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern VOID
AdapterMediaStateChange(
    _In_ PXENNET_ADAPTER    Adapter
    );

extern NDIS_STATUS
AdapterSetInformation(
    _In_ PXENNET_ADAPTER    Adapter,
    _In_ PNDIS_OID_REQUEST  Request
    );

extern NDIS_STATUS
AdapterQueryInformation(
    _In_ PXENNET_ADAPTER    Adapter,
    _In_ PNDIS_OID_REQUEST  Request
    );

#define NBL_BATCH_SIZE_DEFAULT  32
#define NBL_BATCH_SIZE_MAX      64

extern ULONG
AdapterGetNblMaxBatchSize(
    _In_ PXENNET_ADAPTER    Adapter
    );

#endif // _XENNET_ADAPTER_H_
