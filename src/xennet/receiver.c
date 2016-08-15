/* Copyright (c) Citrix Systems Inc.
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

#include <ndis.h>
#include <procgrp.h>
#include <tcpip.h>
#include <xen.h>

#include "util.h"
#include "receiver.h"
#include "adapter.h"
#include "dbg_print.h"
#include "assert.h"

typedef struct _XENNET_RECEIVER_QUEUE {
    PNET_BUFFER_LIST    Head;
    PNET_BUFFER_LIST    Tail;
    ULONG               Count;
} XENNET_RECEIVER_QUEUE, *PXENNET_RECEIVER_QUEUE;

struct _XENNET_RECEIVER {
    PXENNET_ADAPTER             Adapter;
    NDIS_HANDLE                 NetBufferListPool;
    PNET_BUFFER_LIST            PutList;
    PNET_BUFFER_LIST            GetList[HVM_MAX_VCPUS];
    XENNET_RECEIVER_QUEUE       Queue[HVM_MAX_VCPUS];
    LONG                        InNDIS;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
};

#define RECEIVER_POOL_TAG       'RteN'
#define IN_NDIS_MAX             1024

typedef struct _NET_BUFFER_LIST_RESERVED {
    PVOID   Cookie;
} NET_BUFFER_LIST_RESERVED, *PNET_BUFFER_LIST_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

static FORCEINLINE PNET_BUFFER_LIST
__ReceiverGetNetBufferList(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    ULONG                   Index;
    PNET_BUFFER_LIST        NetBufferList;

    Index = KeGetCurrentProcessorNumberEx(NULL);

    NetBufferList = Receiver->GetList[Index];

    if (NetBufferList == NULL)
        Receiver->GetList[Index] =
            InterlockedExchangePointer(&Receiver->PutList, NULL);

    NetBufferList = Receiver->GetList[Index];

    if (NetBufferList == NULL)
        return NULL;

    Receiver->GetList[Index] = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
    NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

    return NetBufferList;
}

static FORCEINLINE VOID
__ReceiverPutNetBufferList(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST        Old;
    PNET_BUFFER_LIST        New;

    ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(NetBufferList), ==, NULL);

    do {
        Old = Receiver->PutList;

        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = Old;
        New = NetBufferList;
    } while (InterlockedCompareExchangePointer(&Receiver->PutList, New, Old) != Old);
}

static PNET_BUFFER_LIST
__ReceiverAllocateNetBufferList(
    IN  PXENNET_RECEIVER        Receiver,
    IN  PMDL                    Mdl,
    IN  ULONG                   Offset,
    IN  ULONG                   Length,
    IN  PVOID                   Cookie
    )
{
    PNET_BUFFER_LIST            NetBufferList;
    PNET_BUFFER_LIST_RESERVED   ListReserved;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    NetBufferList = __ReceiverGetNetBufferList(Receiver);
    if (NetBufferList != NULL) {
        PNET_BUFFER NetBuffer;

        NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, Ieee8021QNetBufferListInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, NetBufferListHashInfo) = NULL;
        NET_BUFFER_LIST_INFO(NetBufferList, NetBufferListHashValue) = NULL;

        NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
        NET_BUFFER_FIRST_MDL(NetBuffer) = Mdl;
        NET_BUFFER_CURRENT_MDL(NetBuffer) = Mdl;
        NET_BUFFER_DATA_OFFSET(NetBuffer) = Offset;
        NET_BUFFER_DATA_LENGTH(NetBuffer) = Length;
        NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = Offset;

        ASSERT3P(NET_BUFFER_NEXT_NB(NetBuffer), ==, NULL);
    } else {
        NetBufferList = NdisAllocateNetBufferAndNetBufferList(Receiver->NetBufferListPool,
                                                              0,
                                                              0,
                                                              Mdl,
                                                              Offset,
                                                              Length);
        ASSERT(IMPLY(NetBufferList != NULL, NET_BUFFER_LIST_NEXT_NBL(NetBufferList) == NULL));
    }

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
    ASSERT3P(ListReserved->Cookie, ==, NULL);
    ListReserved->Cookie = Cookie;

    return NetBufferList;
}        

static PVOID
__ReceiverReleaseNetBufferList(
    IN  PXENNET_RECEIVER        Receiver,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  BOOLEAN                 Cache
    )
{
    PNET_BUFFER_LIST_RESERVED   ListReserved;
    PVOID                       Cookie;

    ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
    Cookie = ListReserved->Cookie;
    ListReserved->Cookie = NULL;

    if (Cache)
        __ReceiverPutNetBufferList(Receiver, NetBufferList);
    else
        NdisFreeNetBufferList(NetBufferList);

    return Cookie;
}

static FORCEINLINE VOID
__ReceiverReturnNetBufferList(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  BOOLEAN             Cache
    )
{
    PXENVIF_VIF_INTERFACE   VifInterface;
    PVOID                   Cookie;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);

    Cookie = __ReceiverReleaseNetBufferList(Receiver, NetBufferList, Cache);

    XENVIF_VIF(ReceiverReturnPacket,
               VifInterface,
               Cookie);

    (VOID) InterlockedDecrement(&Receiver->InNDIS);
}

static PNET_BUFFER_LIST
__ReceiverReceivePacket(
    IN  PXENNET_RECEIVER                        Receiver,
    IN  PMDL                                    Mdl,
    IN  ULONG                                   Offset,
    IN  ULONG                                   Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS            Flags,
    IN  USHORT                                  MaximumSegmentSize,
    IN  USHORT                                  TagControlInformation,
    IN  PXENVIF_PACKET_INFO                     Info,
    IN  PXENVIF_PACKET_HASH                     Hash,
    IN  PVOID                                   Cookie
    )
{
    PNET_BUFFER_LIST                            NetBufferList;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO   csumInfo;

    UNREFERENCED_PARAMETER(MaximumSegmentSize);
    UNREFERENCED_PARAMETER(Info);

    NetBufferList = __ReceiverAllocateNetBufferList(Receiver,
                                                    Mdl,
                                                    Offset,
                                                    Length,
                                                    Cookie);
    if (NetBufferList == NULL)
        goto fail1;

    NetBufferList->SourceHandle = AdapterGetHandle(Receiver->Adapter);

    csumInfo.Value = 0;

    csumInfo.Receive.IpChecksumSucceeded = Flags.IpChecksumSucceeded;
    csumInfo.Receive.IpChecksumFailed = Flags.IpChecksumFailed;

    csumInfo.Receive.TcpChecksumSucceeded = Flags.TcpChecksumSucceeded;
    csumInfo.Receive.TcpChecksumFailed = Flags.TcpChecksumFailed;

    csumInfo.Receive.UdpChecksumSucceeded = Flags.UdpChecksumSucceeded;
    csumInfo.Receive.UdpChecksumFailed = Flags.UdpChecksumFailed;

    NET_BUFFER_LIST_INFO(NetBufferList, TcpIpChecksumNetBufferListInfo) = (PVOID)(ULONG_PTR)csumInfo.Value;

    if (TagControlInformation != 0) {
        NDIS_NET_BUFFER_LIST_8021Q_INFO Ieee8021QInfo;

        UNPACK_TAG_CONTROL_INFORMATION(TagControlInformation,
                                       Ieee8021QInfo.TagHeader.UserPriority,
                                       Ieee8021QInfo.TagHeader.CanonicalFormatId,
                                       Ieee8021QInfo.TagHeader.VlanId);

        if (Ieee8021QInfo.TagHeader.VlanId != 0)
            goto fail2;

        NET_BUFFER_LIST_INFO(NetBufferList, Ieee8021QNetBufferListInfo) = Ieee8021QInfo.Value;
    }

    switch (Hash->Algorithm) {
    case XENVIF_PACKET_HASH_ALGORITHM_TOEPLITZ:
        NET_BUFFER_LIST_SET_HASH_FUNCTION(NetBufferList,
                                          NdisHashFunctionToeplitz);
        break;

    default:
        break;
    }

    switch (Hash->Type) {
    case XENVIF_PACKET_HASH_TYPE_IPV4:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_IPV4);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV4_TCP:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_TCP_IPV4);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV6:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_IPV6);
        break;

    case XENVIF_PACKET_HASH_TYPE_IPV6_TCP:
        NET_BUFFER_LIST_SET_HASH_TYPE(NetBufferList,
                                      NDIS_HASH_TCP_IPV6);
        break;
    }

    NET_BUFFER_LIST_SET_HASH_VALUE(NetBufferList,
                                   Hash->Value);


    return NetBufferList;

fail2:
    (VOID) __ReceiverReleaseNetBufferList(Receiver, NetBufferList, TRUE);

fail1:
    return NULL;
}

static VOID
__ReceiverPushPackets(
    IN  PXENNET_RECEIVER    Receiver,
    IN  ULONG               Index
    )
{
    ULONG                   Flags;
    LONG                    InNDIS;
    PXENNET_RECEIVER_QUEUE  Queue;
    PNET_BUFFER_LIST        NetBufferList;
    ULONG                   Count;

    InNDIS = InterlockedIncrement(&Receiver->InNDIS);

    Flags = NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL |
            NDIS_RECEIVE_FLAGS_PERFECT_FILTERED;

    if (InNDIS > IN_NDIS_MAX)
        Flags |= NDIS_RECEIVE_FLAGS_RESOURCES;

    Queue = &Receiver->Queue[Index];

    NetBufferList = Queue->Head;
    Count = Queue->Count;

    RtlZeroMemory(Queue, sizeof (XENNET_RECEIVER_QUEUE));

    NdisMIndicateReceiveNetBufferLists(AdapterGetHandle(Receiver->Adapter),
                                       NetBufferList,
                                       NDIS_DEFAULT_PORT_NUMBER,
                                       Count,
                                       Flags);

    if (Flags & NDIS_RECEIVE_FLAGS_RESOURCES)
        (VOID) __ReceiverReturnNetBufferList(Receiver, NetBufferList, FALSE);
}

NDIS_STATUS
ReceiverInitialize(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PXENNET_RECEIVER    *Receiver
    )
{
    NET_BUFFER_LIST_POOL_PARAMETERS Params;
    NDIS_STATUS                     status;

    *Receiver = ExAllocatePoolWithTag(NonPagedPool,
                                      sizeof(XENNET_RECEIVER),
                                      RECEIVER_POOL_TAG);

    status = NDIS_STATUS_RESOURCES;
    if (*Receiver == NULL)
        goto fail1;

    RtlZeroMemory(*Receiver, sizeof(XENNET_RECEIVER));
    (*Receiver)->Adapter = Adapter;

    RtlZeroMemory(&Params, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
    Params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    Params.Header.Size = sizeof(Params);
    Params.ProtocolId = 0;
    Params.ContextSize = 0;
    Params.fAllocateNetBuffer = TRUE;
    Params.PoolTag = 'PteN';

    (*Receiver)->NetBufferListPool = NdisAllocateNetBufferListPool(AdapterGetHandle(Adapter),
                                                                   &Params);

    status = NDIS_STATUS_RESOURCES;
    if ((*Receiver)->NetBufferListPool == NULL)
        goto fail2;

    return NDIS_STATUS_SUCCESS;

fail2:
fail1:
    return status;
}

VOID
ReceiverTeardown(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    ULONG                   Index;
    PNET_BUFFER_LIST        NetBufferList;

    ASSERT(Receiver != NULL);

    for (Index = 0; Index < HVM_MAX_VCPUS; Index++) {
        NetBufferList = Receiver->GetList[Index];

        while (NetBufferList != NULL) {
            PNET_BUFFER_LIST    Next;

            Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
            NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

            NdisFreeNetBufferList(NetBufferList);

            NetBufferList = Next;
        }
    }

    NetBufferList = Receiver->PutList;
    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST    Next;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        NdisFreeNetBufferList(NetBufferList);

        NetBufferList = Next;
    }

    NdisFreeNetBufferListPool(Receiver->NetBufferListPool);
    Receiver->NetBufferListPool = NULL;

    Receiver->Adapter = NULL;

    ExFreePoolWithTag(Receiver, RECEIVER_POOL_TAG);
}

VOID
ReceiverReturnNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  ULONG               ReturnFlags
    )
{
    UNREFERENCED_PARAMETER(ReturnFlags);

    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST        Next;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        __ReceiverReturnNetBufferList(Receiver, NetBufferList, TRUE);

        NetBufferList = Next;
    }
}

VOID
ReceiverQueuePacket(
    IN  PXENNET_RECEIVER                Receiver,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie
    )
{
    PXENVIF_VIF_INTERFACE               VifInterface;
    PNET_BUFFER_LIST                    NetBufferList;
    ULONG                               Index;
    PXENNET_RECEIVER_QUEUE              Queue;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);

    NetBufferList = __ReceiverReceivePacket(Receiver,
                                            Mdl,
                                            Offset,
                                            Length,
                                            Flags,
                                            MaximumSegmentSize,
                                            TagControlInformation,
                                            Info,
                                            Hash,
                                            Cookie);
    if (NetBufferList == NULL) {
        XENVIF_VIF(ReceiverReturnPacket,
                   VifInterface,
                   Cookie);
        return;
    }

    Index = KeGetCurrentProcessorNumberEx(NULL);

    Queue = &Receiver->Queue[Index];

    if (Queue->Head == NULL) {
        ASSERT3U(Queue->Count, ==, 0);
        Queue->Head = Queue->Tail = NetBufferList;
    } else {
        NET_BUFFER_LIST_NEXT_NBL(Queue->Tail) = NetBufferList;
        Queue->Tail = NetBufferList;
    }
    Queue->Count++;

    if (!More)
        __ReceiverPushPackets(Receiver, Index);
}

PXENVIF_VIF_OFFLOAD_OPTIONS
ReceiverOffloadOptions(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    return &Receiver->OffloadOptions;
}
