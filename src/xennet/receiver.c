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

#include "receiver.h"
#include "adapter.h"
#include <util.h>
#include "dbg_print.h"
#include "assert.h"

struct _XENNET_RECEIVER {
    PXENNET_ADAPTER             Adapter;
    NDIS_HANDLE                 NetBufferListPool;
    PNET_BUFFER_LIST            PutList;
    PNET_BUFFER_LIST            GetList;
    KSPIN_LOCK                  Lock;
    LONG                        InNDIS;
    LONG                        InNDISMax;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
};

#define RECEIVER_POOL_TAG       'RteN'
#define IN_NDIS_MAX             1024

static PNET_BUFFER_LIST
__ReceiverAllocateNetBufferList(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PMDL                Mdl,
    IN  ULONG               Offset,
    IN  ULONG               Length
    )
{
    PNET_BUFFER_LIST        NetBufferList;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Receiver->Lock);

    if (Receiver->GetList == NULL)
        Receiver->GetList = InterlockedExchangePointer(&Receiver->PutList, NULL);

    NetBufferList = Receiver->GetList;
    if (NetBufferList != NULL) {
        PNET_BUFFER NetBuffer;

        Receiver->GetList = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
        NET_BUFFER_FIRST_MDL(NetBuffer) = Mdl;
        NET_BUFFER_CURRENT_MDL(NetBuffer) = Mdl;
        NET_BUFFER_DATA_OFFSET(NetBuffer) = Offset;
        NET_BUFFER_DATA_LENGTH(NetBuffer) = Length;
        NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = Offset;
    } else {
        NetBufferList = NdisAllocateNetBufferAndNetBufferList(Receiver->NetBufferListPool,
                                                              0,
                                                              0,
                                                              Mdl,
                                                              Offset,
                                                              Length);
        ASSERT(IMPLY(NetBufferList != NULL, NET_BUFFER_LIST_NEXT_NBL(NetBufferList) == NULL));
    }

    KeReleaseSpinLockFromDpcLevel(&Receiver->Lock);

    return NetBufferList;
}        

static VOID
__ReceiverReleaseNetBufferList(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  BOOLEAN             Cache
    )
{
    if (Cache) {
        PNET_BUFFER_LIST    Old;
        PNET_BUFFER_LIST    New;

        ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(NetBufferList), ==, NULL);

        do {
            Old = Receiver->PutList;

            NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = Old;
            New = NetBufferList;
        } while (InterlockedCompareExchangePointer(&Receiver->PutList, New, Old) != Old);
    } else {
        NdisFreeNetBufferList(NetBufferList);
    }
}

static FORCEINLINE ULONG
__ReceiverReturnNetBufferLists(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  BOOLEAN             Cache
    )
{
    PXENVIF_VIF_INTERFACE   VifInterface;
    LIST_ENTRY              List;
    ULONG                   Count;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);
    InitializeListHead(&List);

    Count = 0;
    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST        Next;
        PNET_BUFFER             NetBuffer;
        PMDL                    Mdl;
        PXENVIF_RECEIVER_PACKET Packet;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
        ASSERT3P(NET_BUFFER_NEXT_NB(NetBuffer), ==, NULL);

        Mdl = NET_BUFFER_FIRST_MDL(NetBuffer);

        __ReceiverReleaseNetBufferList(Receiver, NetBufferList, Cache);

        Packet = CONTAINING_RECORD(Mdl, XENVIF_RECEIVER_PACKET, Mdl);

        InsertTailList(&List, &Packet->ListEntry);

        Count++;
        NetBufferList = Next;
    }

    if (Count != 0)
        XENVIF_VIF(ReceiverReturnPackets,
                   VifInterface,
                   &List);

    return Count;
}

static PNET_BUFFER_LIST
__ReceiverReceivePacket(
    IN  PXENNET_RECEIVER                Receiver,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          TagControlInformation
    )
{
    PNET_BUFFER_LIST                            NetBufferList;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO   csumInfo;

    NetBufferList = __ReceiverAllocateNetBufferList(Receiver,
                                                    Mdl,
                                                    Offset,
                                                    Length);
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

    return NetBufferList;

fail2:
    __ReceiverReleaseNetBufferList(Receiver, NetBufferList, TRUE);

fail1:
    return NULL;
}

static VOID
__ReceiverPushPackets(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  ULONG               Count,
    IN  BOOLEAN             LowResources
    )
{
    ULONG                   Flags;
    LONG                    InNDIS;

    InNDIS = Receiver->InNDIS;

    Flags = NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL;
    if (LowResources) {
        Flags |= NDIS_RECEIVE_FLAGS_RESOURCES;
    } else {
        InNDIS = __InterlockedAdd(&Receiver->InNDIS, Count);
    }

    for (;;) {
        LONG    InNDISMax;

        InNDISMax = Receiver->InNDISMax;
        KeMemoryBarrier();

        if (InNDIS <= InNDISMax)
            break;

        if (InterlockedCompareExchange(&Receiver->InNDISMax, InNDIS, InNDISMax) == InNDISMax)
            break;
    }

    NdisMIndicateReceiveNetBufferLists(AdapterGetHandle(Receiver->Adapter),
                                       NetBufferList,
                                       NDIS_DEFAULT_PORT_NUMBER,
                                       Count,
                                       Flags);

    if (LowResources)
        (VOID) __ReceiverReturnNetBufferLists(Receiver, NetBufferList, FALSE);
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

    KeInitializeSpinLock(&(*Receiver)->Lock);

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
    PNET_BUFFER_LIST        NetBufferList;

    ASSERT(Receiver != NULL);

    NetBufferList = Receiver->GetList;
    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST    Next;

        Next = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        NdisFreeNetBufferList(NetBufferList);

        NetBufferList = Next;
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
    ULONG                   Count;

    UNREFERENCED_PARAMETER(ReturnFlags);

    Count = __ReceiverReturnNetBufferLists(Receiver, NetBufferList, TRUE);
    (VOID) __InterlockedSubtract(&Receiver->InNDIS, Count);
}

VOID
ReceiverReceivePackets(
    IN  PXENNET_RECEIVER    Receiver,
    IN  PLIST_ENTRY         List
    )
{
    PXENVIF_VIF_INTERFACE   VifInterface;
    PNET_BUFFER_LIST        HeadNetBufferList;
    PNET_BUFFER_LIST        *TailNetBufferList;
    ULONG                   Count;
    BOOLEAN                 LowResources;

    VifInterface = AdapterGetVifInterface(Receiver->Adapter);
    LowResources = FALSE;

again:
    HeadNetBufferList = NULL;
    TailNetBufferList = &HeadNetBufferList;
    Count = 0;

    while (!IsListEmpty(List)) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_RECEIVER_PACKET         Packet;
        PXENVIF_PACKET_INFO             Info;
        PMDL                            Mdl;
        ULONG                           Offset;
        ULONG                           Length;
        XENVIF_PACKET_CHECKSUM_FLAGS    Flags;
        USHORT                          TagControlInformation;
        PNET_BUFFER_LIST                NetBufferList;

        if (!LowResources &&
            Receiver->InNDIS + Count > IN_NDIS_MAX)
            break;

        ListEntry = RemoveHeadList(List);
        ASSERT(ListEntry != List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_RECEIVER_PACKET, ListEntry);
        Mdl = &Packet->Mdl;
        Offset = Packet->Offset;
        Length = Packet->Length;
        Flags = Packet->Flags;

        Info = Packet->Info;

        TagControlInformation = Info->TagControlInformation;

        NetBufferList = __ReceiverReceivePacket(Receiver, Mdl, Offset, Length, Flags, TagControlInformation);

        if (NetBufferList != NULL) {
            *TailNetBufferList = NetBufferList;
            TailNetBufferList = &NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
            Count++;
        } else {
            LIST_ENTRY  PacketList;

            InitializeListHead(&PacketList);
            InsertTailList(&PacketList, &Packet->ListEntry);

            XENVIF_VIF(ReceiverReturnPackets,
                       VifInterface,
                       &PacketList);
        }
    }

    if (Count != 0) {
        ASSERT(HeadNetBufferList != NULL);

        __ReceiverPushPackets(Receiver, HeadNetBufferList, Count, LowResources);
    }

    if (!IsListEmpty(List)) {
        ASSERT(!LowResources);
        LowResources = TRUE;
        goto again;
    }
}

PXENVIF_VIF_OFFLOAD_OPTIONS
ReceiverOffloadOptions(
    IN  PXENNET_RECEIVER    Receiver
    )
{
    return &Receiver->OffloadOptions;
}
