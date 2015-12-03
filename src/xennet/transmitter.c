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
#include "transmitter.h"
#include "adapter.h"
#include <vif_interface.h>
#include <cache_interface.h>
#include <tcpip.h>
#include "dbg_print.h"
#include "assert.h"

struct _XENNET_TRANSMITTER {
    PXENNET_ADAPTER             Adapter;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    KSPIN_LOCK                  Lock;
    PXENBUS_CACHE               PacketCache;
    PXENBUS_CACHE               BufferCache;
};

#define XENNET_PACKET_CACHE_MIN     32
#define TRANSMITTER_POOL_TAG        'TteN'
#define BUFFER_CACHE_ITEM_SIZE      512
#define MAX_HEADERS_LENGTH          (sizeof(IP_ADDRESS) + sizeof(IP_ADDRESS) + sizeof(USHORT) + sizeof(USHORT))

static NTSTATUS
__TransmitterPacketCtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static VOID
__TransmitterPacketDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static VOID
__TransmitterPacketAcquireLock(
    IN  PVOID           Argument
    )
{
    PXENNET_TRANSMITTER Transmitter = Argument;

    KeAcquireSpinLockAtDpcLevel(&Transmitter->Lock);
}

static VOID
__TransmitterPacketReleaseLock(
    IN  PVOID           Argument
    )
{
    PXENNET_TRANSMITTER Transmitter = Argument;

#pragma prefast(suppress:26110)
    KeReleaseSpinLockFromDpcLevel(&Transmitter->Lock);
}

static NTSTATUS
__TransmitterBufferCtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static VOID
__TransmitterBufferDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static VOID
__TransmitterBufferAcquireLock(
    IN  PVOID           Argument
    )
{
    PXENNET_TRANSMITTER Transmitter = Argument;

    KeAcquireSpinLockAtDpcLevel(&Transmitter->Lock);
}

static VOID
__TransmitterBufferReleaseLock(
    IN  PVOID           Argument
    )
{
    PXENNET_TRANSMITTER Transmitter = Argument;

#pragma prefast(suppress:26110)
    KeReleaseSpinLockFromDpcLevel(&Transmitter->Lock);
}

NDIS_STATUS
TransmitterInitialize (
    IN  PXENNET_ADAPTER     Adapter,
    OUT PXENNET_TRANSMITTER *Transmitter
    )
{
    *Transmitter = ExAllocatePoolWithTag(NonPagedPool,
                                         sizeof(XENNET_TRANSMITTER),
                                         TRANSMITTER_POOL_TAG);

    if (*Transmitter == NULL)
        goto fail1;

    RtlZeroMemory(*Transmitter, sizeof(XENNET_TRANSMITTER));

    (*Transmitter)->Adapter = Adapter;

    KeInitializeSpinLock(&(*Transmitter)->Lock);

    return NDIS_STATUS_SUCCESS;

fail1:
    return NDIS_STATUS_FAILURE;
}

NDIS_STATUS
TransmitterEnable (
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;
    NTSTATUS                status;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    status = XENBUS_CACHE(Create,
                          CacheInterface,
                          "packet_cache",
                          sizeof(XENVIF_TRANSMITTER_PACKET),
                          XENNET_PACKET_CACHE_MIN,
                          __TransmitterPacketCtor,
                          __TransmitterPacketDtor,
                          __TransmitterPacketAcquireLock,
                          __TransmitterPacketReleaseLock,
                          Transmitter,
                          &Transmitter->PacketCache);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_CACHE(Create,
                          CacheInterface,
                          "buffer_cache",
                          BUFFER_CACHE_ITEM_SIZE,
                          0,
                          __TransmitterBufferCtor,
                          __TransmitterBufferDtor,
                          __TransmitterBufferAcquireLock,
                          __TransmitterBufferReleaseLock,
                          Transmitter,
                          &Transmitter->BufferCache);
    if (!NT_SUCCESS(status))
        goto fail2;

    return NDIS_STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_CACHE(Destroy,
                 CacheInterface,
                 Transmitter->PacketCache);
    Transmitter->PacketCache = NULL;

fail1:
    Error("fail1\n (%08x)", status);

    return NDIS_STATUS_FAILURE;
}

VOID
TransmitterDisable (
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    XENBUS_CACHE(Destroy,
                 CacheInterface,
                 Transmitter->BufferCache);
    Transmitter->BufferCache = NULL;

    XENBUS_CACHE(Destroy,
                 CacheInterface,
                 Transmitter->PacketCache);
    Transmitter->PacketCache = NULL;
}

VOID
TransmitterTeardown(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    Transmitter->Adapter = NULL;
    Transmitter->OffloadOptions.Value = 0;

    RtlZeroMemory(&Transmitter->Lock, sizeof(KSPIN_LOCK));

    ExFreePoolWithTag(Transmitter, TRANSMITTER_POOL_TAG);
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterGetPacket(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    return XENBUS_CACHE(Get,
                        CacheInterface,
                        Transmitter->PacketCache,
                        FALSE);
}

static FORCEINLINE VOID
__TransmitterPutPacket(
    IN  PXENNET_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    RtlZeroMemory(Packet, sizeof(XENVIF_TRANSMITTER_PACKET));

    XENBUS_CACHE(Put,
                 CacheInterface,
                 Transmitter->PacketCache,
                 Packet,
                 FALSE);
}

static FORCEINLINE PVOID
__TransmitterGetBuffer(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    return XENBUS_CACHE(Get,
                        CacheInterface,
                        Transmitter->BufferCache,
                        FALSE);
}

static FORCEINLINE VOID
__TransmitterPutBuffer(
    IN  PXENNET_TRANSMITTER Transmitter,
    IN  PVOID               Buffer
    )
{
    PXENBUS_CACHE_INTERFACE CacheInterface;

    CacheInterface = AdapterGetCacheInterface(Transmitter->Adapter);

    RtlZeroMemory(Buffer, BUFFER_CACHE_ITEM_SIZE);

    XENBUS_CACHE(Put,
                 CacheInterface,
                 Transmitter->BufferCache,
                 Buffer,
                 FALSE);
}

typedef struct _NET_BUFFER_LIST_RESERVED {
    LONG    Reference;
} NET_BUFFER_LIST_RESERVED, *PNET_BUFFER_LIST_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

static VOID
__TransmitterCompleteNetBufferList(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  NDIS_STATUS             Status
    )
{
    ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(NetBufferList), ==, NULL);

    NET_BUFFER_LIST_STATUS(NetBufferList) = Status;

    if (Status == NDIS_STATUS_SUCCESS) {
        PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO   LargeSendInfo;

        LargeSendInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)
                                &NET_BUFFER_LIST_INFO(NetBufferList,
                                                      TcpLargeSendNetBufferListInfo);
        if (LargeSendInfo->LsoV2Transmit.MSS != 0)
            LargeSendInfo->LsoV2TransmitComplete.Reserved = 0;
    }

    NdisMSendNetBufferListsComplete(AdapterGetHandle(Transmitter->Adapter),
                                    NetBufferList,
                                    NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
}

static VOID
__TransmitterCompletePackets(
    IN  PXENNET_TRANSMITTER Transmitter,
    IN  PLIST_ENTRY         List,
    IN  NDIS_STATUS         Status
    )
{
    while (!IsListEmpty(List)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_PACKET  Packet;
        PNET_BUFFER_LIST            NetBufferList;
        PNET_BUFFER_LIST_RESERVED   ListReserved;

        ListEntry = RemoveHeadList(List);
        ASSERT3P(ListEntry, !=, List);

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);

        NetBufferList = Packet->Cookie;
        ASSERT(NetBufferList != NULL);

        ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);

        ASSERT(ListReserved->Reference != 0);
        if (InterlockedDecrement(&ListReserved->Reference) == 0)
            __TransmitterCompleteNetBufferList(Transmitter, NetBufferList, Status);

        __TransmitterPutPacket(Transmitter, Packet);
    }
}

static VOID
__TransmitterOffloadOptions(
    IN  PNET_BUFFER_LIST            NetBufferList,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS OffloadOptions,
    OUT PUSHORT                     TagControlInformation,
    OUT PUSHORT                     MaximumSegmentSize
    )
{
    PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO   LargeSendInfo;
    PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO          ChecksumInfo;
    PNDIS_NET_BUFFER_LIST_8021Q_INFO                    Ieee8021QInfo;

    LargeSendInfo = (PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                                                TcpLargeSendNetBufferListInfo);
    ChecksumInfo = (PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                                        TcpIpChecksumNetBufferListInfo);
    Ieee8021QInfo = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)&NET_BUFFER_LIST_INFO(NetBufferList,
                                                                            Ieee8021QNetBufferListInfo);

    OffloadOptions->Value = 0;
    *TagControlInformation = 0;
    *MaximumSegmentSize = 0;

    if (ChecksumInfo->Transmit.IsIPv4) {
        if (ChecksumInfo->Transmit.IpHeaderChecksum)
            OffloadOptions->OffloadIpVersion4HeaderChecksum = 1;

        if (ChecksumInfo->Transmit.TcpChecksum)
            OffloadOptions->OffloadIpVersion4TcpChecksum = 1;

        if (ChecksumInfo->Transmit.UdpChecksum)
            OffloadOptions->OffloadIpVersion4UdpChecksum = 1;
    }

    if (ChecksumInfo->Transmit.IsIPv6) {
        if (ChecksumInfo->Transmit.TcpChecksum)
            OffloadOptions->OffloadIpVersion6TcpChecksum = 1;

        if (ChecksumInfo->Transmit.UdpChecksum)
            OffloadOptions->OffloadIpVersion6UdpChecksum = 1;
    }

    if (Ieee8021QInfo->TagHeader.UserPriority != 0) {
        OffloadOptions->OffloadTagManipulation = 1;

        ASSERT3U(Ieee8021QInfo->TagHeader.CanonicalFormatId, ==, 0);
        ASSERT3U(Ieee8021QInfo->TagHeader.VlanId, ==, 0);

        PACK_TAG_CONTROL_INFORMATION(*TagControlInformation,
                                        Ieee8021QInfo->TagHeader.UserPriority,
                                        Ieee8021QInfo->TagHeader.CanonicalFormatId,
                                        Ieee8021QInfo->TagHeader.VlanId);
    }

    if (LargeSendInfo->LsoV2Transmit.MSS != 0) {
        if (LargeSendInfo->LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4)
            OffloadOptions->OffloadIpVersion4LargePacket = 1;

        if (LargeSendInfo->LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6)
            OffloadOptions->OffloadIpVersion6LargePacket = 1;

        ASSERT3U(LargeSendInfo->LsoV2Transmit.MSS >> 16, ==, 0);
        *MaximumSegmentSize = (USHORT)LargeSendInfo->LsoV2Transmit.MSS;
    }
}

static ULONG
__Hash(
    IN  PVOID                       Buffer,
    IN  ULONG                       Length
    )
{
    PUCHAR                          Array = (PUCHAR)Buffer;
    ULONG                           Accumulator;
    ULONG                           Index;

    Accumulator = 0;

    for (Index = 0; Index < Length; ++Index) {
        ULONG   Overflow;

        Accumulator = (Accumulator << 4) + Array[Index];

        Overflow = Accumulator & 0x00000f00;
        if (Overflow != 0) {
            Accumulator ^= Overflow >> 8;
            Accumulator ^= Overflow;
        }
    }

    return Accumulator;
}

static ULONG
__TransmitterCalculateHash(
    IN  PVOID                       Buffer,
    IN  PXENVIF_PACKET_INFO         Info
    )
{
    UCHAR       Headers[MAX_HEADERS_LENGTH];
    PUCHAR      Ptr;

    Ptr = (PUCHAR)Headers;

    if (Info->IpHeader.Length) {
        PIP_HEADER  Ip = (PIP_HEADER)((PUCHAR)Buffer + Info->IpHeader.Offset);

        switch (Ip->Version) {
        case 4:
            RtlCopyMemory(Ptr, &Ip->Version4.SourceAddress, sizeof(IPV4_ADDRESS));
            Ptr += sizeof(IPV4_ADDRESS);
            RtlCopyMemory(Ptr, &Ip->Version4.DestinationAddress, sizeof(IPV4_ADDRESS));
            Ptr += sizeof(IPV4_ADDRESS);
            break;
        case 6:
            RtlCopyMemory(Ptr, &Ip->Version6.SourceAddress, sizeof(IPV6_ADDRESS));
            Ptr += sizeof(IPV6_ADDRESS);
            RtlCopyMemory(Ptr, &Ip->Version6.DestinationAddress, sizeof(IPV6_ADDRESS));
            Ptr += sizeof(IPV6_ADDRESS);
            break;
        default:
            break;
        }
    }

    if (Info->TcpHeader.Length) {
        PTCP_HEADER Tcp = (PTCP_HEADER)((PUCHAR)Buffer + Info->TcpHeader.Offset);

        RtlCopyMemory(Ptr, &Tcp->SourcePort, sizeof(USHORT));
        Ptr += sizeof(USHORT);
        RtlCopyMemory(Ptr, &Tcp->DestinationPort, sizeof(USHORT));
        Ptr += sizeof(USHORT);
    } else if (Info->UdpHeader.Length) {
        PUDP_HEADER Udp = (PUDP_HEADER)((PUCHAR)Buffer + Info->UdpHeader.Offset);

        RtlCopyMemory(Ptr, &Udp->SourcePort, sizeof(USHORT));
        Ptr += sizeof(USHORT);
        RtlCopyMemory(Ptr, &Udp->DestinationPort, sizeof(USHORT));
        Ptr += sizeof(USHORT);
    }

    if (Ptr == (PUCHAR)Headers)
        return 0;

    return __Hash(Headers, (ULONG)((ULONG_PTR)Ptr - (ULONG_PTR)Headers));
}

static ULONG
__TransmitterGetHash(
    IN  PXENNET_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_VIF_INTERFACE           VifInterface;
    ULONG                           Hash;
    XENVIF_PACKET_INFO              Info;
    PVOID                           Buffer;
    NTSTATUS                        status;

    Hash = 0;
    VifInterface = AdapterGetVifInterface(Transmitter->Adapter);

    Buffer = __TransmitterGetBuffer(Transmitter);
    if (Buffer == NULL)
        goto fail1;

    RtlZeroMemory(&Info, sizeof(XENVIF_PACKET_INFO));

    status = XENVIF_VIF(TransmitterGetPacketHeaders,
                        VifInterface,
                        Packet,
                        Buffer,
                        &Info);
    if (!NT_SUCCESS(status))
        goto fail2;

    Hash = __TransmitterCalculateHash(Buffer, &Info);

    __TransmitterPutBuffer(Transmitter, Buffer);
    return Hash;

fail2:
    __TransmitterPutBuffer(Transmitter, Buffer);
fail1:
    return 0;
}

VOID
TransmitterSendNetBufferLists(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  NDIS_PORT_NUMBER        PortNumber,
    IN  ULONG                   SendFlags
    )
{
    LIST_ENTRY                  List;
    KIRQL                       Irql;

    UNREFERENCED_PARAMETER(PortNumber);

    InitializeListHead(&List);

    if (!NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags)) {
        ASSERT3U(NDIS_CURRENT_IRQL(), <=, DISPATCH_LEVEL);
        NDIS_RAISE_IRQL_TO_DISPATCH(&Irql);
    } else {
        Irql = DISPATCH_LEVEL;
    }

    while (NetBufferList != NULL) {
        PNET_BUFFER_LIST            ListNext;
        PNET_BUFFER_LIST_RESERVED   ListReserved;
        PNET_BUFFER                 NetBuffer;
        XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
        USHORT                      TagControlInformation;
        USHORT                      MaximumSegmentSize;

        ListNext = NET_BUFFER_LIST_NEXT_NBL(NetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(NetBufferList) = NULL;

        __TransmitterOffloadOptions(NetBufferList,
                                    &OffloadOptions,
                                    &TagControlInformation,
                                    &MaximumSegmentSize);

        ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);
        RtlZeroMemory(ListReserved, sizeof (NET_BUFFER_LIST_RESERVED));

        NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
        while (NetBuffer != NULL) {
            PXENVIF_TRANSMITTER_PACKET  Packet;

            Packet = __TransmitterGetPacket(Transmitter);
            if (Packet == NULL) {
                while (ListReserved->Reference--) {
                    PLIST_ENTRY     ListEntry;

                    ListEntry = RemoveTailList(&List);
                    ASSERT3P(ListEntry, !=, &List);

                    Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);

                    __TransmitterPutPacket(Transmitter, Packet);
                }
                __TransmitterCompleteNetBufferList(Transmitter, NetBufferList, NDIS_STATUS_NOT_ACCEPTED);
                break;
            }

            ListReserved->Reference++;

            Packet->Cookie = NetBufferList;
            Packet->Send.OffloadOptions.Value = OffloadOptions.Value & Transmitter->OffloadOptions.Value;
            Packet->Send.MaximumSegmentSize = MaximumSegmentSize;
            Packet->Send.TagControlInformation = TagControlInformation;
            Packet->Mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
            Packet->Length = NET_BUFFER_DATA_LENGTH(NetBuffer);
            Packet->Offset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
            Packet->Value = __TransmitterGetHash(Transmitter, Packet);

            InsertTailList(&List, &Packet->ListEntry);

            NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer);
        }

        NetBufferList = ListNext;
    }

    if (!IsListEmpty(&List)) {
        NTSTATUS    status; 

        status = XENVIF_VIF(TransmitterQueuePackets,
                            AdapterGetVifInterface(Transmitter->Adapter),
                            &List);
        if (!NT_SUCCESS(status))
            __TransmitterCompletePackets(Transmitter, &List, NDIS_STATUS_NOT_ACCEPTED);
    }

    NDIS_LOWER_IRQL(Irql, DISPATCH_LEVEL);
}

VOID
TransmitterCompletePackets(
    IN  PXENNET_TRANSMITTER Transmitter,
    IN  PLIST_ENTRY         List
    )
{
    __TransmitterCompletePackets(Transmitter, List, NDIS_STATUS_SUCCESS);
}

PXENVIF_VIF_OFFLOAD_OPTIONS
TransmitterOffloadOptions(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    return &Transmitter->OffloadOptions;
}
