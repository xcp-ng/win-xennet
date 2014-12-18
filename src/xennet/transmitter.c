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
#include "dbg_print.h"
#include "assert.h"

struct _XENNET_TRANSMITTER {
    PXENNET_ADAPTER             Adapter;
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
};

#define TRANSMITTER_POOL_TAG        'TteN'

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

    return NDIS_STATUS_SUCCESS;

fail1:
    return NDIS_STATUS_FAILURE;
}

VOID
TransmitterTeardown(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    Transmitter->Adapter = NULL;
    Transmitter->OffloadOptions.Value = 0;

    ExFreePoolWithTag(Transmitter, TRANSMITTER_POOL_TAG);
}

VOID
TransmitterEnable(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    PXENVIF_VIF_INTERFACE   VifInterface = AdapterGetVifInterface(Transmitter->Adapter);

    (VOID) XENVIF_VIF(TransmitterSetPacketOffset,
                      VifInterface,
                      XENVIF_TRANSMITTER_PACKET_OFFSET_OFFSET,
                      (LONG_PTR)&NET_BUFFER_CURRENT_MDL_OFFSET((PNET_BUFFER)NULL) -
                      (LONG_PTR)&NET_BUFFER_MINIPORT_RESERVED((PNET_BUFFER)NULL));

    (VOID) XENVIF_VIF(TransmitterSetPacketOffset,
                      VifInterface,
                      XENVIF_TRANSMITTER_PACKET_LENGTH_OFFSET,
                      (LONG_PTR)&NET_BUFFER_DATA_LENGTH((PNET_BUFFER)NULL) -
                      (LONG_PTR)&NET_BUFFER_MINIPORT_RESERVED((PNET_BUFFER)NULL));

    (VOID) XENVIF_VIF(TransmitterSetPacketOffset,
                      VifInterface,
                      XENVIF_TRANSMITTER_PACKET_MDL_OFFSET,
                      (LONG_PTR)&NET_BUFFER_CURRENT_MDL((PNET_BUFFER)NULL) -
                      (LONG_PTR)&NET_BUFFER_MINIPORT_RESERVED((PNET_BUFFER)NULL));
}

typedef struct _NET_BUFFER_LIST_RESERVED {
    LONG    Reference;
} NET_BUFFER_LIST_RESERVED, *PNET_BUFFER_LIST_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

typedef struct _NET_BUFFER_RESERVED {
    XENVIF_TRANSMITTER_PACKET   Packet;
    PNET_BUFFER_LIST            NetBufferList;
} NET_BUFFER_RESERVED, *PNET_BUFFER_RESERVED;

C_ASSERT(sizeof (NET_BUFFER_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER, MiniportReserved));

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
    IN  PXENNET_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet,
    IN  NDIS_STATUS                 Status
    )
{
    while (Packet != NULL) {
        PXENVIF_TRANSMITTER_PACKET  Next;
        PNET_BUFFER_RESERVED        Reserved;
        PNET_BUFFER_LIST            NetBufferList;
        PNET_BUFFER_LIST_RESERVED   ListReserved;

        Next = Packet->Next;
        Packet->Next = NULL;

        Reserved = CONTAINING_RECORD(Packet, NET_BUFFER_RESERVED, Packet);

        NetBufferList = Reserved->NetBufferList;
        ASSERT(NetBufferList != NULL);

        ListReserved = (PNET_BUFFER_LIST_RESERVED)NET_BUFFER_LIST_MINIPORT_RESERVED(NetBufferList);

        ASSERT(ListReserved->Reference != 0);
        if (InterlockedDecrement(&ListReserved->Reference) == 0)
            __TransmitterCompleteNetBufferList(Transmitter, NetBufferList, Status);

        Packet = Next;
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

VOID
TransmitterSendNetBufferLists(
    IN  PXENNET_TRANSMITTER     Transmitter,
    IN  PNET_BUFFER_LIST        NetBufferList,
    IN  NDIS_PORT_NUMBER        PortNumber,
    IN  ULONG                   SendFlags
    )
{
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    PXENVIF_TRANSMITTER_PACKET  *TailPacket;
    KIRQL                       Irql;

    UNREFERENCED_PARAMETER(PortNumber);

    HeadPacket = NULL;
    TailPacket = &HeadPacket;

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
            PNET_BUFFER_RESERVED        Reserved;
            PXENVIF_TRANSMITTER_PACKET  Packet;

            Reserved = (PNET_BUFFER_RESERVED)NET_BUFFER_MINIPORT_RESERVED(NetBuffer);
            RtlZeroMemory(Reserved, sizeof (NET_BUFFER_RESERVED));

            Reserved->NetBufferList = NetBufferList;
            ListReserved->Reference++;

            Packet = &Reserved->Packet;
            Packet->Send.OffloadOptions.Value = OffloadOptions.Value & Transmitter->OffloadOptions.Value;
            Packet->Send.MaximumSegmentSize = MaximumSegmentSize;
            Packet->Send.TagControlInformation = TagControlInformation;

            ASSERT3P(Packet->Next, ==, NULL);
            *TailPacket = Packet;
            TailPacket = &Packet->Next;

            NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer);
        }

        NetBufferList = ListNext;
    }

    if (HeadPacket != NULL) {
        NTSTATUS    status; 

        status = XENVIF_VIF(TransmitterQueuePackets,
                            AdapterGetVifInterface(Transmitter->Adapter),
                            HeadPacket);
        if (!NT_SUCCESS(status))
            __TransmitterCompletePackets(Transmitter, HeadPacket, NDIS_STATUS_NOT_ACCEPTED);
    }

    NDIS_LOWER_IRQL(Irql, DISPATCH_LEVEL);
}

VOID
TransmitterCompletePackets(
    IN  PXENNET_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    __TransmitterCompletePackets(Transmitter, Packet, NDIS_STATUS_SUCCESS);
}

PXENVIF_VIF_OFFLOAD_OPTIONS
TransmitterOffloadOptions(
    IN  PXENNET_TRANSMITTER Transmitter
    )
{
    return &Transmitter->OffloadOptions;
}
