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
#include "adapter.h"
#include "transmitter.h"
#include "receiver.h"
#include <vif_interface.h>
#include <cache_interface.h>
#include <version.h>
#include "dbg_print.h"
#include "assert.h"

struct _XENNET_ADAPTER {
    XENVIF_VIF_INTERFACE    VifInterface;
    XENBUS_CACHE_INTERFACE  CacheInterface;

    ULONG                   MaximumFrameSize;
    ULONG                   CurrentLookahead;

    NDIS_HANDLE             NdisAdapterHandle;
    NDIS_HANDLE             NdisDmaHandle;
    NDIS_PNP_CAPABILITIES   Capabilities;
    NDIS_OFFLOAD            Offload;
    PROPERTIES              Properties;

    PXENNET_RECEIVER        Receiver;
    PXENNET_TRANSMITTER     Transmitter;
    BOOLEAN                 Enabled;
};

static NDIS_OID XennetSupportedOids[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_LINK_SPEED,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_VENDOR_ID,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_CRC_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_GEN_TRANSMIT_QUEUE_LENGTH,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_STATISTICS,
    OID_GEN_DIRECTED_BYTES_XMIT,
    OID_GEN_DIRECTED_FRAMES_XMIT,
    OID_GEN_MULTICAST_BYTES_XMIT,
    OID_GEN_MULTICAST_FRAMES_XMIT,
    OID_GEN_BROADCAST_BYTES_XMIT,
    OID_GEN_BROADCAST_FRAMES_XMIT,
    OID_GEN_DIRECTED_BYTES_RCV,
    OID_GEN_DIRECTED_FRAMES_RCV,
    OID_GEN_MULTICAST_BYTES_RCV,
    OID_GEN_MULTICAST_FRAMES_RCV,
    OID_GEN_BROADCAST_BYTES_RCV,
    OID_GEN_BROADCAST_FRAMES_RCV,
    OID_GEN_INTERRUPT_MODERATION,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_OFFLOAD_ENCAPSULATION,
    OID_TCP_OFFLOAD_PARAMETERS,
    OID_PNP_CAPABILITIES,
    OID_PNP_QUERY_POWER,
    OID_PNP_SET_POWER,
};

#define ADAPTER_POOL_TAG    'AteN'

__drv_functionClass(MINIPORT_PROCESS_SG_LIST)
static VOID
AdapterProcessSGList(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PVOID                Reserved,
    IN PSCATTER_GATHER_LIST SGL,
    IN PVOID                Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(SGL);
    UNREFERENCED_PARAMETER(Context);

    ASSERT(FALSE);
}

__drv_functionClass(MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE)
static VOID
AdapterAllocateComplete (
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN PVOID                    VirtualAddress,
    IN PNDIS_PHYSICAL_ADDRESS   PhysicalAddress,
    IN ULONG                    Length,
    IN PVOID                    Context
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Context);

    ASSERT(FALSE);
}

static VOID
AdapterVifCallback(
    IN  PVOID                       Context,
    IN  XENVIF_VIF_CALLBACK_TYPE    Type,
    ...
    )
{
    PXENNET_ADAPTER     Adapter = Context;
    va_list             Arguments;

    va_start(Arguments, Type);

    switch (Type) {
    case XENVIF_TRANSMITTER_RETURN_PACKETS: {
        PLIST_ENTRY List;

        List = va_arg(Arguments, PLIST_ENTRY);

        TransmitterCompletePackets(Adapter->Transmitter, List);
        break;
    }
    case XENVIF_RECEIVER_QUEUE_PACKETS: {
        PLIST_ENTRY List;

        List = va_arg(Arguments, PLIST_ENTRY);

        ReceiverReceivePackets(Adapter->Receiver, List);
        break;
    }
    case XENVIF_MAC_STATE_CHANGE: {
        AdapterMediaStateChange(Adapter);
        break;
    }
    }

    va_end(Arguments);
}

static VOID
AdapterIndicateOffloadChanged(
    IN  PXENNET_ADAPTER         Adapter
    )
{
    NDIS_STATUS_INDICATION      Status;
    NDIS_OFFLOAD                Offload;
    PXENVIF_VIF_OFFLOAD_OPTIONS RxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS TxOptions;

    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);
    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);

    RtlZeroMemory(&Offload, sizeof(NDIS_OFFLOAD));
    Offload.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    Offload.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    Offload.Header.Size = sizeof(NDIS_OFFLOAD);

    Offload.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (RxOptions->OffloadIpVersion4HeaderChecksum) {
        Offload.Checksum.IPv4Receive.IpChecksum = 1;
        Offload.Checksum.IPv4Receive.IpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion4TcpChecksum) {
        Offload.Checksum.IPv4Receive.TcpChecksum = 1;
        Offload.Checksum.IPv4Receive.TcpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion4UdpChecksum) {
        Offload.Checksum.IPv4Receive.UdpChecksum = 1;
    }

    Offload.Checksum.IPv6Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
    Offload.Checksum.IPv6Receive.IpExtensionHeadersSupported = 1;

    if (RxOptions->OffloadIpVersion6TcpChecksum) {
        Offload.Checksum.IPv6Receive.TcpChecksum = 1;
        Offload.Checksum.IPv6Receive.TcpOptionsSupported = 1;
    }
    if (RxOptions->OffloadIpVersion6UdpChecksum) {
        Offload.Checksum.IPv6Receive.UdpChecksum = 1;
    }

    XENVIF_VIF(ReceiverSetOffloadOptions,
               &Adapter->VifInterface,
               *RxOptions);

    Offload.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (TxOptions->OffloadIpVersion4HeaderChecksum) {
        Offload.Checksum.IPv4Transmit.IpChecksum = 1;
        Offload.Checksum.IPv4Transmit.IpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion4TcpChecksum) {
        Offload.Checksum.IPv4Transmit.TcpChecksum = 1;
        Offload.Checksum.IPv4Transmit.TcpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion4UdpChecksum) {
        Offload.Checksum.IPv4Transmit.UdpChecksum = 1;
    }

    Offload.Checksum.IPv6Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
    Offload.Checksum.IPv6Transmit.IpExtensionHeadersSupported = 1;

    if (TxOptions->OffloadIpVersion6TcpChecksum) {
        Offload.Checksum.IPv6Transmit.TcpChecksum = 1;
        Offload.Checksum.IPv6Transmit.TcpOptionsSupported = 1;
    }
    if (TxOptions->OffloadIpVersion6UdpChecksum) {
        Offload.Checksum.IPv6Transmit.UdpChecksum = 1;
    }

    if (TxOptions->OffloadIpVersion4LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   4,
                   &Offload.LsoV2.IPv4.MaxOffLoadSize);
        Offload.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Offload.LsoV2.IPv4.MinSegmentCount = 2;
    }

    if (TxOptions->OffloadIpVersion6LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   6,
                   &Offload.LsoV2.IPv6.MaxOffLoadSize);
        Offload.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Offload.LsoV2.IPv6.MinSegmentCount = 2;
        Offload.LsoV2.IPv6.IpExtensionHeadersSupported = 1;
        Offload.LsoV2.IPv6.TcpOptionsSupported = 1;
    }

    if (!RtlEqualMemory(&Adapter->Offload, &Offload, sizeof(NDIS_OFFLOAD))) {
        Adapter->Offload = Offload;
        // DISPPLAY_OFFLOAD(Offload);
    }

    RtlZeroMemory(&Status, sizeof(NDIS_STATUS_INDICATION));
    Status.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    Status.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    Status.Header.Size = sizeof(NDIS_STATUS_INDICATION);
    Status.StatusCode = NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG;
    Status.StatusBuffer = &Offload;
    Status.StatusBufferSize = sizeof(Offload);

    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &Status);
}

static VOID
AdapterGetPacketFilter(
    IN  PXENNET_ADAPTER         Adapter,
    OUT PULONG                  PacketFilter
    )
{
    XENVIF_MAC_FILTER_LEVEL UnicastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL MulticastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL BroadcastFilterLevel;

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_UNICAST,
               &UnicastFilterLevel);

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_MULTICAST,
               &MulticastFilterLevel);

    XENVIF_VIF(MacQueryFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_BROADCAST,
               &BroadcastFilterLevel);

    *PacketFilter = 0;

    if (UnicastFilterLevel == XENVIF_MAC_FILTER_ALL) {
        ASSERT3U(MulticastFilterLevel, ==, XENVIF_MAC_FILTER_ALL);
        ASSERT3U(BroadcastFilterLevel, ==, XENVIF_MAC_FILTER_ALL);

        *PacketFilter |= NDIS_PACKET_TYPE_PROMISCUOUS;
        return;
    } else if (UnicastFilterLevel == XENVIF_MAC_FILTER_MATCHING) {
        *PacketFilter |= NDIS_PACKET_TYPE_DIRECTED;
    }

    if (MulticastFilterLevel == XENVIF_MAC_FILTER_ALL)
        *PacketFilter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
    else if (MulticastFilterLevel == XENVIF_MAC_FILTER_MATCHING)
        *PacketFilter |= NDIS_PACKET_TYPE_MULTICAST;

    if (BroadcastFilterLevel == XENVIF_MAC_FILTER_ALL)
        *PacketFilter |= NDIS_PACKET_TYPE_BROADCAST;
}

static NDIS_STATUS
AdapterSetPacketFilter(
    IN  PXENNET_ADAPTER         Adapter,
    IN  PULONG                  PacketFilter
    )
{
    XENVIF_MAC_FILTER_LEVEL UnicastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL MulticastFilterLevel;
    XENVIF_MAC_FILTER_LEVEL BroadcastFilterLevel;

    if (*PacketFilter & ~XENNET_SUPPORTED_PACKET_FILTERS)
        return NDIS_STATUS_INVALID_PARAMETER;

    if (*PacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
        UnicastFilterLevel = XENVIF_MAC_FILTER_ALL;
        MulticastFilterLevel = XENVIF_MAC_FILTER_ALL;
        BroadcastFilterLevel = XENVIF_MAC_FILTER_ALL;
        goto done;
    }

    if (*PacketFilter & NDIS_PACKET_TYPE_DIRECTED)
        UnicastFilterLevel = XENVIF_MAC_FILTER_MATCHING;
    else
        UnicastFilterLevel = XENVIF_MAC_FILTER_NONE;

    if (*PacketFilter & NDIS_PACKET_TYPE_ALL_MULTICAST)
        MulticastFilterLevel = XENVIF_MAC_FILTER_ALL;
    else if (*PacketFilter & NDIS_PACKET_TYPE_MULTICAST)
        MulticastFilterLevel = XENVIF_MAC_FILTER_MATCHING;
    else
        MulticastFilterLevel = XENVIF_MAC_FILTER_NONE;

    if (*PacketFilter & NDIS_PACKET_TYPE_BROADCAST)
        BroadcastFilterLevel = XENVIF_MAC_FILTER_ALL;
    else
        BroadcastFilterLevel = XENVIF_MAC_FILTER_NONE;

done:
    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_UNICAST,
               UnicastFilterLevel);

    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_MULTICAST,
               MulticastFilterLevel);

    XENVIF_VIF(MacSetFilterLevel,
               &Adapter->VifInterface,
               ETHERNET_ADDRESS_BROADCAST,
               BroadcastFilterLevel);

    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
AdapterGetOffloadEncapsulation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OFFLOAD_ENCAPSULATION Offload
    )
{
    XENVIF_VIF_OFFLOAD_OPTIONS  Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS TxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS RxOptions;

    if (Offload->IPv4.Enabled == NDIS_OFFLOAD_SET_ON &&
        Offload->IPv4.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
        goto invalid_parameter;

    if (Offload->IPv6.Enabled == NDIS_OFFLOAD_SET_ON &&
        Offload->IPv6.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
        goto invalid_parameter;

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    TxOptions->Value = 0;
    TxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.lsov4 && Options.OffloadIpVersion4LargePacket)
        TxOptions->OffloadIpVersion4LargePacket = 1;
    if (Adapter->Properties.lsov6 && Options.OffloadIpVersion6LargePacket)
        TxOptions->OffloadIpVersion6LargePacket = 1;
    if ((Adapter->Properties.ipv4_csum & 1) && Options.OffloadIpVersion4HeaderChecksum)
        TxOptions->OffloadIpVersion4HeaderChecksum = 1;
    if ((Adapter->Properties.tcpv4_csum & 1) && Options.OffloadIpVersion4TcpChecksum)
        TxOptions->OffloadIpVersion4TcpChecksum = 1;
    if ((Adapter->Properties.udpv4_csum & 1) && Options.OffloadIpVersion4UdpChecksum)
        TxOptions->OffloadIpVersion4UdpChecksum = 1;
    if ((Adapter->Properties.tcpv6_csum & 1) && Options.OffloadIpVersion6TcpChecksum)
        TxOptions->OffloadIpVersion6TcpChecksum = 1;
    if ((Adapter->Properties.udpv6_csum & 1) && Options.OffloadIpVersion6UdpChecksum)
        TxOptions->OffloadIpVersion6UdpChecksum = 1;

    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    RxOptions->Value = 0;
    RxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.need_csum_value)
        RxOptions->NeedChecksumValue = 1;
    if (Adapter->Properties.lrov4)
        RxOptions->OffloadIpVersion4LargePacket = 1;
    if (Adapter->Properties.lrov4)
        RxOptions->NeedLargePacketSplit = 1;
    if (Adapter->Properties.lrov6)
        RxOptions->OffloadIpVersion6LargePacket = 1;
    if (Adapter->Properties.lrov6)
        RxOptions->NeedLargePacketSplit = 1;
    if (Adapter->Properties.ipv4_csum & 2)
        RxOptions->OffloadIpVersion4HeaderChecksum = 1;
    if (Adapter->Properties.tcpv4_csum & 2)
        RxOptions->OffloadIpVersion4TcpChecksum = 1;
    if (Adapter->Properties.udpv4_csum & 2)
        RxOptions->OffloadIpVersion4UdpChecksum = 1;
    if (Adapter->Properties.tcpv6_csum & 2)
        RxOptions->OffloadIpVersion6TcpChecksum = 1;
    if (Adapter->Properties.udpv6_csum & 2)
        RxOptions->OffloadIpVersion6UdpChecksum = 1;

    AdapterIndicateOffloadChanged(Adapter);
    return NDIS_STATUS_SUCCESS;

invalid_parameter:
    return NDIS_STATUS_INVALID_PARAMETER;
}

#define NO_CHANGE(x)    ((x) == NDIS_OFFLOAD_PARAMETERS_NO_CHANGE)
#define RX_ENABLED(x)   ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||            \
                         (x) == NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED)
#define TX_ENABLED(x)   ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||            \
                         (x) == NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED)
#define CHANGE(x, y)    (((x) == (y)) ? 0 : (((x) = (y)), 1))

static NDIS_STATUS
AdapterGetTcpOffloadParameters(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OFFLOAD_PARAMETERS    Offload
    )
{
    XENVIF_VIF_OFFLOAD_OPTIONS      Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS     TxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS     RxOptions;
    BOOLEAN                         Changed;

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    if (!NO_CHANGE(Offload->IPsecV1))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV1))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->TcpConnectionIPv4))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->TcpConnectionIPv6))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV2IPv4) &&
        !(Options.OffloadIpVersion4LargePacket))
        goto invalid_parameter;
    if (!NO_CHANGE(Offload->LsoV2IPv6) &&
        !(Options.OffloadIpVersion6LargePacket))
        goto invalid_parameter;

    Changed = FALSE;
    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    if (Offload->LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion4LargePacket, 1);
    } else if (Offload->LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion4LargePacket, 0);
    }

    if (Offload->LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion6LargePacket, 1);
    } else if (Offload->LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED) {
        Changed |= CHANGE(TxOptions->OffloadIpVersion6LargePacket, 0);
    }

    Changed |= CHANGE(TxOptions->OffloadIpVersion4HeaderChecksum, TX_ENABLED(Offload->IPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion4TcpChecksum, TX_ENABLED(Offload->TCPIPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion4UdpChecksum, TX_ENABLED(Offload->UDPIPv4Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion6TcpChecksum, TX_ENABLED(Offload->TCPIPv6Checksum));
    Changed |= CHANGE(TxOptions->OffloadIpVersion6UdpChecksum, TX_ENABLED(Offload->UDPIPv6Checksum));

    Changed |= CHANGE(RxOptions->OffloadIpVersion4HeaderChecksum, RX_ENABLED(Offload->IPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion4TcpChecksum, RX_ENABLED(Offload->TCPIPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion4UdpChecksum, RX_ENABLED(Offload->UDPIPv4Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion6TcpChecksum, RX_ENABLED(Offload->TCPIPv6Checksum));
    Changed |= CHANGE(RxOptions->OffloadIpVersion6UdpChecksum, RX_ENABLED(Offload->UDPIPv6Checksum));

    if (Changed)
        AdapterIndicateOffloadChanged(Adapter);

    return NDIS_STATUS_SUCCESS;

invalid_parameter:
    return NDIS_STATUS_INVALID_PARAMETER;
}

#undef NO_CHANGE
#undef RX_ENABLED
#undef TX_ENABLED
#undef CHANGE

static NDIS_STATUS
AdapterQueryGeneralStatistics(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_STATISTICS_INFO   Info,
    IN  ULONG               BufferLength,
    IN OUT PULONG           BytesWritten
    )
{
    ULONGLONG   Value;

    if (BufferLength < sizeof(NDIS_STATISTICS_INFO))
        goto fail1;

    RtlZeroMemory(Info, sizeof(NDIS_STATISTICS_INFO));
    Info->Header.Revision = NDIS_OBJECT_REVISION_1;
    Info->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Info->Header.Size = sizeof(NDIS_STATISTICS_INFO);

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BACKEND_ERRORS,
                      &Value);
    Info->ifInErrors = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_FRONTEND_ERRORS,
                      &Value);
    Info->ifInErrors += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_PACKETS_DROPPED,
                      &Value);
    Info->ifInDiscards = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCInOctets = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCInOctets += Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCInOctets += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCInUcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_UNICAST_PACKETS,
                      &Value);
    Info->ifHCInUcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCInMulticastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_MULTICAST_PACKETS,
                      &Value);
    Info->ifHCInMulticastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCInBroadcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_RECEIVER_BROADCAST_PACKETS,
                      &Value);
    Info->ifHCInBroadcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BACKEND_ERRORS,
                      &Value);
    Info->ifOutErrors = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                      &Value);
    Info->ifOutErrors += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets = Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets += Value;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCOutOctets += Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_OCTETS,
                      &Value);
    Info->ifHCOutUcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_UNICAST_PACKETS,
                      &Value);
    Info->ifHCOutUcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                      &Value);
    Info->ifHCOutMulticastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                      &Value);
    Info->ifHCOutMulticastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                      &Value);
    Info->ifHCOutBroadcastOctets = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT;
    (VOID) XENVIF_VIF(QueryStatistic,
                      &Adapter->VifInterface,
                      XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                      &Value);
    Info->ifHCOutBroadcastPkts = Value;

    Info->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS;
    Info->ifOutDiscards = 0;

    *BytesWritten = sizeof(NDIS_STATISTICS_INFO);
    return NDIS_STATUS_SUCCESS;

fail1:
    *BytesWritten = 0;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

static NDIS_STATUS
AdapterQueryMulticastList(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PVOID               Buffer,
    IN  ULONG               BufferLength,
    IN OUT PULONG           BytesNeeded,
    IN OUT PULONG           BytesWritten
    )
{
    ULONG       Count;
    NDIS_STATUS ndisStatus;
    NTSTATUS    status;

    XENVIF_VIF(MacQueryMulticastAddresses,
               &Adapter->VifInterface,
               NULL,
               &Count);
    *BytesNeeded = Count * ETHERNET_ADDRESS_LENGTH;

    ndisStatus = NDIS_STATUS_INVALID_LENGTH;
    if (BufferLength < *BytesNeeded)
        goto fail1;

    status = XENVIF_VIF(MacQueryMulticastAddresses,
                        &Adapter->VifInterface,
                        Buffer,
                        &Count);
    ndisStatus = NDIS_STATUS_FAILURE;
    if (!NT_SUCCESS(status))
        goto fail2;

    *BytesWritten = Count * ETHERNET_ADDRESS_LENGTH;
    return NDIS_STATUS_SUCCESS;

fail2:
fail1:
    *BytesWritten = 0;
    return ndisStatus;
}

static FORCEINLINE NDIS_STATUS
AdapterSetMulticastAddresses(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    NTSTATUS        status;

    status = XENVIF_VIF(MacSetMulticastAddresses,
                        &Adapter->VifInterface,
                        Address,
                        Count);
    if (!NT_SUCCESS(status))
        return NDIS_STATUS_INVALID_DATA;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE VOID
AdapterGetXmitOk(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONGLONG          Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_UNICAST_PACKETS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;
}

static FORCEINLINE VOID
AdapterGetRcvOk(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONGLONG          Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_UNICAST_PACKETS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_MULTICAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_BROADCAST_PACKETS,
                &Value);

    *Buffer += (ULONG)Value;
}

static NDIS_STATUS
AdapterGetXmitError(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONG              Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_BACKEND_ERRORS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                &Value);

    *Buffer += (ULONG)Value;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE NDIS_STATUS
AdapterGetRcvError(
    IN  PXENNET_ADAPTER     Adapter,
    OUT PULONG              Buffer
    )
{
    ULONGLONG   Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_BACKEND_ERRORS,
                &Value);

    *Buffer = (ULONG)Value;

    XENVIF_VIF(QueryStatistic,
                &Adapter->VifInterface,
                XENVIF_RECEIVER_FRONTEND_ERRORS,
                &Value);

    *Buffer += (ULONG)Value;

    return NDIS_STATUS_SUCCESS;
}

static FORCEINLINE NDIS_STATUS
AdapterInterruptModeration(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_INTERRUPT_MODERATION_PARAMETERS   Params,
    IN  ULONG               BufferLength,
    IN OUT PULONG           BytesWritten
    )
{
    UNREFERENCED_PARAMETER(Adapter);

    if (BufferLength < sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS))
        goto fail1;

    Params->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Params->Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
    Params->Header.Size = sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);

    Params->Flags = 0;
    Params->InterruptModeration = NdisInterruptModerationNotSupported;

    *BytesWritten = sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);
    return NDIS_STATUS_SUCCESS;

fail1:
    *BytesWritten = 0;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

NDIS_HANDLE
AdapterGetHandle(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->NdisAdapterHandle;
}

PXENVIF_VIF_INTERFACE
AdapterGetVifInterface(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return &Adapter->VifInterface;
}

PXENBUS_CACHE_INTERFACE
AdapterGetCacheInterface(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return &Adapter->CacheInterface;
}

PXENNET_TRANSMITTER
AdapterGetTransmitter(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->Transmitter;
}

PXENNET_RECEIVER
AdapterGetReceiver(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    return Adapter->Receiver;
}

NDIS_STATUS
AdapterEnable(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    NTSTATUS        status;

    if (Adapter->Enabled)
        return NDIS_STATUS_SUCCESS;

    status = XENVIF_VIF(Enable,
                        &Adapter->VifInterface,
                        AdapterVifCallback,
                        Adapter);
    if (!NT_SUCCESS(status))
        goto fail1;

    Adapter->Enabled = TRUE;

    return NDIS_STATUS_SUCCESS;

fail1:
    return NDIS_STATUS_FAILURE;
}

BOOLEAN
AdapterDisable(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    if (!Adapter->Enabled)
        return FALSE;

    XENVIF_VIF(Disable,
               &Adapter->VifInterface);

    AdapterMediaStateChange(Adapter);

    Adapter->Enabled = FALSE;

    return TRUE;
}

VOID
AdapterMediaStateChange(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    NDIS_LINK_STATE         LinkState;
    NDIS_STATUS_INDICATION  StatusIndication;

    RtlZeroMemory(&LinkState, sizeof (NDIS_LINK_STATE));
    LinkState.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    LinkState.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    LinkState.Header.Size = sizeof(NDIS_LINK_STATE);

    XENVIF_VIF(MacQueryState,
               &Adapter->VifInterface,
               &LinkState.MediaConnectState,
               &LinkState.RcvLinkSpeed,
               &LinkState.MediaDuplexState);

    if (LinkState.MediaConnectState == MediaConnectStateUnknown) {
        Info("LINK: STATE UNKNOWN\n");
    } else if (LinkState.MediaConnectState == MediaConnectStateDisconnected) {
        Info("LINK: DOWN\n");
    } else {
        ASSERT3U(LinkState.MediaConnectState, ==, MediaConnectStateConnected);

        if (LinkState.MediaDuplexState == MediaDuplexStateHalf)
            Info("LINK: UP: SPEED=%u DUPLEX=HALF\n", LinkState.RcvLinkSpeed);
        else if (LinkState.MediaDuplexState == MediaDuplexStateFull)
            Info("LINK: UP: SPEED=%u DUPLEX=FULL\n", LinkState.RcvLinkSpeed);
        else
            Info("LINK: UP: SPEED=%u DUPLEX=UNKNOWN\n", LinkState.RcvLinkSpeed);
    }

    LinkState.XmitLinkSpeed = LinkState.RcvLinkSpeed;

    RtlZeroMemory(&StatusIndication, sizeof (NDIS_STATUS_INDICATION));
    StatusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    StatusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    StatusIndication.Header.Size = sizeof (NDIS_STATUS_INDICATION);

    StatusIndication.SourceHandle = Adapter->NdisAdapterHandle;
    StatusIndication.StatusCode = NDIS_STATUS_LINK_STATE;
    StatusIndication.StatusBuffer = &LinkState;
    StatusIndication.StatusBufferSize = sizeof (NDIS_LINK_STATE);

    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &StatusIndication);
}

NDIS_STATUS
AdapterSetInformation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OID_REQUEST   Request
    )
{
    PVOID           Buffer;
    ULONG           BufferLength;
    ULONG           BytesNeeded;
    ULONG           BytesRead;
    NDIS_STATUS     ndisStatus;

    Buffer = Request->DATA.SET_INFORMATION.InformationBuffer;
    BufferLength = Request->DATA.SET_INFORMATION.InformationBufferLength;
    BytesNeeded = BytesRead = 0;
    ndisStatus = NDIS_STATUS_SUCCESS;

    switch (Request->DATA.SET_INFORMATION.Oid) {
    case OID_PNP_SET_POWER:
        BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
        // do nothing
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
        BytesNeeded = sizeof(ULONG);
        Adapter->CurrentLookahead = Adapter->MaximumFrameSize;
        if (BufferLength == BytesNeeded) {
            Adapter->CurrentLookahead = *(PULONG)Buffer;
            BytesRead = sizeof(ULONG);
        }
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        BytesNeeded = sizeof(ULONG);
        if (BufferLength == BytesNeeded) {
            ndisStatus = AdapterSetPacketFilter(Adapter,
                                                (PULONG)Buffer);
            BytesRead = sizeof(ULONG);
        }
        break;

    case OID_802_3_MULTICAST_LIST:
        BytesNeeded = ETHERNET_ADDRESS_LENGTH;
        if (BufferLength % ETHERNET_ADDRESS_LENGTH == 0) {
            ndisStatus = AdapterSetMulticastAddresses(Adapter,
                                                      Buffer,
                                                      BufferLength / ETHERNET_ADDRESS_LENGTH);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = BufferLength;
        } else {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
        }
        break;

    case OID_OFFLOAD_ENCAPSULATION:
        BytesNeeded = sizeof(NDIS_OFFLOAD_ENCAPSULATION);
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetOffloadEncapsulation(Adapter,
                                                        (PNDIS_OFFLOAD_ENCAPSULATION)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = sizeof(NDIS_OFFLOAD_ENCAPSULATION);
        }
        break;

    case OID_TCP_OFFLOAD_PARAMETERS:
        BytesNeeded = sizeof(NDIS_OFFLOAD_PARAMETERS);
        if (BufferLength >= BytesNeeded) {
            ndisStatus = AdapterGetTcpOffloadParameters(Adapter,
                                                        (PNDIS_OFFLOAD_PARAMETERS)Buffer);
            if (ndisStatus == NDIS_STATUS_SUCCESS)
                BytesRead = sizeof(NDIS_OFFLOAD_PARAMETERS);
        }
        break;

    case OID_GEN_INTERRUPT_MODERATION:
    case OID_GEN_MACHINE_NAME:
    default:
        ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    Request->DATA.SET_INFORMATION.BytesNeeded = BytesNeeded;
    if (ndisStatus == NDIS_STATUS_SUCCESS)
        Request->DATA.SET_INFORMATION.BytesRead = BytesRead;

    return ndisStatus;
}

static FORCEINLINE NDIS_STATUS
__CopyBuffer(
    IN  PVOID               Buffer,
    IN  ULONG               BufferLength,
    IN  PVOID               Source,
    IN  ULONG               SourceLength
    )
{
    if (BufferLength >= SourceLength) {
        RtlCopyMemory(Buffer, Source, SourceLength);
        return NDIS_STATUS_SUCCESS;
    }

    RtlCopyMemory(Buffer, Source, BufferLength);
    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

static FORCEINLINE NDIS_STATUS
__SetUlong(
    IN  PVOID               Buffer,
    IN  ULONG               BufferLength,
    IN  ULONG               Source,
    IN OUT PULONG           SourceLength
    )
{
    *SourceLength = sizeof(ULONG);

    if (BufferLength >= sizeof(ULONG)) {
        *(PULONG)Buffer = (ULONG)Source;
        return NDIS_STATUS_SUCCESS;
    }

    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

static FORCEINLINE NDIS_STATUS
__SetUlong64(
    IN  PVOID               Buffer,
    IN  ULONG               BufferLength,
    IN  ULONGLONG           Source,
    IN OUT PULONG           SourceLength
    )
{
    *SourceLength = sizeof(ULONGLONG);

    if (BufferLength >= sizeof(ULONGLONG)) {
        *(PULONGLONG)Buffer = Source;
        return NDIS_STATUS_SUCCESS;
    }

    if (BufferLength >= sizeof(ULONG)) {
        *(PULONG)Buffer = (ULONG)Source;
        *SourceLength = sizeof(ULONG);
        return NDIS_STATUS_SUCCESS;
    }

    return NDIS_STATUS_BUFFER_TOO_SHORT;
}

NDIS_STATUS
AdapterQueryInformation(
    IN  PXENNET_ADAPTER     Adapter,
    IN  PNDIS_OID_REQUEST   Request
    )
{
    PVOID           Buffer;
    ULONG           BufferLength;
    ULONG           BytesNeeded;
    ULONG           BytesWritten;
    ULONG           Value32;
    ULONGLONG       Value64;
    ETHERNET_ADDRESS    EthernetAddress;
    NDIS_STATUS     ndisStatus;

    Buffer = Request->DATA.QUERY_INFORMATION.InformationBuffer;
    BufferLength = Request->DATA.QUERY_INFORMATION.InformationBufferLength;
    BytesNeeded = BytesWritten = sizeof(ULONG);
    ndisStatus = NDIS_STATUS_SUCCESS;

    switch (Request->DATA.QUERY_INFORMATION.Oid) {
    case OID_PNP_CAPABILITIES:
        BytesNeeded = BytesWritten = sizeof(Adapter->Capabilities);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &Adapter->Capabilities,
                                  BytesWritten);
        break;

    case OID_PNP_QUERY_POWER:
        BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
        BytesWritten = 0;
        // do nothing
        break;

    case OID_GEN_SUPPORTED_LIST:
        BytesNeeded = BytesWritten = sizeof(XennetSupportedOids);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &XennetSupportedOids[0],
                                  BytesWritten);
        break;

    case OID_GEN_HARDWARE_STATUS:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                NdisHardwareStatusReady,
                                &BytesWritten);
        break;

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                XENNET_MEDIA_TYPE,
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize,
                                &BytesWritten);
        break;

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
    case OID_GEN_RECEIVE_BUFFER_SPACE:
        XENVIF_VIF(TransmitterQueryRingSize,
                    &Adapter->VifInterface,
                    (PULONG)&Value32);
        Value32 *= Adapter->MaximumFrameSize;
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_VENDOR_DESCRIPTION:
        BytesNeeded = BytesWritten = (ULONG)strlen(COMPANY_NAME_STR) + 1;
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  COMPANY_NAME_STR,
                                  BytesWritten);
        break;

    case OID_GEN_VENDOR_DRIVER_VERSION:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                ((MAJOR_VERSION << 8) | MINOR_VERSION) << 8,
                                &BytesWritten);
        break;

    case OID_GEN_DRIVER_VERSION:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (6 << 8) | 0, // NDIS 6.0
                                &BytesWritten);
        break;

    case OID_GEN_MAC_OPTIONS:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                XENNET_MAC_OPTIONS,
                                &BytesWritten);
        break;

    case OID_GEN_STATISTICS:
        BytesNeeded = BytesWritten = sizeof(NDIS_STATISTICS_INFO);
        ndisStatus = AdapterQueryGeneralStatistics(Adapter,
                                                   (PNDIS_STATISTICS_INFO)Buffer,
                                                   BufferLength,
                                                   &BytesWritten);
        break;

    case OID_802_3_MULTICAST_LIST:
        ndisStatus = AdapterQueryMulticastList(Adapter,
                                               Buffer,
                                               BufferLength,
                                               &BytesNeeded,
                                               &BytesWritten);
        break;

    case OID_802_3_PERMANENT_ADDRESS:
        XENVIF_VIF(MacQueryPermanentAddress,
                    &Adapter->VifInterface,
                    &EthernetAddress);
        BytesNeeded = BytesWritten = sizeof(ETHERNET_ADDRESS);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &EthernetAddress,
                                  BytesWritten);
        break;

    case OID_802_3_CURRENT_ADDRESS:
        XENVIF_VIF(MacQueryCurrentAddress,
                    &Adapter->VifInterface,
                    &EthernetAddress);
        BytesNeeded = BytesWritten = sizeof(ETHERNET_ADDRESS);
        ndisStatus = __CopyBuffer(Buffer,
                                  BufferLength,
                                  &EthernetAddress,
                                  BytesWritten);
        break;

    case OID_GEN_MAXIMUM_FRAME_SIZE:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize -
                                    sizeof(ETHERNET_TAGGED_HEADER),
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_TOTAL_SIZE:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->MaximumFrameSize -
                                    sizeof(ETHERNET_TAGGED_HEADER) +
                                    sizeof (ETHERNET_UNTAGGED_HEADER),
                                &BytesWritten);
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Adapter->CurrentLookahead,
                                &BytesWritten);
        break;

    case OID_GEN_VENDOR_ID:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                0x5853,
                                &BytesWritten);
        break;

    case OID_GEN_LINK_SPEED:
        XENVIF_VIF(MacQueryState,
                   &Adapter->VifInterface,
                   NULL,
                   &Value64,
                   NULL);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)(Value64 / 100),
                                &BytesWritten);
        break;

    case OID_GEN_MEDIA_CONNECT_STATUS:
        XENVIF_VIF(MacQueryState,
                    &Adapter->VifInterface,
                    (PNET_IF_MEDIA_CONNECT_STATE)&Value32,
                    NULL,
                    NULL);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_MAXIMUM_SEND_PACKETS:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                16,
                                &BytesWritten);
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        AdapterGetPacketFilter(Adapter, &Value32);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_XMIT_OK:
        AdapterGetXmitOk(Adapter, &Value64);
        ndisStatus = __SetUlong64(Buffer,
                                  BufferLength,
                                  Value64,
                                  &BytesWritten);
        break;

    case OID_GEN_RCV_OK:
        AdapterGetRcvOk(Adapter, &Value64);
        ndisStatus = __SetUlong64(Buffer,
                                  BufferLength,
                                  Value64,
                                  &BytesWritten);
        break;

    case OID_GEN_XMIT_ERROR:
        AdapterGetXmitError(Adapter, &Value32);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_RCV_ERROR:
        AdapterGetRcvError(Adapter, &Value32);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                Value32,
                                &BytesWritten);
        break;

    case OID_GEN_RCV_NO_BUFFER:
    case OID_GEN_TRANSMIT_QUEUE_LENGTH:
    case OID_GEN_RCV_CRC_ERROR:
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                0,
                                &BytesWritten);
        break;

    case OID_802_3_MAXIMUM_LIST_SIZE:
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                32,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_UNICAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_UNICAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_BYTES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_FRAMES_XMIT:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_UNICAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_DIRECTED_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_UNICAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_MULTICAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_MULTICAST_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_MULTICAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_BYTES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_BROADCAST_OCTETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_BROADCAST_FRAMES_RCV:
        XENVIF_VIF(QueryStatistic,
                   &Adapter->VifInterface,
                   XENVIF_RECEIVER_BROADCAST_PACKETS,
                   &Value64);
        ndisStatus = __SetUlong(Buffer,
                                BufferLength,
                                (ULONG)Value64,
                                &BytesWritten);
        break;

    case OID_GEN_INTERRUPT_MODERATION:
        BytesNeeded = sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);
        ndisStatus = AdapterInterruptModeration(Adapter,
                                                (PNDIS_INTERRUPT_MODERATION_PARAMETERS)Buffer,
                                                BufferLength,
                                                &BytesWritten);
        break;

    case OID_IP4_OFFLOAD_STATS:
    case OID_IP6_OFFLOAD_STATS:
    case OID_GEN_SUPPORTED_GUIDS:

        // We don't handle these since NDIS 6.0 is supposed to do this for us
    case OID_GEN_MAC_ADDRESS:
    case OID_GEN_MAX_LINK_SPEED:

        // ignore these common unwanted OIDs
	case OID_GEN_INIT_TIME_MS:
	case OID_GEN_RESET_COUNTS:
	case OID_GEN_MEDIA_SENSE_COUNTS:

    default:
        ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
        BytesNeeded = 0;
        break;
    }

    Request->DATA.QUERY_INFORMATION.BytesWritten = BytesWritten;
    Request->DATA.QUERY_INFORMATION.BytesNeeded = BytesNeeded;

    return ndisStatus;
}

static NTSTATUS
__QueryInterface(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  const GUID      *Guid,
    IN  ULONG           Version,
    OUT PINTERFACE      Interface,
    IN  ULONG           Size,
    IN  BOOLEAN         Optional
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       DeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = Guid;
    StackLocation->Parameters.QueryInterface.Size = (USHORT)Size;
    StackLocation->Parameters.QueryInterface.Version = (USHORT)Version;
    StackLocation->Parameters.QueryInterface.Interface = Interface;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_NOT_SUPPORTED && Optional)
            goto done;

        goto fail2;
    }

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#pragma prefast(push)
#pragma prefast(disable:6102)

#define READ_PROPERTY(field, name, defaultval, handle)  \
    do {                                                \
        NDIS_STATUS                     _Status;        \
        NDIS_STRING                     _Value;         \
        PNDIS_CONFIGURATION_PARAMETER   _Data;          \
        RtlInitUnicodeString(&_Value, name);            \
        NdisReadConfiguration(&_Status, &_Data, handle, \
                        &_Value, NdisParameterInteger); \
        if (_Status == NDIS_STATUS_SUCCESS)             \
            field = _Data->ParameterData.IntegerData;   \
        else                                            \
            field = defaultval;                         \
    } while (FALSE);

static NDIS_STATUS
AdapterGetAdvancedSettings(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_CONFIGURATION_OBJECT   Config;
    NDIS_HANDLE                 Handle;
    NDIS_STATUS                 ndisStatus;

    RtlZeroMemory(&Config, sizeof(NDIS_CONFIGURATION_OBJECT));
    Config.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    Config.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    Config.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    Config.NdisHandle = Adapter->NdisAdapterHandle;
    Config.Flags = 0;

    ndisStatus = NdisOpenConfigurationEx(&Config, &Handle);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail1;

    READ_PROPERTY(Adapter->Properties.ipv4_csum, L"*IPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.tcpv4_csum, L"*TCPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.udpv4_csum, L"*UDPChecksumOffloadIPv4", 3, Handle);
    READ_PROPERTY(Adapter->Properties.tcpv6_csum, L"*TCPChecksumOffloadIPv6", 3, Handle);
    READ_PROPERTY(Adapter->Properties.udpv6_csum, L"*UDPChecksumOffloadIPv6", 3, Handle);
    READ_PROPERTY(Adapter->Properties.lsov4, L"*LSOv2IPv4", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lsov6, L"*LSOv2IPv6", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lrov4, L"LROIPv4", 1, Handle);
    READ_PROPERTY(Adapter->Properties.lrov6, L"LROIPv6", 1, Handle);
    READ_PROPERTY(Adapter->Properties.need_csum_value, L"NeedChecksumValue", 1, Handle);

    NdisCloseConfiguration(Handle);

    return NDIS_STATUS_SUCCESS;

fail1:
    return NDIS_STATUS_FAILURE;
}

#undef READ_PROPERTY

#pragma prefast(pop)

static NDIS_STATUS
AdapterSetRegistrationAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES   Attribs;
    NDIS_STATUS                                     ndisStatus;

    RtlZeroMemory(&Attribs, sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES);
    Attribs.MiniportAdapterContext = (NDIS_HANDLE)Adapter;
    Attribs.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER |
                             NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;
    Attribs.CheckForHangTimeInSeconds = 0;
    Attribs.InterfaceType = XENNET_INTERFACE_TYPE;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);

    return ndisStatus;
}

static NDIS_STATUS
AdapterSetGeneralAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES    Attribs;
    NDIS_STATUS                                 ndisStatus;

    RtlZeroMemory(&Attribs, sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES);
    Attribs.MediaType = XENNET_MEDIA_TYPE;

    XENVIF_VIF(MacQueryMaximumFrameSize,
               &Adapter->VifInterface,
               (PULONG)&Adapter->MaximumFrameSize);

    Attribs.MtuSize = Adapter->MaximumFrameSize - sizeof (ETHERNET_TAGGED_HEADER);
    Attribs.MaxXmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.MaxRcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.XmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.RcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    Attribs.MediaConnectState = MediaConnectStateConnected;
    Attribs.MediaDuplexState = MediaDuplexStateFull;
    Attribs.LookaheadSize = Adapter->MaximumFrameSize;
    Attribs.PowerManagementCapabilities = &Adapter->Capabilities;
    Attribs.MacOptions = XENNET_MAC_OPTIONS;
    Attribs.SupportedPacketFilters = XENNET_SUPPORTED_PACKET_FILTERS;
    Attribs.MaxMulticastListSize = 32;
    Attribs.MacAddressLength = ETHERNET_ADDRESS_LENGTH;

    XENVIF_VIF(MacQueryPermanentAddress,
               &Adapter->VifInterface,
               (PETHERNET_ADDRESS)&Attribs.PermanentMacAddress);
    XENVIF_VIF(MacQueryCurrentAddress,
               &Adapter->VifInterface,
               (PETHERNET_ADDRESS)&Attribs.CurrentMacAddress);

    Attribs.PhysicalMediumType = NdisPhysicalMedium802_3;
    Attribs.RecvScaleCapabilities = NULL;
    Attribs.AccessType = NET_IF_ACCESS_BROADCAST;
    Attribs.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    Attribs.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    Attribs.IfType = IF_TYPE_ETHERNET_CSMACD;
    Attribs.IfConnectorPresent = TRUE;
    Attribs.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
                                  NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED |
                                  NDIS_STATISTICS_RCV_OK_SUPPORTED |
                                  NDIS_STATISTICS_RCV_ERROR_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED |
                                  NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED;
                      
    Attribs.SupportedOidList = XennetSupportedOids;
    Attribs.SupportedOidListLength = sizeof(XennetSupportedOids);

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);

    return ndisStatus;
}

static NDIS_STATUS
AdapterSetOffloadAttributes(
    IN  PXENNET_ADAPTER Adapter
    )
{
    NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES    Attribs;
    XENVIF_VIF_OFFLOAD_OPTIONS                  Options;
    PXENVIF_VIF_OFFLOAD_OPTIONS                 RxOptions;
    PXENVIF_VIF_OFFLOAD_OPTIONS                 TxOptions;
    NDIS_OFFLOAD                                Default;
    NDIS_OFFLOAD                                Supported;
    NDIS_STATUS                                 ndisStatus;

    TxOptions = TransmitterOffloadOptions(Adapter->Transmitter);
    RxOptions = ReceiverOffloadOptions(Adapter->Receiver);

    TxOptions->Value = 0;
    TxOptions->OffloadTagManipulation = 1;

    RxOptions->Value = 0;
    RxOptions->OffloadTagManipulation = 1;

    if (Adapter->Properties.need_csum_value)
        RxOptions->NeedChecksumValue = 1;

    if (Adapter->Properties.lrov4) {
        RxOptions->OffloadIpVersion4LargePacket = 1;
        RxOptions->NeedLargePacketSplit = 1;
    }

    if (Adapter->Properties.lrov6) {
        RxOptions->OffloadIpVersion6LargePacket = 1;
        RxOptions->NeedLargePacketSplit = 1;
    }

    XENVIF_VIF(ReceiverSetOffloadOptions,
               &Adapter->VifInterface,
               *RxOptions);

    XENVIF_VIF(TransmitterQueryOffloadOptions,
               &Adapter->VifInterface,
               &Options);

    RtlZeroMemory(&Supported, sizeof(NDIS_OFFLOAD));
    Supported.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    Supported.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    Supported.Header.Size = sizeof(NDIS_OFFLOAD);

    Supported.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv4Receive.IpChecksum = 1;
    Supported.Checksum.IPv4Receive.IpOptionsSupported = 1;

    Supported.Checksum.IPv4Receive.TcpChecksum = 1;
    Supported.Checksum.IPv4Receive.TcpOptionsSupported = 1;

    Supported.Checksum.IPv4Receive.UdpChecksum = 1;

    Supported.Checksum.IPv6Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv6Receive.IpExtensionHeadersSupported = 1;

    Supported.Checksum.IPv6Receive.TcpChecksum = 1;
    Supported.Checksum.IPv6Receive.TcpOptionsSupported = 1;

    Supported.Checksum.IPv6Receive.UdpChecksum = 1;

    Supported.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Options.OffloadIpVersion4HeaderChecksum) {
        Supported.Checksum.IPv4Transmit.IpChecksum = 1;
        Supported.Checksum.IPv4Transmit.IpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion4TcpChecksum) {
        Supported.Checksum.IPv4Transmit.TcpChecksum = 1;
        Supported.Checksum.IPv4Transmit.TcpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion4UdpChecksum)
        Supported.Checksum.IPv4Transmit.UdpChecksum = 1;

    Supported.Checksum.IPv6Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    Supported.Checksum.IPv6Transmit.IpExtensionHeadersSupported = 1;

    if (Options.OffloadIpVersion6TcpChecksum) {
        Supported.Checksum.IPv6Transmit.TcpChecksum = 1;
        Supported.Checksum.IPv6Transmit.TcpOptionsSupported = 1;
    }

    if (Options.OffloadIpVersion6UdpChecksum)
        Supported.Checksum.IPv6Transmit.UdpChecksum = 1;

    if (Options.OffloadIpVersion4LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   4,
                   &Supported.LsoV2.IPv4.MaxOffLoadSize);
        Supported.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Supported.LsoV2.IPv4.MinSegmentCount = 2;
    }

    if (Options.OffloadIpVersion6LargePacket) {
        XENVIF_VIF(TransmitterQueryLargePacketSize,
                   &Adapter->VifInterface,
                   6,
                   &Supported.LsoV2.IPv6.MaxOffLoadSize);
        Supported.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        Supported.LsoV2.IPv6.MinSegmentCount = 2;
        Supported.LsoV2.IPv6.IpExtensionHeadersSupported = 1;
        Supported.LsoV2.IPv6.TcpOptionsSupported = 1;
    }

    Default = Supported;

    if (!(Adapter->Properties.ipv4_csum & 2))
        Default.Checksum.IPv4Receive.IpChecksum = 0;

    if (!(Adapter->Properties.tcpv4_csum & 2))
        Default.Checksum.IPv4Receive.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv4_csum & 2))
        Default.Checksum.IPv4Receive.UdpChecksum = 0;

    if (!(Adapter->Properties.tcpv6_csum & 2))
        Default.Checksum.IPv6Receive.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv6_csum & 2))
        Default.Checksum.IPv6Receive.UdpChecksum = 0;

    if (!(Adapter->Properties.ipv4_csum & 1))
        Default.Checksum.IPv4Transmit.IpChecksum = 0;

    if (!(Adapter->Properties.tcpv4_csum & 1))
        Default.Checksum.IPv4Transmit.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv4_csum & 1))
        Default.Checksum.IPv4Transmit.UdpChecksum = 0;

    if (!(Adapter->Properties.tcpv6_csum & 1))
        Default.Checksum.IPv6Transmit.TcpChecksum = 0;

    if (!(Adapter->Properties.udpv6_csum & 1))
        Default.Checksum.IPv6Transmit.UdpChecksum = 0;

    if (!(Adapter->Properties.lsov4)) {
        Default.LsoV2.IPv4.MaxOffLoadSize = 0;
        Default.LsoV2.IPv4.MinSegmentCount = 0;
    }

    if (!(Adapter->Properties.lsov6)) {
        Default.LsoV2.IPv6.MaxOffLoadSize = 0;
        Default.LsoV2.IPv6.MinSegmentCount = 0;
    }

    if (!RtlEqualMemory(&Adapter->Offload, &Default, sizeof (NDIS_OFFLOAD))) {
        Adapter->Offload = Default;
        //DISPLAY_OFFLOAD(Default);
    }

    RtlZeroMemory(&Attribs, sizeof(NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES));
    Attribs.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;
    Attribs.Header.Revision = NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    Attribs.Header.Size = sizeof(Attribs);
    Attribs.DefaultOffloadConfiguration = &Default;
    Attribs.HardwareOffloadCapabilities = &Supported;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&Attribs);
    return ndisStatus;
}

NDIS_STATUS
AdapterInitialize(
    IN  NDIS_HANDLE         Handle,
    OUT PXENNET_ADAPTER     *Adapter
    )
{
    NDIS_STATUS             ndisStatus;
    NTSTATUS                status;
    PDEVICE_OBJECT          DeviceObject;
    NDIS_SG_DMA_DESCRIPTION Dma;

    *Adapter = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(XENNET_ADAPTER),
                                     ADAPTER_POOL_TAG);

    ndisStatus = NDIS_STATUS_RESOURCES;
    if (*Adapter == NULL)
        goto fail1;

    RtlZeroMemory(*Adapter, sizeof (XENNET_ADAPTER));

    NdisMGetDeviceProperty(Handle,
                           &DeviceObject,
                           NULL,
                           NULL,
                           NULL,
                           NULL);

    status = __QueryInterface(DeviceObject,
                              &GUID_XENVIF_VIF_INTERFACE,
                              XENVIF_VIF_INTERFACE_VERSION_MAX,
                              (PINTERFACE)&(*Adapter)->VifInterface,
                              sizeof(XENVIF_VIF_INTERFACE),
                              FALSE);

    ndisStatus = NDIS_STATUS_FAILURE;
    if (!NT_SUCCESS(status))
        goto fail2;

    status = __QueryInterface(DeviceObject,
                              &GUID_XENBUS_CACHE_INTERFACE,
                              XENBUS_CACHE_INTERFACE_VERSION_MAX,
                              (PINTERFACE)&(*Adapter)->CacheInterface,
                              sizeof(XENBUS_CACHE_INTERFACE),
                              FALSE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENVIF_VIF(Acquire,
                        &(*Adapter)->VifInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_CACHE(Acquire,
                          &(*Adapter)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    (*Adapter)->NdisAdapterHandle = Handle;

    ndisStatus = TransmitterInitialize(*Adapter, &(*Adapter)->Transmitter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail6;

    ndisStatus = ReceiverInitialize(*Adapter, &(*Adapter)->Receiver);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail7;

    ndisStatus = AdapterGetAdvancedSettings(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail8;

    ndisStatus = AdapterSetRegistrationAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail9;

    ndisStatus = AdapterSetGeneralAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail10;

    ndisStatus = AdapterSetOffloadAttributes(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail11;

    RtlZeroMemory(&Dma, sizeof(NDIS_SG_DMA_DESCRIPTION));
    Dma.Header.Type = NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION;
    Dma.Header.Revision = NDIS_SG_DMA_DESCRIPTION_REVISION_1;
    Dma.Header.Size = sizeof(NDIS_SG_DMA_DESCRIPTION);
    Dma.Flags = NDIS_SG_DMA_64_BIT_ADDRESS;
    Dma.MaximumPhysicalMapping = 65536;
    Dma.ProcessSGListHandler = AdapterProcessSGList;
    Dma.SharedMemAllocateCompleteHandler = AdapterAllocateComplete;

    ndisStatus = NdisMRegisterScatterGatherDma((*Adapter)->NdisAdapterHandle,
                                               &Dma,
                                               &(*Adapter)->NdisDmaHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        (*Adapter)->NdisDmaHandle = NULL;

    ndisStatus = AdapterEnable(*Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail12;

    return NDIS_STATUS_SUCCESS;

fail12:
    if ((*Adapter)->NdisDmaHandle)
        NdisMDeregisterScatterGatherDma((*Adapter)->NdisDmaHandle);
    (*Adapter)->NdisDmaHandle = NULL;
fail11:
fail10:
fail9:
fail8:
    ReceiverTeardown((*Adapter)->Receiver);
    (*Adapter)->Receiver = NULL;
fail7:
    TransmitterTeardown((*Adapter)->Transmitter);
    (*Adapter)->Transmitter = NULL;
fail6:
    (*Adapter)->NdisAdapterHandle = NULL;

    XENBUS_CACHE(Release, &(*Adapter)->CacheInterface);
fail5:
    XENVIF_VIF(Release, &(*Adapter)->VifInterface);
fail4:
    RtlZeroMemory(&(*Adapter)->CacheInterface, sizeof(XENBUS_CACHE_INTERFACE));
fail3:
    RtlZeroMemory(&(*Adapter)->VifInterface, sizeof(XENVIF_VIF_INTERFACE));
fail2:
    ExFreePoolWithTag(*Adapter, ADAPTER_POOL_TAG);
fail1:
    return ndisStatus;
}

VOID
AdapterTeardown(
    IN  PXENNET_ADAPTER     Adapter
    )
{
    TransmitterTeardown(Adapter->Transmitter);
    Adapter->Transmitter = NULL;

    ReceiverTeardown(Adapter->Receiver);
    Adapter->Receiver = NULL;

    if (Adapter->NdisDmaHandle != NULL)
        NdisMDeregisterScatterGatherDma(Adapter->NdisDmaHandle);
    Adapter->NdisDmaHandle = NULL;

    XENBUS_CACHE(Release, &Adapter->CacheInterface);
    RtlZeroMemory(&Adapter->CacheInterface, sizeof(XENBUS_CACHE_INTERFACE));

    XENVIF_VIF(Release, &Adapter->VifInterface);
    RtlZeroMemory(&Adapter->VifInterface, sizeof(XENVIF_VIF_INTERFACE));

    ExFreePoolWithTag(Adapter, ADAPTER_POOL_TAG);
}
