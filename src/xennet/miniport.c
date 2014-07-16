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

#define INITGUID 1

#include "common.h"
#include "registry.h"

#pragma warning( disable : 4098 )

extern NTSTATUS AllocAdapter(PADAPTER *Adapter);

#define SERVICES_KEY        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"

static FORCEINLINE NTSTATUS
__QueryInterface(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  const WCHAR     *ProviderName,
    IN  const CHAR      *InterfaceName,
    IN  const GUID      *Guid,
    IN  ULONG           Version,
    OUT PINTERFACE      Interface,
    IN  ULONG           Size,
    IN  BOOLEAN         Optional
    )
{
    UNICODE_STRING      Unicode;
    HANDLE              InterfacesKey;
    HANDLE              SubscriberKey;
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Unicode.MaximumLength = (USHORT)((wcslen(SERVICES_KEY) +
                                      1 +
                                      wcslen(ProviderName) +
                                      1 +
                                      wcslen(L"Interfaces") +
                                      1) * sizeof (WCHAR));

    Unicode.Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                           Unicode.MaximumLength,
                                           'TEN');

    status = STATUS_NO_MEMORY;
    if (Unicode.Buffer == NULL)
        goto fail1;

    status = RtlStringCbPrintfW(Unicode.Buffer,
                                Unicode.MaximumLength,
                                SERVICES_KEY L"\\%ws\\Interfaces",
                                ProviderName);
    ASSERT(NT_SUCCESS(status));

    Unicode.Length = (USHORT)(wcslen(Unicode.Buffer) * sizeof (WCHAR));

    status = RegistryOpenKey(NULL, &Unicode, KEY_READ, &InterfacesKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryCreateSubKey(InterfacesKey, 
                                  "XENNET", 
                                  REG_OPTION_NON_VOLATILE, 
                                  &SubscriberKey);
    if (!NT_SUCCESS(status))
        goto fail3;
                   
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
        goto fail4;

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

        goto fail5;
    }

    status = RegistryUpdateDwordValue(SubscriberKey,
                                      (PCHAR)InterfaceName,
                                      Version);
    if (!NT_SUCCESS(status))
        goto fail6;

done:
    RegistryCloseKey(SubscriberKey);

    RegistryCloseKey(InterfacesKey);

    ExFreePool(Unicode.Buffer);

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    RegistryCloseKey(SubscriberKey);

fail3:
    Error("fail3\n");

    RegistryCloseKey(InterfacesKey);

fail2:
    Error("fail2\n");

    ExFreePool(Unicode.Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define QUERY_INTERFACE(                                                                \
    _DeviceObject,                                                                      \
    _ProviderName,                                                                      \
    _InterfaceName,                                                                     \
    _Version,                                                                           \
    _Interface,                                                                         \
    _Size,                                                                              \
    _Optional)                                                                          \
    __QueryInterface((_DeviceObject),                                                   \
                     L ## #_ProviderName,                                               \
                     #_InterfaceName,                                                   \
                     &GUID_ ## _ProviderName ## _ ## _InterfaceName ## _INTERFACE,      \
                     (_Version),                                                        \
                     (_Interface),                                                      \
                     (_Size),                                                           \
                     (_Optional))

NDIS_STATUS 
MiniportInitialize (
    IN  NDIS_HANDLE                        MiniportAdapterHandle,
    IN  NDIS_HANDLE                        MiniportDriverContext,
    IN  PNDIS_MINIPORT_INIT_PARAMETERS     MiniportInitParameters
    )
{
    PADAPTER Adapter = NULL;
    NDIS_STATUS ndisStatus;
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);

    Trace("====>\n");

    status = AllocAdapter(&Adapter);

    if (!NT_SUCCESS(status) || Adapter == NULL) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto fail1;
    }

    RtlZeroMemory(Adapter, sizeof (ADAPTER));

    DeviceObject = NULL;
    NdisMGetDeviceProperty(MiniportAdapterHandle,
                           &DeviceObject,
                           NULL,
                           NULL,
                           NULL,
                           NULL);

    status = QUERY_INTERFACE(DeviceObject,
                             XENVIF,
                             VIF,
                             XENVIF_VIF_INTERFACE_VERSION_MAX,
                             (PINTERFACE)&Adapter->VifInterface,
                             sizeof (Adapter->VifInterface),
                             FALSE);

    if (!NT_SUCCESS(status)) {
        ndisStatus = NDIS_STATUS_ADAPTER_NOT_FOUND;
        goto fail2;
    }

    ndisStatus = AdapterInitialize(Adapter, MiniportAdapterHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto fail3;
    }

    Trace("<====\n");
    return ndisStatus;

fail3:
    Error("fail3\n");

    RtlZeroMemory(&Adapter->VifInterface,
                  sizeof (XENVIF_VIF_INTERFACE));

fail2:
    Error("fail2\n");

    ExFreePool(Adapter);

fail1:
    Error("fail1\n");

    return ndisStatus;
}

//
// Stops adapter and frees all resources.
//
VOID 
MiniportHalt (
    IN  NDIS_HANDLE             MiniportAdapterHandle,
    IN  NDIS_HALT_ACTION        HaltAction
    )
{
    PADAPTER Adapter = (PADAPTER)MiniportAdapterHandle;

    UNREFERENCED_PARAMETER(HaltAction);

    if (Adapter == NULL)
        return;

    (VOID) AdapterStop(Adapter);

    AdapterCleanup(Adapter);

    RtlZeroMemory(&Adapter->VifInterface,
                  sizeof (XENVIF_VIF_INTERFACE));

    ExFreePool(Adapter);
}
