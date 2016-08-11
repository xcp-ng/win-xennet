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

#define INITGUID

#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <strsafe.h>
#include <malloc.h>
#include <stdarg.h>
#include <assert.h>
#include <vif_interface.h>

#include <tcpip.h>
#include <version.h>

__user_code;

#define MAXIMUM_BUFFER_SIZE 1024

#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"

#define SERVICE_KEY(_Driver)    \
        SERVICES_KEY ## "\\" ## #_Driver

#define ADDRESSES_KEY   \
        SERVICE_KEY(XENVIF) ## "\\Addresses"

#define CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control"

#define CLASS_KEY   \
        CONTROL_KEY ## "\\Class"

static VOID
#pragma prefast(suppress:6262) // Function uses '1036' bytes of stack: exceeds /analyze:stacksize'1024'
__Log(
    IN  const CHAR  *Format,
    IN  ...
    )
{
    TCHAR               Buffer[MAXIMUM_BUFFER_SIZE];
    va_list             Arguments;
    size_t              Length;
    SP_LOG_TOKEN        LogToken;
    DWORD               Category;
    DWORD               Flags;
    HRESULT             Result;

    va_start(Arguments, Format);
    Result = StringCchVPrintf(Buffer, MAXIMUM_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);

    if (Result != S_OK && Result != STRSAFE_E_INSUFFICIENT_BUFFER)
        return;

    Result = StringCchLength(Buffer, MAXIMUM_BUFFER_SIZE, &Length);
    if (Result != S_OK)
        return;

    LogToken = SetupGetThreadLogToken();
    Category = TXTLOG_VENDOR;
    Flags = TXTLOG_WARNING;

    SetupWriteTextLog(LogToken, Category, Flags, Buffer);
    Length = __min(MAXIMUM_BUFFER_SIZE - 1, Length + 2);

    __analysis_assume(Length < MAXIMUM_BUFFER_SIZE);
    __analysis_assume(Length >= 2);
    Buffer[Length] = '\0';
    Buffer[Length - 1] = '\n';
    Buffer[Length - 2] = '\r';

    OutputDebugString(Buffer);
}

#define Log(_Format, ...) \
        __Log(__MODULE__ "|" __FUNCTION__ ": " _Format, __VA_ARGS__)

static FORCEINLINE PTCHAR
__GetErrorMessage(
    IN  DWORD   Error
    )
{
    PTCHAR      Message;
    ULONG       Index;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  Error,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&Message,
                  0,
                  NULL);

    for (Index = 0; Message[Index] != '\0'; Index++) {
        if (Message[Index] == '\r' || Message[Index] == '\n') {
            Message[Index] = '\0';
            break;
        }
    }

    return Message;
}

static FORCEINLINE const CHAR *
__FunctionName(
    IN  DI_FUNCTION Function
    )
{
#define _NAME(_Function)        \
        case DIF_ ## _Function: \
            return #_Function;

    switch (Function) {
    _NAME(INSTALLDEVICE);
    _NAME(REMOVE);
    _NAME(SELECTDEVICE);
    _NAME(ASSIGNRESOURCES);
    _NAME(PROPERTIES);
    _NAME(FIRSTTIMESETUP);
    _NAME(FOUNDDEVICE);
    _NAME(SELECTCLASSDRIVERS);
    _NAME(VALIDATECLASSDRIVERS);
    _NAME(INSTALLCLASSDRIVERS);
    _NAME(CALCDISKSPACE);
    _NAME(DESTROYPRIVATEDATA);
    _NAME(VALIDATEDRIVER);
    _NAME(MOVEDEVICE);
    _NAME(DETECT);
    _NAME(INSTALLWIZARD);
    _NAME(DESTROYWIZARDDATA);
    _NAME(PROPERTYCHANGE);
    _NAME(ENABLECLASS);
    _NAME(DETECTVERIFY);
    _NAME(INSTALLDEVICEFILES);
    _NAME(ALLOW_INSTALL);
    _NAME(SELECTBESTCOMPATDRV);
    _NAME(REGISTERDEVICE);
    _NAME(NEWDEVICEWIZARD_PRESELECT);
    _NAME(NEWDEVICEWIZARD_SELECT);
    _NAME(NEWDEVICEWIZARD_PREANALYZE);
    _NAME(NEWDEVICEWIZARD_POSTANALYZE);
    _NAME(NEWDEVICEWIZARD_FINISHINSTALL);
    _NAME(INSTALLINTERFACES);
    _NAME(DETECTCANCEL);
    _NAME(REGISTER_COINSTALLERS);
    _NAME(ADDPROPERTYPAGE_ADVANCED);
    _NAME(ADDPROPERTYPAGE_BASIC);
    _NAME(TROUBLESHOOTER);
    _NAME(POWERMESSAGEWAKE);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

static BOOLEAN
AllowUpdate(
    IN  PTCHAR      DriverName,
    OUT PBOOLEAN    Allow
    )
{
    TCHAR           ServiceKeyName[MAX_PATH];
    HKEY            ServiceKey;
    HRESULT         Result;
    HRESULT         Error;
    DWORD           ValueLength;
    DWORD           Value;
    DWORD           Type;

    Log("====> (%s)", DriverName);

    Result = StringCbPrintf(ServiceKeyName,
                            MAX_PATH,
                            SERVICES_KEY "\\%s",
                            DriverName);
    assert(SUCCEEDED(Result));

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         ServiceKeyName,
                         0,
                         KEY_READ,
                         &ServiceKey);
    if (Error != ERROR_SUCCESS) {
        if (Error == ERROR_FILE_NOT_FOUND) {
            Value = 1;
            goto done;
        }

        SetLastError(Error);
        goto fail1;
    }

    ValueLength = sizeof (Value);

    Error = RegQueryValueEx(ServiceKey,
                            "AllowUpdate",
                            NULL,
                            &Type,
                            (LPBYTE)&Value,
                            &ValueLength);
    if (Error != ERROR_SUCCESS) {
        if (Error == ERROR_FILE_NOT_FOUND) {
            Type = REG_DWORD;
            Value = 1;
        } else {
            SetLastError(Error);
            goto fail2;
        }
    }

    if (Type != REG_DWORD) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

done:
    if (Value == 0) {
        Log("DISALLOWED");
        *Allow = FALSE;
    }

    RegCloseKey(ServiceKey);

    Log("<====");

    return TRUE;

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(ServiceKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
AllowInstall(
    OUT PBOOLEAN    Allow
    )
{
    BOOLEAN         Success;
    HRESULT         Error;

    Log("====>");

    *Allow = TRUE;

    Success = AllowUpdate("XENNET", Allow);
    if (!Success)
        goto fail1;

    Log("<====");

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
OpenSoftwareKey(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData,
    OUT PHKEY               Key
    )
{
    HRESULT                 Error;

    *Key = SetupDiOpenDevRegKey(DeviceInfoSet,
                                DeviceInfoData,
                                DICS_FLAG_GLOBAL,
                                0,
                                DIREG_DRV,
                                KEY_ALL_ACCESS);
    if (Key == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        goto fail1;
    }

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static PTCHAR
GetProperty(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData,
    IN  DWORD               Index
    )
{
    DWORD                   Type;
    DWORD                   PropertyLength;
    PTCHAR                  Property;
    HRESULT                 Error;

    if (!SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                          DeviceInfoData,
                                          Index,
                                          &Type,
                                          NULL,
                                          0,
                                          &PropertyLength)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto fail1;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail2;
    }

    PropertyLength += sizeof (TCHAR);

    Property = calloc(1, PropertyLength);
    if (Property == NULL)
        goto fail3;

    if (!SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                          DeviceInfoData,
                                          Index,
                                          NULL,
                                          (PBYTE)Property,
                                          PropertyLength,
                                          NULL))
        goto fail4;

    return Property;

fail4:
    free(Property);

fail3:
    Log("fail3");

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return NULL;
}

static BOOLEAN
GetLocation(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData,
    OUT PTCHAR              *Location
    )
{
    HRESULT                 Error;

    *Location = GetProperty(DeviceInfoSet,
                            DeviceInfoData,
                            SPDRP_LOCATION_INFORMATION);
    if (*Location == NULL)
        goto fail1;

    Log("%s", *Location);

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
ParseMacAddress(
    IN  PCHAR               Buffer,
    OUT PETHERNET_ADDRESS   Address
    )
{
    ULONG                   Length;
    HRESULT                 Error;

    Length = 0;
    for (;;) {
        CHAR    Character;
        UCHAR   Byte;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte = Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte = 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte = 0x0A + Character - 'a';
        else
            break;

        Byte <<= 4;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte += Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte += 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte += 0x0A + Character - 'a';
        else
            break;

        Address->Byte[Length++] = Byte;

        // Skip over any separator
        if (*Buffer == ':' || *Buffer == '-')
            Buffer++;
    }

    if (Length != ETHERNET_ADDRESS_LENGTH) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail1;
    }

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
GetPermanentAddress(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PTCHAR                  Location;
    HRESULT                 Error;
    HKEY                    AddressesKey;
    DWORD                   MaxValueLength;
    DWORD                   BufferLength;
    PTCHAR                  Buffer;
    DWORD                   Type;
    BOOLEAN                 Success;

    Log("====>");

    Success = GetLocation(DeviceInfoSet,
                          DeviceInfoData,
                          &Location);
    if (!Success)
        goto fail1;

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         ADDRESSES_KEY,
                         0,
                         KEY_READ,
                         &AddressesKey);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    Error = RegQueryInfoKey(AddressesKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    BufferLength = MaxValueLength + sizeof (TCHAR);

    Buffer = calloc(1, BufferLength);
    if (Buffer == NULL)
        goto fail4;

    Error = RegQueryValueEx(AddressesKey,
                            Location,
                            NULL,
                            &Type,
                            (LPBYTE)Buffer,
                            &BufferLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail5;
    }

    if (Type != REG_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail6;
    }

    Success = ParseMacAddress(Buffer, Address);
    if (!Success)
        goto fail7;

    free(Buffer);

    RegCloseKey(AddressesKey);

    free(Location);

    Log("%02X:%02X:%02X:%02X:%02X:%02X",
        Address->Byte[0],
        Address->Byte[1],
        Address->Byte[2],
        Address->Byte[3],
        Address->Byte[4],
        Address->Byte[5]);

    Log("<====");

    return TRUE;

fail7:
    Log("fail7");

fail6:
    Log("fail6");

fail5:
    Log("fail5");

    free(Buffer);

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    RegCloseKey(AddressesKey);

fail2:
    Log("fail2");

    free(Location);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
GetNetLuid(
    IN  PETHERNET_ADDRESS   Address,
    OUT PNET_LUID           *NetLuid
    )
{
    PMIB_IF_TABLE2          Table;
    DWORD                   Index;
    PMIB_IF_ROW2            Row;
    HRESULT                 Error;

    Error = GetIfTable2(&Table);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    for (Index = 0; Index < Table->NumEntries; Index++) {
        Row = &Table->Table[Index];

        Log("checking %ws (%ws)",
            Row->Alias,
            Row->Description);

        if (!Row->InterfaceAndOperStatusFlags.ConnectorPresent)
            continue;

        if (Row->PhysicalAddressLength != sizeof (ETHERNET_ADDRESS))
            continue;

        if (memcmp(Row->PermanentPhysicalAddress,
                   Address,
                   sizeof (ETHERNET_ADDRESS)) != 0)
            continue;

        if (Row->OperStatus != IfOperStatusUp)
            continue;

        goto found;
    }

    *NetLuid = NULL;
    goto done;

found:
    *NetLuid = calloc(1, sizeof (NET_LUID));
    if (*NetLuid == NULL)
        goto fail2;

    (*NetLuid)->Value = Row->InterfaceLuid.Value;

    Log("%08x.%08x",
        (*NetLuid)->Info.IfType,
        (*NetLuid)->Info.NetLuidIndex);

done:
    FreeMibTable(Table);

    return TRUE;

fail2:
    Log("fail2");

    FreeMibTable(Table);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
OpenClassKey(
    IN  const GUID  *Guid,
    OUT PHKEY       Key
    )
{
    TCHAR           KeyName[MAX_PATH];
    HRESULT         Result;
    HRESULT         Error;

    Result = StringCbPrintf(KeyName,
                            MAX_PATH,
                            "%s\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                            CLASS_KEY,
                            Guid->Data1,
                            Guid->Data2,
                            Guid->Data3,
                            Guid->Data4[0],
                            Guid->Data4[1],
                            Guid->Data4[2],
                            Guid->Data4[3],
                            Guid->Data4[4],
                            Guid->Data4[5],
                            Guid->Data4[6],
                            Guid->Data4[7]);
    if (!SUCCEEDED(Result)) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        goto fail1;
    }

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         KeyName,
                         0,
                         KEY_READ,
                         Key);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    return TRUE;

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
FindAliasByAddress(
    IN  PETHERNET_ADDRESS   Address,
    OUT PTCHAR              *SoftwareKeyName
    )
{
    const GUID              *Guid = &GUID_DEVCLASS_NET;
    BOOLEAN                 Success;
    PNET_LUID               NetLuid;
    HKEY                    NetKey;
    HRESULT                 Error;
    DWORD                   SubKeys;
    DWORD                   MaxSubKeyLength;
    DWORD                   SubKeyLength;
    PTCHAR                  SubKeyName;
    DWORD                   Index;
    HKEY                    SubKey;

    Log("====>");

    Success = GetNetLuid(Address, &NetLuid);
    if (!Success)
        goto fail1;

    *SoftwareKeyName = NULL;

    if (NetLuid == NULL)
        goto done;

    Success = OpenClassKey(Guid, &NetKey);
    if (!Success)
        goto fail2;

    Error = RegQueryInfoKey(NetKey,
                            NULL,
                            NULL,
                            NULL,
                            &SubKeys,
                            &MaxSubKeyLength,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);

    SubKeyName = calloc(1, SubKeyLength);
    if (SubKeyName == NULL)
        goto fail4;

    for (Index = 0; Index < SubKeys; Index++) {
        DWORD   Length;
        DWORD   Type;
        DWORD   IfType;
        DWORD   NetLuidIndex;

        SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);
        memset(SubKeyName, 0, SubKeyLength);

        Error = RegEnumKeyEx(NetKey,
                             Index,
                             (LPTSTR)SubKeyName,
                             &SubKeyLength,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail5;
        }

        Error = RegOpenKeyEx(NetKey,
                             SubKeyName,
                             0,
                             KEY_READ,
                             &SubKey);
        if (Error != ERROR_SUCCESS)
            continue;

        Length = sizeof (DWORD);
        Error = RegQueryValueEx(SubKey,
                                "*IfType",
                                NULL,
                                &Type,
                                (LPBYTE)&IfType,
                                &Length);
        if (Error != ERROR_SUCCESS ||
            Type != REG_DWORD)
            goto loop;

        Length = sizeof (DWORD);
        Error = RegQueryValueEx(SubKey,
                                "NetLuidIndex",
                                NULL,
                                &Type,
                                (LPBYTE)&NetLuidIndex,
                                &Length);
        if (Error != ERROR_SUCCESS ||
            Type != REG_DWORD)
            goto loop;

        if (NetLuid->Info.IfType == IfType &&
            NetLuid->Info.NetLuidIndex == NetLuidIndex) {
            *SoftwareKeyName = SubKeyName;

            RegCloseKey(SubKey);
            break;
        }

loop:
        RegCloseKey(SubKey);
    }

    if (*SoftwareKeyName == NULL)
        free(SubKeyName);

    RegCloseKey(NetKey);

    free(NetLuid);

done:
    Log("%s", (*SoftwareKeyName == NULL) ? "[NONE]" : *SoftwareKeyName);

    Log("<====");

    return TRUE;

fail5:
    Log("fail5");

    free(SubKeyName);

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    RegCloseKey(NetKey);

fail2:
    Log("fail2");

    free(NetLuid);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
LinkAliasToLocation(
    IN  PTCHAR  Location,
    IN  PTCHAR  SoftwareKeyName
    )
{
    const GUID  *Guid = &GUID_DEVCLASS_NET;
    HKEY        NetKey;
    HRESULT     Error;
    HKEY        SoftwareKey;
    DWORD       LocationLength;
    BOOLEAN     Success;

    Log("====>");

    Success = OpenClassKey(Guid, &NetKey);
    if (!Success)
        goto fail1;

    Error = RegOpenKeyEx(NetKey,
                         SoftwareKeyName,
                         0,
                         KEY_ALL_ACCESS,
                         &SoftwareKey);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    LocationLength = (DWORD)((strlen(Location) + 1) * sizeof (TCHAR));

    Error = RegSetValueEx(SoftwareKey,
                          "VIF",
                          0,
                          REG_SZ,
                          (LPBYTE)Location,
                          LocationLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    Log("VIF = %s", Location);

    RegCloseKey(SoftwareKey);

    RegCloseKey(NetKey);

    Log("<====");

    return TRUE;

fail3:
    Log("fail3");

    RegCloseKey(SoftwareKey);

fail2:
    Log("fail2");

    RegCloseKey(NetKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
FindAliasByLocation(
    IN  PTCHAR  Location,
    OUT PTCHAR  *SoftwareKeyName
    )
{
    const GUID  *Guid = &GUID_DEVCLASS_NET;
    BOOLEAN     Success;
    HKEY        NetKey;
    HRESULT     Error;
    DWORD       SubKeys;
    DWORD       MaxSubKeyLength;
    DWORD       SubKeyLength;
    PTCHAR      SubKeyName;
    DWORD       Index;
    DWORD       VifLength;
    PTCHAR      Vif;
    HKEY        SubKey;

    Log("====>");

    *SoftwareKeyName = NULL;

    Success = OpenClassKey(Guid, &NetKey);
    if (!Success)
        goto fail1;

    Error = RegQueryInfoKey(NetKey,
                            NULL,
                            NULL,
                            NULL,
                            &SubKeys,
                            &MaxSubKeyLength,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);

    SubKeyName = calloc(1, SubKeyLength);
    if (SubKeyName == NULL)
        goto fail3;

    for (Index = 0; Index < SubKeys; Index++) {
        DWORD   MaxValueLength;
        DWORD   Type;

        SubKeyLength = MaxSubKeyLength + sizeof (TCHAR);
        memset(SubKeyName, 0, SubKeyLength);

        Error = RegEnumKeyEx(NetKey,
                             Index,
                             (LPTSTR)SubKeyName,
                             &SubKeyLength,
                             NULL,
                             NULL,
                             NULL,
                             NULL);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail4;
        }

        Error = RegOpenKeyEx(NetKey,
                             SubKeyName,
                             0,
                             KEY_READ,
                             &SubKey);
        if (Error != ERROR_SUCCESS)
            continue;

        Error = RegQueryInfoKey(SubKey,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                &MaxValueLength,
                                NULL,
                                NULL);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail5;
        }

        VifLength = MaxValueLength + sizeof (TCHAR);

        Vif = calloc(1, VifLength);
        if (Vif == NULL)
            goto fail6;

        Error = RegQueryValueEx(SubKey,
                                "VIF",
                                NULL,
                                &Type,
                                (LPBYTE)Vif,
                                &VifLength);
        if (Error != ERROR_SUCCESS ||
            Type != REG_SZ)
            goto loop;

        if (strcmp(Vif, Location) == 0) {
            *SoftwareKeyName = SubKeyName;

            free(Vif);

            RegCloseKey(SubKey);
            break;
        }

loop:
        free(Vif);

        RegCloseKey(SubKey);
    }

    if (*SoftwareKeyName == NULL)
        free(SubKeyName);

    RegCloseKey(NetKey);

    Log("%s", (*SoftwareKeyName == NULL) ? "[NONE]" : *SoftwareKeyName);

    Log("<====");

    return TRUE;

fail6:
    Log("fail6");

fail5:
    Log("fail5");

    RegCloseKey(SubKey);

fail4:
    Log("fail4");

    free(SubKeyName);

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(NetKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;
        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
CopyKeyValues(
    IN  HKEY    DestinationKey,
    IN  HKEY    SourceKey
    )
{
    HRESULT     Error;
    DWORD       Values;
    DWORD       MaxValueNameLength;
    PTCHAR      ValueName;
    DWORD       MaxValueLength;
    LPBYTE      Value;
    DWORD       Index;

    Error = RegQueryInfoKey(SourceKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &Values,
                            &MaxValueNameLength,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    if (Values == 0)
        goto done;

    MaxValueNameLength += sizeof (TCHAR);

    ValueName = calloc(1, MaxValueNameLength);
    if (ValueName == NULL)
        goto fail2;

    Value = calloc(1, MaxValueLength);
    if (Value == NULL)
        goto fail3;

    for (Index = 0; Index < Values; Index++) {
        DWORD   ValueNameLength;
        DWORD   ValueLength;
        DWORD   Type;

        ValueNameLength = MaxValueNameLength;
        memset(ValueName, 0, ValueNameLength);

        ValueLength = MaxValueLength;
        memset(Value, 0, ValueLength);

        Error = RegEnumValue(SourceKey,
                             Index,
                             (LPTSTR)ValueName,
                             &ValueNameLength,
                             NULL,
                             &Type,
                             Value,
                             &ValueLength);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail4;
        }

        Error = RegSetValueEx(DestinationKey,
                              ValueName,
                              0,
                              Type,
                              Value,
                              ValueLength);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail5;
        }

        Log("COPIED %s", ValueName);
    }

    free(Value);
    free(ValueName);

done:
    return TRUE;

fail5:
    Log("fail5");

fail4:
    Log("fail4");

    free(Value);

fail3:
    Log("fail3");

    free(ValueName);

fail2:
    Log("fail2");

fail1:
    Log("fail1");

    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
CopySubKey(
    IN  HKEY    DestinationKey,
    IN  HKEY    SourceKey,
    IN  PTCHAR  SubKeyName
    )
{
    HRESULT     Error;
    HKEY        DestinationSubKey;
    HKEY        SourceSubKey;

    Log("====>");

    Log("%s", SubKeyName);

    Error = RegOpenKeyEx(SourceKey,
                         SubKeyName,
                         0,
                         KEY_READ,
                         &SourceSubKey);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    Error = RegCreateKeyEx(DestinationKey,
                           SubKeyName,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_ALL_ACCESS,
                           NULL,
                           &DestinationSubKey,
                           NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    CopyKeyValues(DestinationSubKey, SourceSubKey);

    RegCloseKey(DestinationSubKey);
    RegCloseKey(SourceSubKey);

    Log("<====");

    return TRUE;

fail2:
    Log("fail2");

    RegCloseKey(SourceSubKey);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
CopyValue(
    IN  HKEY    DestinationKey,
    IN  HKEY    SourceKey,
    IN  PTCHAR  ValueName
    )
{
    HRESULT     Error;
    DWORD       MaxValueLength;
    LPBYTE      Value;
    DWORD       ValueLength;
    DWORD       Type;

    Log("====>");

    Error = RegQueryInfoKey(SourceKey,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            &MaxValueLength,
                            NULL,
                            NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    ValueLength = MaxValueLength;

    Value = calloc(1, ValueLength);
    if (Value == NULL)
        goto fail2;

    memset(Value, 0, ValueLength);

    Error = RegQueryValueEx(SourceKey,
                            ValueName,
                            NULL,
                            &Type,
                            (LPBYTE)Value,
                            &ValueLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail3;
    }

    Error = RegSetValueEx(DestinationKey,
                          ValueName,
                          0,
                          Type,
                          Value,
                          ValueLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail4;
    }

    Log("COPIED %s", ValueName);

    free(Value);

    Log("<====");

    return TRUE;

fail4:
    Log("fail4");

fail3:
    Log("fail3");

    free(Value);

fail2:
    Log("fail2");

fail1:
    Log("fail1");

    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
StealLinkageFromAlias(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData,
    IN  PTCHAR              SoftwareKeyName
    )
{
    const GUID              *Guid = &GUID_DEVCLASS_NET;
    BOOLEAN                 Success;
    HKEY                    NetKey;
    HRESULT                 Error;
    HKEY                    SourceKey;
    HKEY                    DestinationKey;

    Log("====>");

    Success = OpenClassKey(Guid, &NetKey);
    if (!Success)
        goto fail1;

    Error = RegOpenKeyEx(NetKey,
                         SoftwareKeyName,
                         0,
                         KEY_ALL_ACCESS,
                         &SourceKey);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail2;
    }

    Success = OpenSoftwareKey(DeviceInfoSet,
                              DeviceInfoData,
                              &DestinationKey);
    if (!Success)
        goto fail3;

    Success = CopyValue(DestinationKey,
                        SourceKey,
                        "NetCfgInstanceID");
    if (!Success)
        goto fail4;

    Success = CopyValue(DestinationKey,
                        SourceKey,
                        "NetLuidIndex");
    if (!Success)
        goto fail5;

    Success = CopySubKey(DestinationKey,
                         SourceKey,
                         "Linkage");
    if (!Success)
        goto fail6;

    RegCloseKey(DestinationKey);

    RegCloseKey(SourceKey);

    RegCloseKey(NetKey);

    Log("<====");

    return TRUE;

fail6:
    Log("fail6");

fail5:
    Log("fail5");

fail4:
    Log("fail4");

    RegCloseKey(DestinationKey);

fail3:
    Log("fail3");

    RegCloseKey(SourceKey);

fail2:
    Log("fail2");

    RegCloseKey(NetKey);

fail1:
    Log("fail1");

    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
ClearStolenLinkage(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData
    )
{
    BOOLEAN                 Success;
    HKEY                    SoftwareKey;
    HRESULT                 Error;

    Log("====>");

    Success = OpenSoftwareKey(DeviceInfoSet,
                              DeviceInfoData,
                              &SoftwareKey);
    if (!Success)
        goto fail1;

    (VOID) RegDeleteKey(SoftwareKey, "Linkage");
    (VOID) RegDeleteValue(SoftwareKey, "NetLuidIndex");
    (VOID) RegDeleteValue(SoftwareKey, "NetCfgInstanceID");

    RegCloseKey(SoftwareKey);

    Log("<====");

    return TRUE;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static FORCEINLINE HRESULT
__DifInstallPreProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;
    BOOLEAN                         Success;
    BOOLEAN                         Allow;
    ETHERNET_ADDRESS                Address;
    PTCHAR                          Location;
    PTCHAR                          SoftwareKeyName;

    Log("====>");

    Context->PrivateData = NULL;

    Success = AllowInstall(&Allow);
    if (!Success)
        goto fail1;

    if (!Allow) {
        SetLastError(ERROR_ACCESS_DENIED);
        goto fail2;
    }

    Location = NULL;

    Success = GetLocation(DeviceInfoSet,
                          DeviceInfoData,
                          &Location);
    if (!Success)
        goto fail3;

    Success = GetPermanentAddress(DeviceInfoSet,
                                  DeviceInfoData,
                                  &Address);
    if (!Success)
        goto fail4;

    SoftwareKeyName = NULL;

    Success = FindAliasByAddress(&Address,
                                 &SoftwareKeyName);
    if (!Success)
        goto fail5;

    if (SoftwareKeyName != NULL) {
        Success = LinkAliasToLocation(Location,
                                      SoftwareKeyName);

        free(SoftwareKeyName);

        if (!Success)
            goto fail6;

        Context->PrivateData = (PVOID)TRUE;
        goto done;
    }

    SoftwareKeyName = NULL;

    Success = FindAliasByLocation(Location,
                                  &SoftwareKeyName);
    if (!Success)
        goto fail7;

    if (SoftwareKeyName != NULL) {
        Success = StealLinkageFromAlias(DeviceInfoSet,
                                        DeviceInfoData,
                                        SoftwareKeyName);

        free(SoftwareKeyName);

        if (!Success)
            goto fail8;
    }

done:
    Log("<====");

    return NO_ERROR;

fail8:
    Log("fail8");

fail7:
    Log("fail7");

fail6:
    Log("fail6");

fail5:
    Log("fail5");

fail4:
    Log("fail4");

    free(Location);

fail3:
    Log("fail3");

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static FORCEINLINE HRESULT
__DifInstallPostProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;
    BOOLEAN                         Success;
    PTCHAR                          Location;
    PTCHAR                          SoftwareKeyName;

    Log("====>");

    if (Context->PrivateData == NULL)
        goto done;

    Location = NULL;

    Success = GetLocation(DeviceInfoSet,
                          DeviceInfoData,
                          &Location);
    if (!Success)
        goto fail1;

    SoftwareKeyName = NULL;

    Success = FindAliasByLocation(Location,
                                  &SoftwareKeyName);
    if (!Success)
        goto fail2;

    if (SoftwareKeyName != NULL) {
        Success = StealLinkageFromAlias(DeviceInfoSet,
                                        DeviceInfoData,
                                        SoftwareKeyName);

        free(SoftwareKeyName);

        if (!Success)
            goto fail3;
    }

done:
    Log("<====");

    return NO_ERROR;

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    free(Location);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static DECLSPEC_NOINLINE HRESULT
DifInstall(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;

    if (!Context->PostProcessing) {
        Error = __DifInstallPreProcess(DeviceInfoSet, DeviceInfoData, Context);
        if (Error == NO_ERROR)
            Error = ERROR_DI_POSTPROCESSING_REQUIRED;
    } else {
        Error = Context->InstallResult;

        if (Error == NO_ERROR) {
            (VOID) __DifInstallPostProcess(DeviceInfoSet, DeviceInfoData, Context);
        } else {
            PTCHAR  Message;

            Message = __GetErrorMessage(Error);
            Log("NOT RUNNING (__DifInstallPreProcess Error: %s)", Message);
            LocalFree(Message);
        }
    }

    return Error;
}

static FORCEINLINE HRESULT
__DifRemovePreProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;
    BOOLEAN                         Success;
    PTCHAR                          Location;
    PTCHAR                          SoftwareKeyName;

    UNREFERENCED_PARAMETER(Context);

    Log("====>");

    Location = NULL;

    Success = GetLocation(DeviceInfoSet,
                          DeviceInfoData,
                          &Location);
    if (!Success)
        goto fail1;

    SoftwareKeyName = NULL;

    Success = FindAliasByLocation(Location,
                                  &SoftwareKeyName);

    if (!Success)
        goto fail2;

    if (SoftwareKeyName != NULL) {
        free(SoftwareKeyName);

        (VOID) ClearStolenLinkage(DeviceInfoSet,
                                  DeviceInfoData);
    }

    Log("<====");

    return NO_ERROR;

fail2:
    Log("fail2");

    free(Location);

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = __GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static FORCEINLINE HRESULT
__DifRemovePostProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    UNREFERENCED_PARAMETER(DeviceInfoSet);
    UNREFERENCED_PARAMETER(DeviceInfoData);
    UNREFERENCED_PARAMETER(Context);

    Log("<===>");

    return NO_ERROR;
}

static DECLSPEC_NOINLINE HRESULT
DifRemove(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;

    if (!Context->PostProcessing) {
        Error = __DifRemovePreProcess(DeviceInfoSet, DeviceInfoData, Context);

        if (Error == NO_ERROR)
            Error = ERROR_DI_POSTPROCESSING_REQUIRED; 
    } else {
        Error = Context->InstallResult;
        
        if (Error == NO_ERROR) {
            (VOID) __DifRemovePostProcess(DeviceInfoSet, DeviceInfoData, Context);
        } else {
            PTCHAR  Message;

            Message = __GetErrorMessage(Error);
            Log("NOT RUNNING (__DifRemovePreProcess Error: %s)", Message);
            LocalFree(Message);
        }
    }

    return Error;
}

DWORD CALLBACK
Entry(
    IN  DI_FUNCTION                 Function,
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;

    Log("%s (%s) ===>",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    if (!Context->PostProcessing) {
        Log("%s PreProcessing",
            __FunctionName(Function));
    } else {
        Log("%s PostProcessing (%08x)",
            __FunctionName(Function),
            Context->InstallResult);
    }

    switch (Function) {
    case DIF_INSTALLDEVICE: {
        SP_DRVINFO_DATA         DriverInfoData;
        BOOLEAN                 DriverInfoAvailable;

        DriverInfoData.cbSize = sizeof (DriverInfoData);
        DriverInfoAvailable = SetupDiGetSelectedDriver(DeviceInfoSet,
                                                       DeviceInfoData,
                                                       &DriverInfoData) ?
                              TRUE :
                              FALSE;

        // The NET class installer will call DIF_REMOVE even in the event of
        // a NULL driver add. However, the default installer (for the NULL
        // driver) then fails for some reason so we squash the error in
        // post-processing.
        if (DriverInfoAvailable) {
            Error = DifInstall(DeviceInfoSet, DeviceInfoData, Context);
        } else {
            if (!Context->PostProcessing) {
                Error = ERROR_DI_POSTPROCESSING_REQUIRED; 
            } else {
                Error = NO_ERROR;
            }
        }
        break;
    }
    case DIF_REMOVE:
        Error = DifRemove(DeviceInfoSet, DeviceInfoData, Context);
        break;
    default:
        if (!Context->PostProcessing) {
            Error = NO_ERROR;
        } else {
            Error = Context->InstallResult;
        }

        break;
    }

    Log("%s (%s) <===",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    return (DWORD)Error;
}

DWORD CALLBACK
Version(
    IN  HWND        Window,
    IN  HINSTANCE   Module,
    IN  PTCHAR      Buffer,
    IN  INT         Reserved
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s (%s)",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    return NO_ERROR;
}

static FORCEINLINE const CHAR *
__ReasonName(
    IN  DWORD       Reason
    )
{
#define _NAME(_Reason)          \
        case DLL_ ## _Reason:   \
            return #_Reason;

    switch (Reason) {
    _NAME(PROCESS_ATTACH);
    _NAME(PROCESS_DETACH);
    _NAME(THREAD_ATTACH);
    _NAME(THREAD_DETACH);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

BOOL WINAPI
DllMain(
    IN  HINSTANCE   Module,
    IN  DWORD       Reason,
    IN  PVOID       Reserved
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s (%s): %s",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR,
        __ReasonName(Reason));

    return TRUE;
}
