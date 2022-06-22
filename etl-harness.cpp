#define INITGUID

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>

#pragma comment(lib, "tdh.lib")

wchar_t* g_filename;

#define LOGFILE_PATH L"C:\\Code\\etw\\V2EventTraceController\\mylogfile.etl"   /// Hardcoded stuff
ULONG g_TimerResolution = 0;
BOOL g_bUserMode = FALSE;
TRACEHANDLE g_hTrace = 0;


void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
extern "C"
__declspec(dllexport)
__declspec(noinline)
void fuzzme1(wchar_t* fPath)
{
    try {
        TDHSTATUS status = ERROR_SUCCESS;
        EVENT_TRACE_LOGFILE trace;
        TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
        trace.LogFileName = (LPWSTR)fPath;
        trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(ProcessEvent);
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;

        g_hTrace = OpenTrace(&trace);
        if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)
        {
            wprintf(L"OpenTrace failed with %lu\n", GetLastError());
            goto cleanup;
        }

        g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

        if (pHeader->TimerResolution > 0)
        {
            g_TimerResolution = pHeader->TimerResolution / 10000;
        }

        if (pHeader->PointerSize != sizeof(PVOID))
        {
            pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
                2 * (pHeader->PointerSize - sizeof(PVOID)));
        }

        status = ProcessTrace(&g_hTrace, 1, 0, 0);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
        {
            wprintf(L"ProcessTrace failed with %lu\n", status);
            goto cleanup;
        }

    cleanup:

        if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
        {
            status = CloseTrace(g_hTrace);
        }
    }
    catch (...) {

        // Ignore C++ Exceptions

        return;

    }



}

void wmain(int argc, wchar_t* argv[])
{
    g_filename = argv[1];

    fuzzme1(g_filename);

}


// Callback that receives the events. 

VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pwsEventGuid = NULL;
    PBYTE pUserData = NULL;
    PBYTE pEndOfUserData = NULL;
    DWORD PointerSize = 0;
    ULONGLONG TimeStamp = 0;
    ULONGLONG Nanoseconds = 0;
    SYSTEMTIME st;
    SYSTEMTIME stLocal;
    FILETIME ft;

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
        pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {

        status = GetEventInformation(pEvent, pInfo);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"GetEventInformation failed with %lu\n", status);
            goto cleanup;
        }

        if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
        {
            HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

            if (FAILED(hr))
            {
                wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
                status = hr;
                goto cleanup;
            }

            CoTaskMemFree(pwsEventGuid);
            pwsEventGuid = NULL;
        }
        else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
        {
        }
        else 
        {
            goto cleanup;
        }

        // Print the time stamp for when the event occurred.

        ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

        TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
        Nanoseconds = (TimeStamp % 10000000) * 100;

        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            PointerSize = 4;
        }
        else
        {
            PointerSize = 8;
        }

        pUserData = (PBYTE)pEvent->UserData;
        pEndOfUserData = (PBYTE)pEvent->UserData + pEvent->UserDataLength;
        for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
        {
            pUserData = PrintProperties(pEvent, pInfo, PointerSize, i, pUserData, pEndOfUserData);
            if (NULL == pUserData)
            {
                wprintf(L"Printing top level properties failed.\n");
                goto cleanup;
            }
        }
    }

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    if (ERROR_SUCCESS != status || NULL == pUserData)
    {
        CloseTrace(g_hTrace);
    }
}

PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData)
{
    TDHSTATUS status = ERROR_SUCCESS;
    USHORT PropertyLength = 0;
    DWORD FormattedDataSize = 0;
    USHORT UserDataConsumed = 0;
    USHORT UserDataLength = 0;
    LPWSTR pFormattedData = NULL;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;


    // Get the length of the property.

    status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength);
    if (ERROR_SUCCESS != status)
    {
        wprintf(L"GetPropertyLength failed.\n");
        pUserData = NULL;
        goto cleanup;
    }

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; k++)
    {
        // If the property is a structure, print the members of the structure.

        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
            {
                pUserData = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
                if (NULL == pUserData)
                {
                    wprintf(L"Printing the members of the structure failed.\n");
                    pUserData = NULL;
                    goto cleanup;
                }
            }
        }
        else
        {
            // Get the name/value mapping if the property specifies a value map.

            status = GetMapInfo(pEvent,
                (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                pInfo->DecodingSource,
                pMapInfo);

            if (ERROR_SUCCESS != status)
            {
                wprintf(L"GetMapInfo failed\n");
                pUserData = NULL;
                goto cleanup;
            }


            status = TdhFormatProperty(
                pInfo,
                pMapInfo,
                PointerSize,
                pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                PropertyLength,
                (USHORT)(pEndOfUserData - pUserData),
                pUserData,
                &FormattedDataSize,
                pFormattedData,
                &UserDataConsumed);

            if (ERROR_INSUFFICIENT_BUFFER == status)
            {
                if (pFormattedData)
                {
                    free(pFormattedData);
                    pFormattedData = NULL;
                }

                pFormattedData = (LPWSTR)malloc(FormattedDataSize);
                if (pFormattedData == NULL)
                {
                    wprintf(L"Failed to allocate memory for formatted data (size=%lu).\n", FormattedDataSize);
                    status = ERROR_OUTOFMEMORY;
                    pUserData = NULL;
                    goto cleanup;
                }


                status = TdhFormatProperty(
                    pInfo,
                    pMapInfo,
                    PointerSize,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    PropertyLength,
                    (USHORT)(pEndOfUserData - pUserData),
                    pUserData,
                    &FormattedDataSize,
                    pFormattedData,
                    &UserDataConsumed);
            }

            if (ERROR_SUCCESS == status)
            {

                pUserData += UserDataConsumed;
            }
            else
            {
                wprintf(L"TdhFormatProperty failed with %lu.\n", status);
                pUserData = NULL;
                goto cleanup;
            }
        }
    }

cleanup:

    if (pFormattedData)
    {
        free(pFormattedData);
        pFormattedData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return pUserData;
}

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        *PropertyLength = (USHORT)Length;
    }
    else
    {
        if (pInfo->EventPropertyInfoArray[i].length > 0)
        {
            *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
        }
        else
        {

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                *PropertyLength = (USHORT)sizeof(IN6_ADDR);
            }
            else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                (pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
            {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
            }
            else
            {
                wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                status = ERROR_EVT_INVALID_EVENT_DATA;
                goto cleanup;
            }
        }
    }

cleanup:

    return status;
}

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO& pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
        if (pMapInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else
    {
        if (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
        }
    }

cleanup:

    return status;
}

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    DWORD ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}

DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO& pInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;
    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
        if (pInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }
        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS != status)
    {
        wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
    }

cleanup:

    return status;
}
