/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            ntoskrnl/cache/fssup.c
 * PURPOSE:         Logging and configuration routines
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Art Yerkes
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "newcc.h"
#include "section/newmm.h"
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PFSN_PREFETCHER_GLOBALS CcPfGlobals;
extern LONG CcOutstandingDeletes;
extern KEVENT CcpLazyWriteEvent;
extern KEVENT CcFinalizeEvent;
extern VOID NTAPI CcpUnmapThread(PVOID Unused);
extern VOID NTAPI CcpLazyWriteThread(PVOID Unused);
HANDLE CcUnmapThreadHandle, CcLazyWriteThreadHandle;
CLIENT_ID CcUnmapThreadId, CcLazyWriteThreadId;
FAST_MUTEX GlobalPageOperation;
static UNICODE_STRING CcPfRegistryKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Prefetcher");
static UNICODE_STRING CcPfRegistryValue = RTL_CONSTANT_STRING(L"BootTrace");

static VOID
NTAPI
CcPfTraceTimerDpc(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

static VOID
CcPfInitializeTraceHeader(
    _Out_ PPFSN_TRACE_HEADER Trace,
    _In_opt_ PEPROCESS Process,
    _In_ ULONG ScenarioType)
{
    LARGE_INTEGER SystemTime;

    RtlZeroMemory(Trace, sizeof(*Trace));
    InitializeListHead(&Trace->ActiveTracesLink);
    InitializeListHead(&Trace->TraceBuffersList);
    KeInitializeSpinLock(&Trace->TraceBufferSpinLock);
    KeInitializeTimer(&Trace->TraceTimer);
    KeInitializeDpc(&Trace->TraceTimerDpc, CcPfTraceTimerDpc, Trace);
    KeInitializeSpinLock(&Trace->TraceTimerSpinLock);
    ExInitializeRundownProtection(&Trace->RefCount);
    Trace->Process = Process;
    Trace->ScenarioType = ScenarioType;
    Trace->Magic = 'fPcC';
    if (Process)
    {
        Trace->ScenarioId.HashId = (ULONG)(ULONG_PTR)Process;
        RtlStringCbPrintfW(Trace->ScenarioId.ScenName,
                           sizeof(Trace->ScenarioId.ScenName),
                           L"%hs",
                           Process->ImageFileName);
    }

    KeQuerySystemTime(&SystemTime);
    Trace->LaunchTime = SystemTime;
}

static ULONG
CcPfGetSerializedTraceSize(
    _In_ PPFSN_TRACE_HEADER Trace)
{
    ULONG Size = sizeof(CCPF_TRACE_BLOB_HEADER);
    PLIST_ENTRY Entry;

    for (Entry = Trace->TraceBuffersList.Flink;
         Entry != &Trace->TraceBuffersList;
         Entry = Entry->Flink)
    {
        PPFSN_LOG_ENTRIES Buffer = CONTAINING_RECORD(Entry, PFSN_LOG_ENTRIES, TraceBuffersLink);
        Size += sizeof(CCPF_TRACE_BUFFER_BLOB) + (Buffer->NumEntries * sizeof(PF_LOG_ENTRY));
    }

    return Size;
}

static NTSTATUS
CcPfSerializeTrace(
    _In_ PPFSN_TRACE_HEADER Trace,
    _Outptr_result_bytebuffer_(*SerializedSize) PVOID *SerializedTrace,
    _Out_ PULONG SerializedSize)
{
    PCCPF_TRACE_BLOB_HEADER Blob;
    ULONG Size;
    PLIST_ENTRY Entry;
    PUCHAR Cursor;

    Size = CcPfGetSerializedTraceSize(Trace);
    Blob = ExAllocatePoolWithTag(PagedPool, Size, 'tPcC');
    if (!Blob)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Blob, Size);
    Blob->Signature = CCPF_TRACE_BLOB_SIGNATURE;
    Blob->Version = CCPF_TRACE_BLOB_VERSION;
    Blob->Size = Size;
    Blob->Trace = *(PF_TRACE_HEADER *)Trace;
    Blob->NumBuffers = Trace->NumTraceBuffers;

    Cursor = (PUCHAR)(Blob + 1);
    for (Entry = Trace->TraceBuffersList.Flink;
         Entry != &Trace->TraceBuffersList;
         Entry = Entry->Flink)
    {
        PPFSN_LOG_ENTRIES Buffer = CONTAINING_RECORD(Entry, PFSN_LOG_ENTRIES, TraceBuffersLink);
        PCCPF_TRACE_BUFFER_BLOB BufferBlob = (PCCPF_TRACE_BUFFER_BLOB)Cursor;

        BufferBlob->NumEntries = Buffer->NumEntries;
        BufferBlob->MaxEntries = Buffer->MaxEntries;
        Cursor += sizeof(*BufferBlob);

        RtlCopyMemory(Cursor,
                      Buffer->Entries,
                      Buffer->NumEntries * sizeof(PF_LOG_ENTRY));
        Cursor += Buffer->NumEntries * sizeof(PF_LOG_ENTRY);
    }

    *SerializedTrace = Blob;
    *SerializedSize = Size;
    return STATUS_SUCCESS;
}

static NTSTATUS
CcPfWriteTraceRegistryValue(
    _In_ PVOID SerializedTrace,
    _In_ ULONG SerializedSize)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes,
                               &CcPfRegistryKey,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    Status = ZwCreateKey(&KeyHandle,
                         KEY_SET_VALUE,
                         &ObjectAttributes,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ZwSetValueKey(KeyHandle,
                           &CcPfRegistryValue,
                           0,
                           REG_BINARY,
                           SerializedTrace,
                           SerializedSize);
    ZwClose(KeyHandle);
    return Status;
}

static PPFSN_TRACE_HEADER
CcPfReadTraceRegistryValue(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    NTSTATUS Status;
    ULONG Length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = NULL;
    PPFSN_TRACE_HEADER Trace = NULL;

    InitializeObjectAttributes(&ObjectAttributes,
                               &CcPfRegistryKey,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        return NULL;
    }

    Status = ZwQueryValueKey(KeyHandle,
                             &CcPfRegistryValue,
                             KeyValuePartialInformation,
                             NULL,
                             0,
                             &Length);
    if ((Status != STATUS_BUFFER_TOO_SMALL) && (Status != STATUS_BUFFER_OVERFLOW))
    {
        ZwClose(KeyHandle);
        return NULL;
    }

    ValueInfo = ExAllocatePoolWithTag(PagedPool, Length, 'tPcC');
    if (!ValueInfo)
    {
        ZwClose(KeyHandle);
        return NULL;
    }

    Status = ZwQueryValueKey(KeyHandle,
                             &CcPfRegistryValue,
                             KeyValuePartialInformation,
                             ValueInfo,
                             Length,
                             &Length);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ValueInfo, 'tPcC');
        return NULL;
    }

    if ((ValueInfo->Type != REG_BINARY) ||
        (ValueInfo->DataLength < sizeof(CCPF_TRACE_BLOB_HEADER)))
    {
        ExFreePoolWithTag(ValueInfo, 'tPcC');
        return NULL;
    }

    {
        PCCPF_TRACE_BLOB_HEADER Blob = (PCCPF_TRACE_BLOB_HEADER)ValueInfo->Data;
        PUCHAR Cursor;
        ULONG BufferIndex;

        if ((Blob->Signature != CCPF_TRACE_BLOB_SIGNATURE) ||
            (Blob->Version != CCPF_TRACE_BLOB_VERSION) ||
            (Blob->Size != ValueInfo->DataLength))
        {
            ExFreePoolWithTag(ValueInfo, 'tPcC');
            return NULL;
        }

        Trace = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Trace), 'tPcC');
        if (!Trace)
        {
            ExFreePoolWithTag(ValueInfo, 'tPcC');
            return NULL;
        }

        CcPfInitializeTraceHeader(Trace, NULL, Blob->Trace.ScenarioType);
        Trace->ScenarioId = Blob->Trace.ScenarioId;
        Trace->NumEventEntryIdxs = Blob->Trace.NumEventEntryIdxs;
        RtlCopyMemory(Trace->EventEntryIdxs,
                      Blob->Trace.EventEntryIdxs,
                      sizeof(Trace->EventEntryIdxs));
        RtlCopyMemory(Trace->FaultsPerPeriod,
                      Blob->Trace.FaultsPerPeriod,
                      sizeof(Trace->FaultsPerPeriod));
        Trace->LastNumFaults = Blob->Trace.NumEntries;
        Trace->CurPeriod = 0;
        Trace->NumFaults = (LONG)Blob->Trace.NumEntries;
        Trace->MaxFaults = (LONG)Blob->Trace.NumEntries;
        Trace->LaunchTime = Blob->Trace.LaunchTime;

        Cursor = (PUCHAR)(Blob + 1);
        InitializeListHead(&Trace->TraceBuffersList);
        Trace->NumTraceBuffers = 0;
        Trace->CurrentTraceBuffer = NULL;

        for (BufferIndex = 0; BufferIndex < Blob->NumBuffers; BufferIndex++)
        {
            PCCPF_TRACE_BUFFER_BLOB BufferBlob = (PCCPF_TRACE_BUFFER_BLOB)Cursor;
            ULONG AllocSize;
            PPFSN_LOG_ENTRIES Buffer;

            Cursor += sizeof(*BufferBlob);
            AllocSize = FIELD_OFFSET(PFSN_LOG_ENTRIES, Entries) + (BufferBlob->MaxEntries * sizeof(PF_LOG_ENTRY));
            Buffer = ExAllocatePoolWithTag(NonPagedPool, AllocSize, 'tPcC');
            if (!Buffer)
            {
                CcPfFreeTraceBuffers(Trace);
                ExFreePoolWithTag(Trace, 'tPcC');
                ExFreePoolWithTag(ValueInfo, 'tPcC');
                return NULL;
            }

            RtlZeroMemory(Buffer, AllocSize);
            InitializeListHead(&Buffer->TraceBuffersLink);
            Buffer->NumEntries = BufferBlob->NumEntries;
            Buffer->MaxEntries = BufferBlob->MaxEntries;
            RtlCopyMemory(Buffer->Entries,
                          Cursor,
                          BufferBlob->NumEntries * sizeof(PF_LOG_ENTRY));
            Cursor += BufferBlob->NumEntries * sizeof(PF_LOG_ENTRY);
            InsertTailList(&Trace->TraceBuffersList, &Buffer->TraceBuffersLink);
            Trace->NumTraceBuffers++;
            if (Trace->CurrentTraceBuffer == NULL)
            {
                Trace->CurrentTraceBuffer = Buffer;
            }
        }

        if (Trace->CurrentTraceBuffer == NULL)
        {
            CcPfFreeTraceBuffers(Trace);
            ExFreePoolWithTag(Trace, 'tPcC');
            ExFreePoolWithTag(ValueInfo, 'tPcC');
            return NULL;
        }
    }

    ExFreePoolWithTag(ValueInfo, 'tPcC');
    return Trace;
}

static VOID
CcPfSaveTrace(
    _In_opt_ PPFSN_TRACE_HEADER Trace)
{
    PVOID SerializedTrace = NULL;
    ULONG SerializedSize = 0;

    if ((Trace != NULL) &&
        NT_SUCCESS(CcPfSerializeTrace(Trace, &SerializedTrace, &SerializedSize)))
    {
        if (NT_SUCCESS(CcPfWriteTraceRegistryValue(SerializedTrace, SerializedSize)))
        {
            Trace->TraceDumpStatus = STATUS_SUCCESS;
        }

        ExFreePoolWithTag(SerializedTrace, 'tPcC');
    }
}

static VOID
CcPfInitializeTraceBuffers(
    _Inout_ PPFSN_TRACE_HEADER Trace)
{
    PPFSN_LOG_ENTRIES TraceBuffer;
    ULONG AllocSize;

    AllocSize = FIELD_OFFSET(PFSN_LOG_ENTRIES, Entries) + (64 * sizeof(PF_LOG_ENTRY));
    TraceBuffer = ExAllocatePoolWithTag(NonPagedPool, AllocSize, 'tPcC');
    if (!TraceBuffer)
    {
        return;
    }

    RtlZeroMemory(TraceBuffer, AllocSize);
    InitializeListHead(&TraceBuffer->TraceBuffersLink);
    TraceBuffer->NumEntries = 0;
    TraceBuffer->MaxEntries = 64;

    InitializeListHead(&Trace->TraceBuffersList);
    InsertTailList(&Trace->TraceBuffersList, &TraceBuffer->TraceBuffersLink);
    Trace->CurrentTraceBuffer = TraceBuffer;
    Trace->NumTraceBuffers = 1;
}

static VOID
CcPfFreeTraceBuffers(
    _Inout_ PPFSN_TRACE_HEADER Trace)
{
    PLIST_ENTRY Entry;

    while (!IsListEmpty(&Trace->TraceBuffersList))
    {
        Entry = RemoveHeadList(&Trace->TraceBuffersList);
        ExFreePoolWithTag(CONTAINING_RECORD(Entry, PFSN_LOG_ENTRIES, TraceBuffersLink), 'tPcC');
    }
}

static VOID
CcPfAppendTraceEntry(
    _Inout_ PPFSN_TRACE_HEADER Trace,
    _In_ ULONG Type,
    _In_ ULONG FileOffset)
{
    KIRQL OldIrql;
    PPFSN_LOG_ENTRIES CurrentBuffer = Trace->CurrentTraceBuffer;

    KeAcquireSpinLock(&Trace->TraceBufferSpinLock, &OldIrql);

    if ((CurrentBuffer == NULL) || (CurrentBuffer->NumEntries >= CurrentBuffer->MaxEntries))
    {
        PPFSN_LOG_ENTRIES TraceBuffer;
        ULONG AllocSize;

        AllocSize = FIELD_OFFSET(PFSN_LOG_ENTRIES, Entries) + (64 * sizeof(PF_LOG_ENTRY));
        TraceBuffer = ExAllocatePoolWithTag(NonPagedPool, AllocSize, 'tPcC');
        if (TraceBuffer)
        {
            RtlZeroMemory(TraceBuffer, AllocSize);
            InitializeListHead(&TraceBuffer->TraceBuffersLink);
            TraceBuffer->MaxEntries = 64;
            InsertTailList(&Trace->TraceBuffersList, &TraceBuffer->TraceBuffersLink);
            Trace->CurrentTraceBuffer = TraceBuffer;
            Trace->NumTraceBuffers++;
            CurrentBuffer = TraceBuffer;
        }
    }

    if (CurrentBuffer && (CurrentBuffer->NumEntries < CurrentBuffer->MaxEntries))
    {
        CurrentBuffer->Entries[CurrentBuffer->NumEntries].FileOffset = FileOffset & 0x3fffffff;
        CurrentBuffer->Entries[CurrentBuffer->NumEntries].Type = Type & 3;
        CurrentBuffer->NumEntries++;
        Trace->NumFaults++;
        Trace->FaultsPerPeriod[0]++;
    }

    KeReleaseSpinLock(&Trace->TraceBufferSpinLock, OldIrql);
}

static VOID
CcPfFreeCompletedTraces(VOID)
{
    PLIST_ENTRY Entry;

    ExAcquireFastMutex(&CcPfGlobals.CompletedTracesLock);
    while (!IsListEmpty(&CcPfGlobals.CompletedTraces))
    {
        Entry = RemoveHeadList(&CcPfGlobals.CompletedTraces);
        ExFreePoolWithTag(CONTAINING_RECORD(Entry, PFSN_TRACE_DUMP, CompletedTracesLink), 'tPcC');
        if (CcPfGlobals.NumCompletedTraces > 0)
        {
            CcPfGlobals.NumCompletedTraces--;
        }
    }
    ExReleaseFastMutex(&CcPfGlobals.CompletedTracesLock);
}

static VOID
CcPfInsertActiveTrace(
    _In_ PPFSN_TRACE_HEADER Trace)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&CcPfGlobals.ActiveTracesLock, &OldIrql);
    InsertTailList(&CcPfGlobals.ActiveTraces, &Trace->ActiveTracesLink);
    KeReleaseSpinLock(&CcPfGlobals.ActiveTracesLock, OldIrql);
}

static VOID
CcPfRemoveActiveTrace(
    _In_ PPFSN_TRACE_HEADER Trace)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&CcPfGlobals.ActiveTracesLock, &OldIrql);
    RemoveEntryList(&Trace->ActiveTracesLink);
    KeReleaseSpinLock(&CcPfGlobals.ActiveTracesLock, OldIrql);
}

static VOID
CcPfQueueCompletedTrace(
    _In_ PPFSN_TRACE_HEADER Trace)
{
    PPFSN_TRACE_DUMP TraceDump;

    TraceDump = ExAllocatePoolWithTag(NonPagedPool, sizeof(*TraceDump), 'tPcC');
    if (TraceDump)
    {
        RtlZeroMemory(TraceDump, sizeof(*TraceDump));
        InitializeListHead(&TraceDump->CompletedTracesLink);
        TraceDump->Trace.Version = 1;
        TraceDump->Trace.MagicNumber = 'fPcC';
        TraceDump->Trace.Size = sizeof(TraceDump->Trace);
        TraceDump->Trace.ScenarioId = Trace->ScenarioId;
        TraceDump->Trace.ScenarioType = Trace->ScenarioType;
        TraceDump->Trace.NumEventEntryIdxs = Trace->NumEventEntryIdxs;
        RtlCopyMemory(TraceDump->Trace.EventEntryIdxs,
                      Trace->EventEntryIdxs,
                      sizeof(TraceDump->Trace.EventEntryIdxs));
        TraceDump->Trace.NumEntries = (ULONG)Trace->NumFaults;
        TraceDump->Trace.NumSections = Trace->SectionInfoCount;
        TraceDump->Trace.LaunchTime = Trace->LaunchTime;

        ExAcquireFastMutex(&CcPfGlobals.CompletedTracesLock);
        InsertTailList(&CcPfGlobals.CompletedTraces, &TraceDump->CompletedTracesLink);
        CcPfGlobals.NumCompletedTraces++;
        ExReleaseFastMutex(&CcPfGlobals.CompletedTracesLock);
    }

    ExFreePoolWithTag(Trace, 'tPcC');
}

PPFSN_TRACE_HEADER
NTAPI
CcPfCreateTrace(
    _In_opt_ PEPROCESS Process,
    _In_ ULONG ScenarioType)
{
    PPFSN_TRACE_HEADER Trace;

    if (!CcPfEnablePrefetcher)
    {
        return NULL;
    }

    Trace = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Trace), 'tPcC');
    if (!Trace)
    {
        return NULL;
    }

    CcPfInitializeTraceHeader(Trace, Process, ScenarioType);
    CcPfInitializeTraceBuffers(Trace);
    CcPfAppendTraceEntry(Trace, 0, (ULONG)(ULONG_PTR)Process);
    CcPfInsertActiveTrace(Trace);
    return Trace;
}

VOID
NTAPI
CcPfDestroyTrace(
    _In_opt_ PPFSN_TRACE_HEADER Trace)
{
    if (!Trace)
    {
        return;
    }

    CcPfRemoveActiveTrace(Trace);

    if (CcPfGlobals.SystemWideTrace == Trace)
    {
        CcPfGlobals.SystemWideTrace = NULL;
    }

    CcPfAppendTraceEntry(Trace, 1, (ULONG)(ULONG_PTR)Trace->Process);
    CcPfFreeTraceBuffers(Trace);
    CcPfQueueCompletedTrace(Trace);
}

VOID
NTAPI
CcPfBeginBootPhase(
    _In_ ULONG BootPhase)
{
    if (!CcPfEnablePrefetcher)
    {
        return;
    }

    if (CcPfGlobals.SystemWideTrace == NULL)
    {
        CcPfGlobals.SystemWideTrace = CcPfReadTraceRegistryValue();
        if (CcPfGlobals.SystemWideTrace == NULL)
        {
            CcPfGlobals.SystemWideTrace = CcPfCreateTrace(NULL, BootPhase);
        }
        else
        {
            CcPfInsertActiveTrace(CcPfGlobals.SystemWideTrace);
        }
    }

    if (CcPfGlobals.SystemWideTrace)
    {
        CcPfAppendTraceEntry(CcPfGlobals.SystemWideTrace, 2, BootPhase);
        CcPfSaveTrace(CcPfGlobals.SystemWideTrace);
    }
}

VOID
NTAPI
CcPfShutdownPrefetcher(VOID)
{
    PPFSN_TRACE_HEADER SystemWideTrace;

    SystemWideTrace = CcPfGlobals.SystemWideTrace;
    CcPfGlobals.SystemWideTrace = NULL;

    if (SystemWideTrace)
    {
        CcPfSaveTrace(SystemWideTrace);
        CcPfDestroyTrace(SystemWideTrace);
    }

    CcPfFreeCompletedTraces();
}

/*

A note about private cache maps.

CcInitializeCacheMap and CcUninitializeCacheMap are not meant to be paired,
although they can work that way.

The actual operation I've gleaned from reading both jan kratchovil's writing
and real filesystems is this:

CcInitializeCacheMap means:

Make the indicated FILE_OBJECT have a private cache map if it doesn't already
and make it have a shared cache map if it doesn't already.

CcUninitializeCacheMap means:

Take away the private cache map from this FILE_OBJECT.  If it's the last
private cache map corresponding to a specific shared cache map (the one that
was present in the FILE_OBJECT when it was created), then delete that too,
flusing all cached information.

Using these simple semantics, filesystems can do all the things they actually
do:

- Copy out the shared cache map pointer from a newly initialized file object
and store it in the fcb cache.
- Copy it back into any file object and call CcInitializeCacheMap to make
that file object be associated with the caching of all the other siblings.
- Call CcUninitializeCacheMap on a FILE_OBJECT many times, but have only the
first one count for each specific FILE_OBJECT.
- Have the actual last call to CcUninitializeCacheMap (that is, the one that
causes zero private cache maps to be associated with a shared cache map) to
delete the cache map and flush.

So private cache map here is a light weight structure that just remembers
what shared cache map it associates with.

 */
typedef struct _NOCC_PRIVATE_CACHE_MAP
{
    LIST_ENTRY ListEntry;
    PFILE_OBJECT FileObject;
    PNOCC_CACHE_MAP Map;
} NOCC_PRIVATE_CACHE_MAP, *PNOCC_PRIVATE_CACHE_MAP;

LIST_ENTRY CcpAllSharedCacheMaps;

/* FUNCTIONS ******************************************************************/

CODE_SEG("INIT")
BOOLEAN
NTAPI
CcInitializeCacheManager(VOID)
{
    int i;

    DPRINT("Initialize\n");
    for (i = 0; i < CACHE_NUM_SECTIONS; i++)
    {
        KeInitializeEvent(&CcCacheSections[i].ExclusiveWait,
                          SynchronizationEvent,
                          FALSE);

        InitializeListHead(&CcCacheSections[i].ThisFileList);
    }

    InitializeListHead(&CcpAllSharedCacheMaps);

    KeInitializeEvent(&CcDeleteEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&CcFinalizeEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&CcpLazyWriteEvent, SynchronizationEvent, FALSE);

    CcCacheBitmap->Buffer = ((PULONG)&CcCacheBitmap[1]);
    CcCacheBitmap->SizeOfBitMap = ROUND_UP(CACHE_NUM_SECTIONS, 32);
    DPRINT1("Cache has %d entries\n", CcCacheBitmap->SizeOfBitMap);
    ExInitializeFastMutex(&CcMutex);

    return TRUE;
}

CODE_SEG("INIT")
VOID
NTAPI
CcPfInitializePrefetcher(VOID)
{
    /* Notify debugger */
    DbgPrintEx(DPFLTR_PREFETCHER_ID,
               DPFLTR_TRACE_LEVEL,
               "CCPF: InitializePrefetecher()\n");

    /* Setup the Prefetcher Data */
    InitializeListHead(&CcPfGlobals.ActiveTraces);
    InitializeListHead(&CcPfGlobals.CompletedTraces);
    ExInitializeFastMutex(&CcPfGlobals.CompletedTracesLock);
    CcPfGlobals.SystemWideTrace = NULL;
    CcPfGlobals.CompletedTracesEvent = NULL;
    CcPfGlobals.NumCompletedTraces = 0;
    CcPfGlobals.ActivePrefetches = 0;

    /* FIXME: Setup the rest of the prefetecher */
}

BOOLEAN
NTAPI
CcpAcquireFileLock(PNOCC_CACHE_MAP Map)
{
    DPRINT("Calling AcquireForLazyWrite: %x\n", Map->LazyContext);
    return Map->Callbacks.AcquireForLazyWrite(Map->LazyContext, TRUE);
}

VOID
NTAPI
CcpReleaseFileLock(PNOCC_CACHE_MAP Map)
{
    DPRINT("Releasing Lazy Write %x\n", Map->LazyContext);
    Map->Callbacks.ReleaseFromLazyWrite(Map->LazyContext);
}

/*

Cc functions are required to treat alternate streams of a file as the same
for the purpose of caching, meaning that we must be able to find the shared
cache map associated with the ``real'' stream associated with a stream file
object, if one exists.  We do that by identifying a private cache map in
our gamut that has the same volume, device and fscontext as the stream file
object we're holding.  It's heavy but it does work.  This can probably be
improved, although there doesn't seem to be any real association between
a stream file object and a sibling file object in the file object struct
itself.

 */

/* Must have CcpLock() */
PFILE_OBJECT CcpFindOtherStreamFileObject(PFILE_OBJECT FileObject)
{
    PLIST_ENTRY Entry, Private;
    for (Entry = CcpAllSharedCacheMaps.Flink;
         Entry != &CcpAllSharedCacheMaps;
         Entry = Entry->Flink)
    {
        /* 'Identical' test for other stream file object */
        PNOCC_CACHE_MAP Map = CONTAINING_RECORD(Entry, NOCC_CACHE_MAP, Entry);
        for (Private = Map->PrivateCacheMaps.Flink;
             Private != &Map->PrivateCacheMaps;
             Private = Private->Flink)
        {
            PNOCC_PRIVATE_CACHE_MAP PrivateMap = CONTAINING_RECORD(Private,
                                                                   NOCC_PRIVATE_CACHE_MAP,
                                                                   ListEntry);

            if (PrivateMap->FileObject->Flags & FO_STREAM_FILE &&
                PrivateMap->FileObject->DeviceObject == FileObject->DeviceObject &&
                PrivateMap->FileObject->Vpb == FileObject->Vpb &&
                PrivateMap->FileObject->FsContext == FileObject->FsContext &&
                PrivateMap->FileObject->FsContext2 == FileObject->FsContext2 &&
                1)
            {
                return PrivateMap->FileObject;
            }
        }
    }
    return 0;
}

/* Thanks: https://web.archive.org/web/20070228145211/http://windowsitpro.com/Windows/Articles/ArticleID/3864/pg/2/2.html */

VOID
NTAPI
CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
                     IN PCC_FILE_SIZES FileSizes,
                     IN BOOLEAN PinAccess,
                     IN PCACHE_MANAGER_CALLBACKS Callbacks,
                     IN PVOID LazyWriteContext)
{
    PNOCC_CACHE_MAP Map = FileObject->SectionObjectPointer->SharedCacheMap;
    PNOCC_PRIVATE_CACHE_MAP PrivateCacheMap = FileObject->PrivateCacheMap;

    CcpLock();
    /* We don't have a shared cache map.  First find out if we have a sibling
       stream file object we can take it from. */
    if (!Map && FileObject->Flags & FO_STREAM_FILE)
    {
        PFILE_OBJECT IdenticalStreamFileObject = CcpFindOtherStreamFileObject(FileObject);
        if (IdenticalStreamFileObject)
            Map = IdenticalStreamFileObject->SectionObjectPointer->SharedCacheMap;
        if (Map)
        {
            DPRINT1("Linking SFO %x to previous SFO %x through cache map %x #\n",
                    FileObject,
                    IdenticalStreamFileObject,
                    Map);
        }
    }
    /* We still don't have a shared cache map.  We need to create one. */
    if (!Map)
    {
        DPRINT("Initializing file object for (%p) %wZ\n",
               FileObject,
               &FileObject->FileName);

        Map = ExAllocatePool(NonPagedPool, sizeof(NOCC_CACHE_MAP));
        FileObject->SectionObjectPointer->SharedCacheMap = Map;
        Map->FileSizes = *FileSizes;
        Map->LazyContext = LazyWriteContext;
        Map->ReadAheadGranularity = PAGE_SIZE;
        RtlCopyMemory(&Map->Callbacks, Callbacks, sizeof(*Callbacks));

        /* For now ... */
        DPRINT("FileSizes->ValidDataLength %I64x\n",
               FileSizes->ValidDataLength.QuadPart);

        InitializeListHead(&Map->AssociatedBcb);
        InitializeListHead(&Map->PrivateCacheMaps);
        InsertTailList(&CcpAllSharedCacheMaps, &Map->Entry);
        DPRINT("New Map %p\n", Map);
    }
    /* We don't have a private cache map.  Link it with the shared cache map
       to serve as a held reference. When the list in the shared cache map
       is empty, we know we can delete it. */
    if (!PrivateCacheMap)
    {
        PrivateCacheMap = ExAllocatePool(NonPagedPool,
                                         sizeof(*PrivateCacheMap));

        FileObject->PrivateCacheMap = PrivateCacheMap;
        PrivateCacheMap->FileObject = FileObject;
        ObReferenceObject(PrivateCacheMap->FileObject);
    }

    PrivateCacheMap->Map = Map;
    InsertTailList(&Map->PrivateCacheMaps, &PrivateCacheMap->ListEntry);

    CcpUnlock();
}

/*

This function is used by NewCC's MM to determine whether any section objects
for a given file are not cache sections.  If that's true, we're not allowed
to resize the file, although nothing actually prevents us from doing ;-)

 */

ULONG
NTAPI
CcpCountCacheSections(IN PNOCC_CACHE_MAP Map)
{
    PLIST_ENTRY Entry;
    ULONG Count;

    for (Count = 0, Entry = Map->AssociatedBcb.Flink;
         Entry != &Map->AssociatedBcb;
         Entry = Entry->Flink, Count++);

    return Count;
}

BOOLEAN
NTAPI
CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
                       IN OPTIONAL PLARGE_INTEGER TruncateSize,
                       IN OPTIONAL PCACHE_UNINITIALIZE_EVENT UninitializeEvent)
{
    BOOLEAN LastMap = FALSE;
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    PNOCC_PRIVATE_CACHE_MAP PrivateCacheMap = FileObject->PrivateCacheMap;

    DPRINT("Uninitializing file object for %wZ SectionObjectPointer %x\n",
           &FileObject->FileName,
           FileObject->SectionObjectPointer);

    ASSERT(UninitializeEvent == NULL);

    /* It may not be strictly necessary to flush here, but we do just for
       kicks. */
    if (Map)
        CcpFlushCache(Map, NULL, 0, NULL, FALSE);

    CcpLock();
    /* We have a private cache map, so we've been initialized and haven't been
     * uninitialized. */
    if (PrivateCacheMap)
    {
        ASSERT(!Map || Map == PrivateCacheMap->Map);
        ASSERT(PrivateCacheMap->FileObject == FileObject);

        RemoveEntryList(&PrivateCacheMap->ListEntry);
        /* That was the last private cache map.  It's time to delete all
           cache stripes and all aspects of caching on the file. */
        if (IsListEmpty(&PrivateCacheMap->Map->PrivateCacheMaps))
        {
            /* Get rid of all the cache stripes. */
            while (!IsListEmpty(&PrivateCacheMap->Map->AssociatedBcb))
            {
                PNOCC_BCB Bcb = CONTAINING_RECORD(PrivateCacheMap->Map->AssociatedBcb.Flink,
                                                  NOCC_BCB,
                                                  ThisFileList);

                DPRINT("Evicting cache stripe #%x\n", Bcb - CcCacheSections);
                Bcb->RefCount = 1;
                CcpDereferenceCache(Bcb - CcCacheSections, TRUE);
            }
            RemoveEntryList(&PrivateCacheMap->Map->Entry);
            ExFreePool(PrivateCacheMap->Map);
            FileObject->SectionObjectPointer->SharedCacheMap = NULL;
            LastMap = TRUE;
        }
        ObDereferenceObject(PrivateCacheMap->FileObject);
        FileObject->PrivateCacheMap = NULL;
        ExFreePool(PrivateCacheMap);
    }
    CcpUnlock();

    DPRINT("Uninit complete\n");

    /* The return from CcUninitializeCacheMap means that 'caching was stopped'. */
    return LastMap;
}

/*

CcSetFileSizes is used to tell the cache manager that the file changed
size.  In our case, we use the internal Mm method MmExtendCacheSection
to notify Mm that our section potentially changed size, which may mean
truncating off data.

 */
VOID
NTAPI
CcSetFileSizes(IN PFILE_OBJECT FileObject,
               IN PCC_FILE_SIZES FileSizes)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    PNOCC_BCB Bcb;

    if (!Map) return;
    Map->FileSizes = *FileSizes;
    Bcb = Map->AssociatedBcb.Flink == &Map->AssociatedBcb ?
        NULL : CONTAINING_RECORD(Map->AssociatedBcb.Flink, NOCC_BCB, ThisFileList);
    if (!Bcb) return;
    MmExtendCacheSection(Bcb->SectionObject, &FileSizes->FileSize, FALSE);
    DPRINT("FileSizes->FileSize %x\n", FileSizes->FileSize.LowPart);
    DPRINT("FileSizes->AllocationSize %x\n", FileSizes->AllocationSize.LowPart);
    DPRINT("FileSizes->ValidDataLength %x\n", FileSizes->ValidDataLength.LowPart);
}

BOOLEAN
NTAPI
CcGetFileSizes(IN PFILE_OBJECT FileObject,
               IN PCC_FILE_SIZES FileSizes)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    if (!Map) return FALSE;
    *FileSizes = Map->FileSizes;
    return TRUE;
}

BOOLEAN
NTAPI
CcPurgeCacheSection(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                    IN OPTIONAL PLARGE_INTEGER FileOffset,
                    IN ULONG Length,
                    IN BOOLEAN UninitializeCacheMaps)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)SectionObjectPointer->SharedCacheMap;
    if (!Map) return TRUE;
    CcpFlushCache(Map, NULL, 0, NULL, TRUE);
    return TRUE;
}

VOID
NTAPI
CcSetDirtyPageThreshold(IN PFILE_OBJECT FileObject,
                        IN ULONG DirtyPageThreshold)
{
    UNIMPLEMENTED_DBGBREAK();
}

/*

This could be implemented much more intelligently by mapping instances
of a CoW zero page into the affected regions.  We just RtlZeroMemory
for now.

*/
BOOLEAN
NTAPI
CcZeroData(IN PFILE_OBJECT FileObject,
           IN PLARGE_INTEGER StartOffset,
           IN PLARGE_INTEGER EndOffset,
           IN BOOLEAN Wait)
{
    PNOCC_BCB Bcb = NULL;
    PLIST_ENTRY ListEntry = NULL;
    LARGE_INTEGER LowerBound = *StartOffset;
    LARGE_INTEGER UpperBound = *EndOffset;
    LARGE_INTEGER Target, End;
    PVOID PinnedBcb, PinnedBuffer;
    PNOCC_CACHE_MAP Map = FileObject->SectionObjectPointer->SharedCacheMap;

    DPRINT("S %I64x E %I64x\n",
           StartOffset->QuadPart,
           EndOffset->QuadPart);

    if (!Map)
    {
        NTSTATUS Status;
        IO_STATUS_BLOCK IOSB;
        PCHAR ZeroBuf = ExAllocatePool(PagedPool, PAGE_SIZE);
        ULONG ToWrite;

        if (!ZeroBuf) RtlRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, PAGE_SIZE);
        RtlZeroMemory(ZeroBuf, PAGE_SIZE);

        Target.QuadPart = PAGE_ROUND_DOWN(LowerBound.QuadPart);
        End.QuadPart = PAGE_ROUND_UP(UpperBound.QuadPart);

        // Handle leading page
        if (LowerBound.QuadPart != Target.QuadPart)
        {
            ToWrite = MIN(UpperBound.QuadPart - LowerBound.QuadPart,
                          (PAGE_SIZE - LowerBound.QuadPart) & (PAGE_SIZE - 1));

            DPRINT("Zero last half %I64x %lx\n",
                   Target.QuadPart,
                   ToWrite);

            Status = MiSimpleRead(FileObject,
                                  &Target,
                                  ZeroBuf,
                                  PAGE_SIZE,
                                  TRUE,
                                  &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }

            DPRINT1("RtlZeroMemory(%p, %lx)\n",
                    ZeroBuf + LowerBound.QuadPart - Target.QuadPart,
                    ToWrite);

            RtlZeroMemory(ZeroBuf + LowerBound.QuadPart - Target.QuadPart,
                          ToWrite);

            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   MIN(PAGE_SIZE,
                                       UpperBound.QuadPart-Target.QuadPart),
                                   &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, PAGE_SIZE);
        RtlZeroMemory(ZeroBuf, PAGE_SIZE);

        while (UpperBound.QuadPart - Target.QuadPart > PAGE_SIZE)
        {
            DPRINT("Zero full page %I64x\n",
                   Target.QuadPart);

            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   PAGE_SIZE,
                                   &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        if (UpperBound.QuadPart > Target.QuadPart)
        {
            ToWrite = UpperBound.QuadPart - Target.QuadPart;
            DPRINT("Zero first half %I64x %lx\n",
                   Target.QuadPart,
                   ToWrite);

            Status = MiSimpleRead(FileObject,
                                  &Target,
                                  ZeroBuf,
                                  PAGE_SIZE,
                                  TRUE,
                                  &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, ToWrite);
            RtlZeroMemory(ZeroBuf, ToWrite);
            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   MIN(PAGE_SIZE,
                                       UpperBound.QuadPart-Target.QuadPart),
                                   &IOSB);
            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        ExFreePool(ZeroBuf);
        return TRUE;
    }

    CcpLock();
    ListEntry = Map->AssociatedBcb.Flink;

    while (ListEntry != &Map->AssociatedBcb)
    {
        Bcb = CONTAINING_RECORD(ListEntry, NOCC_BCB, ThisFileList);
        CcpReferenceCache(Bcb - CcCacheSections);

        if (Bcb->FileOffset.QuadPart + Bcb->Length >= LowerBound.QuadPart &&
            Bcb->FileOffset.QuadPart < UpperBound.QuadPart)
        {
            DPRINT("Bcb #%x (@%I64x)\n",
                   Bcb - CcCacheSections,
                   Bcb->FileOffset.QuadPart);

            Target.QuadPart = MAX(Bcb->FileOffset.QuadPart,
                                  LowerBound.QuadPart);

            End.QuadPart = MIN(Map->FileSizes.ValidDataLength.QuadPart,
                               UpperBound.QuadPart);

            End.QuadPart = MIN(End.QuadPart,
                               Bcb->FileOffset.QuadPart + Bcb->Length);

            CcpUnlock();

            if (!CcPreparePinWrite(FileObject,
                                   &Target,
                                   End.QuadPart - Target.QuadPart,
                                   TRUE,
                                   Wait,
                                   &PinnedBcb,
                                   &PinnedBuffer))
            {
                return FALSE;
            }

            ASSERT(PinnedBcb == Bcb);

            CcpLock();
            ListEntry = ListEntry->Flink;
            /* Return from pin state */
            CcpUnpinData(PinnedBcb, TRUE);
        }

        CcpUnpinData(Bcb, TRUE);
    }

    CcpUnlock();

    return TRUE;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromSectionPtrs(IN PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    PFILE_OBJECT Result = NULL;
    PNOCC_CACHE_MAP Map = SectionObjectPointer->SharedCacheMap;
    CcpLock();
    if (!IsListEmpty(&Map->AssociatedBcb))
    {
        PNOCC_BCB Bcb = CONTAINING_RECORD(Map->AssociatedBcb.Flink,
                                          NOCC_BCB,
                                          ThisFileList);

        Result = MmGetFileObjectForSection((PROS_SECTION_OBJECT)Bcb->SectionObject);
    }
    CcpUnlock();
    return Result;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromBcb(PVOID Bcb)
{
    PNOCC_BCB RealBcb = (PNOCC_BCB)Bcb;
    DPRINT("BCB #%x\n", RealBcb - CcCacheSections);
    return MmGetFileObjectForSection((PROS_SECTION_OBJECT)RealBcb->SectionObject);
}

/* EOF */
