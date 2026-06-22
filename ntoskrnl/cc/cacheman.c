/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/cacheman.c
 * PURPOSE:         Cache manager
 *
 * PROGRAMMERS:     David Welch (welch@cwcom.net)
 *                  Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

BOOLEAN CcPfEnablePrefetcher;
PFSN_PREFETCHER_GLOBALS CcPfGlobals;
MM_SYSTEMSIZE CcCapturedSystemSize;

static ULONG BugCheckFileId = 0x4 << 16;
static UNICODE_STRING CcPfRegistryKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Prefetcher");
static UNICODE_STRING CcPfRegistryValue = RTL_CONSTANT_STRING(L"BootTrace");

static VOID
CcPfFreeTraceBuffers(
    _Inout_ PPFSN_TRACE_HEADER Trace);

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

/* FUNCTIONS *****************************************************************/

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

CODE_SEG("INIT")
BOOLEAN
CcInitializeCacheManager(VOID)
{
    ULONG Thread;

    CcInitView();

    /* Initialize lazy-writer lists */
    InitializeListHead(&CcIdleWorkerThreadList);
    InitializeListHead(&CcExpressWorkQueue);
    InitializeListHead(&CcRegularWorkQueue);
    InitializeListHead(&CcPostTickWorkQueue);

    /* Define lazy writer threshold and the amount of workers,
      * depending on the system type
      */
    CcCapturedSystemSize = MmQuerySystemSize();
    switch (CcCapturedSystemSize)
    {
        case MmSmallSystem:
            CcNumberWorkerThreads = ExCriticalWorkerThreads - 1;
            CcDirtyPageThreshold = MmNumberOfPhysicalPages / 8;
            break;

        case MmMediumSystem:
            CcNumberWorkerThreads = ExCriticalWorkerThreads - 1;
            CcDirtyPageThreshold = MmNumberOfPhysicalPages / 4;
            break;

        case MmLargeSystem:
            CcNumberWorkerThreads = ExCriticalWorkerThreads - 2;
            CcDirtyPageThreshold = MmNumberOfPhysicalPages / 8 + MmNumberOfPhysicalPages / 4;
            break;

        default:
            CcNumberWorkerThreads = 1;
            CcDirtyPageThreshold = MmNumberOfPhysicalPages / 8;
            break;
    }

    /* Allocate a work item for all our threads */
    for (Thread = 0; Thread < CcNumberWorkerThreads; ++Thread)
    {
        PWORK_QUEUE_ITEM Item;

        Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'qWcC');
        if (Item == NULL)
        {
            CcBugCheck(0, 0, 0);
        }

        /* By default, it's obviously idle */
        ExInitializeWorkItem(Item, CcWorkerThread, Item);
        InsertTailList(&CcIdleWorkerThreadList, &Item->List);
    }

    /* Initialize our lazy writer */
    RtlZeroMemory(&LazyWriter, sizeof(LazyWriter));
    InitializeListHead(&LazyWriter.WorkQueue);
    /* Delay activation of the lazy writer */
    KeInitializeDpc(&LazyWriter.ScanDpc, CcScanDpc, NULL);
    KeInitializeTimer(&LazyWriter.ScanTimer);

    /* Lookaside list for our work items */
    ExInitializeNPagedLookasideList(&CcTwilightLookasideList, NULL, NULL, 0, sizeof(WORK_QUEUE_ENTRY), 'KWcC', 0);

    return TRUE;
}

VOID
NTAPI
CcShutdownSystem(VOID)
{
    CcPfShutdownPrefetcher();
}

/*
 * @unimplemented
 */
LARGE_INTEGER
NTAPI
CcGetFlushedValidData (
    IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
    IN BOOLEAN BcbListHeld
    )
{
	LARGE_INTEGER i;

	UNIMPLEMENTED;

	i.QuadPart = 0;
	return i;
}

/*
 * @unimplemented
 */
PVOID
NTAPI
CcRemapBcb (
    IN PVOID Bcb
    )
{
	UNIMPLEMENTED;

    return 0;
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcScheduleReadAhead (
	IN	PFILE_OBJECT		FileObject,
	IN	PLARGE_INTEGER		FileOffset,
	IN	ULONG			Length
	)
{
    KIRQL OldIrql;
    LARGE_INTEGER NewOffset;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    PPRIVATE_CACHE_MAP PrivateCacheMap;

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    PrivateCacheMap = FileObject->PrivateCacheMap;

    /* If file isn't cached, or if read ahead is disabled, this is no op */
    if (SharedCacheMap == NULL || PrivateCacheMap == NULL ||
        BooleanFlagOn(SharedCacheMap->Flags, READAHEAD_DISABLED))
    {
        return;
    }

    /* Round read length with read ahead mask */
    Length = ROUND_UP(Length, PrivateCacheMap->ReadAheadMask + 1);
    /* Compute the offset we'll reach */
    NewOffset.QuadPart = FileOffset->QuadPart + Length;

    /* Lock read ahead spin lock */
    KeAcquireSpinLock(&PrivateCacheMap->ReadAheadSpinLock, &OldIrql);
    /* Easy case: the file is sequentially read */
    if (BooleanFlagOn(FileObject->Flags, FO_SEQUENTIAL_ONLY))
    {
        /* If we went backward, this is no go! */
        if (NewOffset.QuadPart < PrivateCacheMap->ReadAheadOffset[1].QuadPart)
        {
            KeReleaseSpinLock(&PrivateCacheMap->ReadAheadSpinLock, OldIrql);
            return;
        }

        /* FIXME: hackish, but will do the job for now */
        PrivateCacheMap->ReadAheadOffset[1].QuadPart = NewOffset.QuadPart;
        PrivateCacheMap->ReadAheadLength[1] = Length;
    }
    /* Other cases: try to find some logic in that mess... */
    else
    {
        /* Let's check if we always read the same way (like going down in the file)
         * and pretend it's enough for now
         */
        if (PrivateCacheMap->FileOffset2.QuadPart >= PrivateCacheMap->FileOffset1.QuadPart &&
            FileOffset->QuadPart >= PrivateCacheMap->FileOffset2.QuadPart)
        {
            /* FIXME: hackish, but will do the job for now */
            PrivateCacheMap->ReadAheadOffset[1].QuadPart = NewOffset.QuadPart;
            PrivateCacheMap->ReadAheadLength[1] = Length;
        }
        else
        {
            /* FIXME: handle the other cases */
            KeReleaseSpinLock(&PrivateCacheMap->ReadAheadSpinLock, OldIrql);
            UNIMPLEMENTED_ONCE;
            return;
        }
    }

    /* If read ahead isn't active yet */
    if (!PrivateCacheMap->Flags.ReadAheadActive)
    {
        PWORK_QUEUE_ENTRY WorkItem;

        /* It's active now!
         * Be careful with the mask, you don't want to mess with node code
         */
        InterlockedOr((volatile long *)&PrivateCacheMap->UlongFlags, PRIVATE_CACHE_MAP_READ_AHEAD_ACTIVE);
        KeReleaseSpinLock(&PrivateCacheMap->ReadAheadSpinLock, OldIrql);

        /* Get a work item */
        WorkItem = ExAllocateFromNPagedLookasideList(&CcTwilightLookasideList);
        if (WorkItem != NULL)
        {
            /* Reference our FO so that it doesn't go in between */
            ObReferenceObject(FileObject);

            /* We want to do read ahead! */
            WorkItem->Function = ReadAhead;
            WorkItem->Parameters.Read.FileObject = FileObject;

            /* Queue in the read ahead dedicated queue */
            CcPostWorkQueue(WorkItem, &CcExpressWorkQueue);

            return;
        }

        /* Fail path: lock again, and revert read ahead active */
        KeAcquireSpinLock(&PrivateCacheMap->ReadAheadSpinLock, &OldIrql);
        InterlockedAnd((volatile long *)&PrivateCacheMap->UlongFlags, ~PRIVATE_CACHE_MAP_READ_AHEAD_ACTIVE);
    }

    /* Done (fail) */
    KeReleaseSpinLock(&PrivateCacheMap->ReadAheadSpinLock, OldIrql);
}

/*
 * @implemented
 */
VOID
NTAPI
CcSetAdditionalCacheAttributes (
	IN	PFILE_OBJECT	FileObject,
	IN	BOOLEAN		DisableReadAhead,
	IN	BOOLEAN		DisableWriteBehind
	)
{
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileObject=%p DisableReadAhead=%d DisableWriteBehind=%d\n",
        FileObject, DisableReadAhead, DisableWriteBehind);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    if (DisableReadAhead)
    {
        SetFlag(SharedCacheMap->Flags, READAHEAD_DISABLED);
    }
    else
    {
        ClearFlag(SharedCacheMap->Flags, READAHEAD_DISABLED);
    }

    if (DisableWriteBehind)
    {
        /* FIXME: also set flag 0x200 */
        SetFlag(SharedCacheMap->Flags, WRITEBEHIND_DISABLED);
    }
    else
    {
        ClearFlag(SharedCacheMap->Flags, WRITEBEHIND_DISABLED);
    }
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcSetBcbOwnerPointer (
	IN	PVOID	Bcb,
	IN	PVOID	Owner
	)
{
    PINTERNAL_BCB iBcb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB);

    CCTRACE(CC_API_DEBUG, "Bcb=%p Owner=%p\n",
        Bcb, Owner);

    if (!ExIsResourceAcquiredExclusiveLite(&iBcb->Lock) && !ExIsResourceAcquiredSharedLite(&iBcb->Lock))
    {
        DPRINT1("Current thread doesn't own resource!\n");
        return;
    }

    ExSetResourceOwnerPointer(&iBcb->Lock, Owner);
}

/*
 * @implemented
 */
VOID
NTAPI
CcSetDirtyPageThreshold (
	IN	PFILE_OBJECT	FileObject,
	IN	ULONG		DirtyPageThreshold
	)
{
    PFSRTL_COMMON_FCB_HEADER Fcb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileObject=%p DirtyPageThreshold=%lu\n",
        FileObject, DirtyPageThreshold);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    if (SharedCacheMap != NULL)
    {
        SharedCacheMap->DirtyPageThreshold = DirtyPageThreshold;
    }

    Fcb = FileObject->FsContext;
    if (!BooleanFlagOn(Fcb->Flags, FSRTL_FLAG_LIMIT_MODIFIED_PAGES))
    {
        SetFlag(Fcb->Flags, FSRTL_FLAG_LIMIT_MODIFIED_PAGES);
    }
}

/*
 * @implemented
 */
VOID
NTAPI
CcSetReadAheadGranularity (
	IN	PFILE_OBJECT	FileObject,
	IN	ULONG		Granularity
	)
{
    PPRIVATE_CACHE_MAP PrivateMap;

    CCTRACE(CC_API_DEBUG, "FileObject=%p Granularity=%lu\n",
        FileObject, Granularity);

    PrivateMap = FileObject->PrivateCacheMap;
    PrivateMap->ReadAheadMask = Granularity - 1;
}
