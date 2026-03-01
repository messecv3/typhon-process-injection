#pragma once

// ============================================================================
// NT Types and Structures
// ============================================================================
// Definitions for undocumented NT structures needed for PEB walking,
// syscall extraction, and other low-level operations.

#include <windows.h>
#include <winternl.h>

// ============================================================================
// PEB Structures
// ============================================================================

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    // ... more fields exist but we don't need them
} MY_PEB, *PMY_PEB;

// ============================================================================
// Thread Information Structures
// ============================================================================

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, *PMY_CLIENT_ID;

typedef struct _MY_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    MY_CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} MY_THREAD_BASIC_INFORMATION, *PMY_THREAD_BASIC_INFORMATION;

// ============================================================================
// System Information Structures (for thread enumeration)
// ============================================================================

#pragma pack(push, 8)
typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    MY_CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG ThreadState;
    ULONG WaitReason;
} MY_SYSTEM_THREAD_INFORMATION, *PMY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;
#pragma pack(pop)

// ============================================================================
// Memory Structures
// ============================================================================

typedef struct _MY_MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MY_MEMORY_BASIC_INFORMATION, *PMY_MEMORY_BASIC_INFORMATION;

// ============================================================================
// Section Structures
// ============================================================================

typedef enum _MY_SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} MY_SECTION_INHERIT;

// ============================================================================
// Common NT Function Pointer Typedefs
// ============================================================================

// Memory
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// Sections
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    MY_SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// Process/Thread
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// Timing
typedef NTSTATUS(NTAPI* NtDelayExecution_t)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

// Handles
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);

// APC
typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS(NTAPI* NtTestAlert_t)(VOID);

// VEH
typedef PVOID(NTAPI* RtlAddVectoredExceptionHandler_t)(
    ULONG First,
    PVOID Handler
);

typedef ULONG(NTAPI* RtlRemoveVectoredExceptionHandler_t)(
    PVOID Handle
);

// Function Table (for CET)
typedef BOOLEAN(NTAPI* RtlAddFunctionTable_t)(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    DWORD64 BaseAddress
);

// Version
typedef NTSTATUS(NTAPI* RtlGetVersion_t)(
    PRTL_OSVERSIONINFOW lpVersionInformation
);

// ============================================================================
// System Information Classes
// ============================================================================

#define SystemProcessInformation 5
#define ProcessDebugPort 7
#define ThreadBasicInformation 0

// ============================================================================
// Thread Pool Typedefs (ntdll)
// ============================================================================

// PTP_WORK, PTP_CALLBACK_ENVIRON, PTP_CALLBACK_INSTANCE are already defined
// in winnt.h from the Windows SDK. We only need the ntdll function typedefs.

typedef NTSTATUS(NTAPI* TpAllocWork_t)(
    PTP_WORK* WorkReturn,
    PTP_WORK_CALLBACK Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
);

typedef VOID(NTAPI* TpPostWork_t)(PTP_WORK Work);
typedef VOID(NTAPI* TpReleaseWork_t)(PTP_WORK Work);

// ============================================================================
// Fiber Typedefs (kernel32)
// ============================================================================

typedef LPVOID(WINAPI* ConvertThreadToFiber_t)(LPVOID lpParameter);
typedef LPVOID(WINAPI* CreateFiber_t)(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);
typedef VOID(WINAPI* SwitchToFiber_t)(LPVOID lpFiber);
typedef VOID(WINAPI* DeleteFiber_t)(LPVOID lpFiber);
typedef BOOL(WINAPI* ConvertFiberToThread_t)(VOID);

// ============================================================================
// Callback Injection Typedefs (user32 / kernel32)
// ============================================================================

typedef BOOL(WINAPI* EnumWindows_t)(WNDENUMPROC lpEnumFunc, LPARAM lParam);

typedef HANDLE(WINAPI* CreateEventW_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef BOOL(WINAPI* CreateTimerQueueTimer_t)(
    PHANDLE phNewTimer,
    HANDLE TimerQueue,
    WAITORTIMERCALLBACK Callback,
    PVOID Parameter,
    DWORD DueTime,
    DWORD Period,
    ULONG Flags
);
typedef BOOL(WINAPI* DeleteTimerQueueTimer_t)(HANDLE TimerQueue, HANDLE Timer, HANDLE CompletionEvent);

typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
typedef BOOL(WINAPI* SetEvent_t)(HANDLE hEvent);
typedef BOOL(WINAPI* CloseHandle_t)(HANDLE hObject);

// ============================================================================
// Timer Typedefs (ntdll — for sleep obfuscation rotation)
// ============================================================================

typedef NTSTATUS(NTAPI* NtCreateEvent_t)(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG EventType,       // 0 = NotificationEvent, 1 = SynchronizationEvent
    BOOLEAN InitialState
);

typedef NTSTATUS(NTAPI* NtSetEvent_t)(
    HANDLE EventHandle,
    PLONG PreviousState
);

typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS(NTAPI* NtCreateTimer_t)(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TimerType        // 0 = NotificationTimer, 1 = SynchronizationTimer
);

typedef NTSTATUS(NTAPI* NtSetTimer_t)(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PVOID TimerApcRoutine,
    PVOID TimerContext,
    BOOLEAN ResumeTimer,
    LONG Period,
    PBOOLEAN PreviousState
);

// Thread Pool Timer (ntdll)
typedef NTSTATUS(NTAPI* TpAllocTimer_t)(
    PTP_TIMER* TimerReturn,
    PTP_TIMER_CALLBACK Callback,
    PVOID Context,
    PTP_CALLBACK_ENVIRON CallbackEnviron
);

typedef VOID(NTAPI* TpSetTimer_t)(
    PTP_TIMER Timer,
    PLARGE_INTEGER DueTime,
    ULONG Period,
    ULONG WindowLength
);

typedef VOID(NTAPI* TpReleaseTimer_t)(PTP_TIMER Timer);

typedef VOID(NTAPI* TpWaitForTimer_t)(PTP_TIMER Timer, BOOLEAN CancelPendingCallbacks);

// Context manipulation (ntdll) — for Foliage sleep technique
typedef NTSTATUS(NTAPI* NtContinue_t)(
    PCONTEXT ThreadContext,
    BOOLEAN RaiseAlert
);

typedef VOID(NTAPI* RtlCaptureContext_t)(PCONTEXT ContextRecord);

typedef NTSTATUS(NTAPI* NtSignalAndWaitForSingleObject_t)(
    HANDLE SignalHandle,
    HANDLE WaitHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);


