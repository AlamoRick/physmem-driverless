#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

bool CleanPiDDBCache(HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets, const wchar_t* driverFileName);

struct MmCleanupContext {
    void* mappedDriversPage;
    void* mappedIndexPage;
    ULONG64 driversPA;
    ULONG64 indexPA;
    ULONG preUnloadIndex;
    ULONG64 driversArrayPA;
    ULONG offsetInPage;
    ULONG indexOffsetInPage;
};

bool PrepareMmCleanup(HANDLE device, SyscallTable* sc,
    ULONG64 systemCr3, KernelOffsets* offsets, MmCleanupContext* ctx);

bool FinishMmCleanup(MmCleanupContext* ctx);
