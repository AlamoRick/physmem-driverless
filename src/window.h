#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

#define PHYS_WINDOW_BASE 0x80000000000ULL

bool SetupPhysWindow(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets);

ULONG64 WindowRead64(ULONG64 physAddr);
ULONG WindowRead32(ULONG64 physAddr);
void WindowReadBuffer(ULONG64 physAddr, void* buffer, ULONG size);
void WindowWrite64(ULONG64 physAddr, ULONG64 value);
void WindowWriteBuffer(ULONG64 physAddr, void* buffer, ULONG size);

ULONG64 WindowVirtToPhys(ULONG64 cr3, ULONG64 virtualAddr);
void RestorePhysWindow();

bool SpoofWindowVADs(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets);
