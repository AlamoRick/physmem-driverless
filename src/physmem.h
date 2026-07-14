#pragma once
#include <windows.h>
#include "syscalls.h"

#define IOCTL_MAP_PHYS   0x0022E008
#define IOCTL_UNMAP_PHYS 0x0022E00C

#pragma pack(push, 1)
struct MapPhysInput {
    ULONG64 physicalAddress;
    ULONG64 size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UnmapPhysInput {
    ULONG64 mappedAddress;
};
#pragma pack(pop)

void* PhysMap(HANDLE device, SyscallTable* sc, ULONG64 physAddr, ULONG size);
void PhysUnmap(HANDLE device, SyscallTable* sc, void* mappedAddr);

ULONG64 PhysRead64(HANDLE device, SyscallTable* sc, ULONG64 physAddr);
ULONG PhysRead32(HANDLE device, SyscallTable* sc, ULONG64 physAddr);
bool PhysReadBuffer(HANDLE device, SyscallTable* sc, ULONG64 physAddr, void* buffer, ULONG size);
bool PhysWrite64(HANDLE device, SyscallTable* sc, ULONG64 physAddr, ULONG64 value);
bool PhysWriteBuffer(HANDLE device, SyscallTable* sc, ULONG64 physAddr, void* buffer, ULONG size);

ULONG64 VirtToPhys(HANDLE device, SyscallTable* sc, ULONG64 cr3, ULONG64 virtualAddr);
ULONG64 FindSystemCr3(HANDLE device, SyscallTable* sc, ULONG64 ntoskrnlBase);
