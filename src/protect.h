#pragma once
#include <windows.h>
#include "syscalls.h"
#include "symbols.h"

bool ImpersonateSystem();
bool SetProcessPPL(HANDLE device, SyscallTable* sc, ULONG64 systemCr3, KernelOffsets* offsets);
bool LockProcessDACL();
