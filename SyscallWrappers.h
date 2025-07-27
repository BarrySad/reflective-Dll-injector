#pragma once
#include <Windows.h>
#include <winternl.h>
#include "syscalls.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

inline LPVOID AllocateMemorySyscall(SIZE_T size, DWORD protect = PAGE_EXECUTE_READWRITE) {
    PVOID base = NULL;
    SIZE_T regionSize = size;
    NTSTATUS status = Sw3NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &base,
        0,
        &regionSize,
        MEM_RESERVE | MEM_COMMIT,
        protect
    );
    return NT_SUCCESS(status) ? base : nullptr;
}

inline BOOL ReadMemorySyscall(LPCVOID src, LPVOID dst, SIZE_T size) {
    SIZE_T bytesRead = 0;
    NTSTATUS status = Sw3NtReadVirtualMemory(
        GetCurrentProcess(),
        (PVOID)src,
        dst,
        size,
        &bytesRead
    );
    return NT_SUCCESS(status) && bytesRead == size;
}

inline BOOL ProtectMemorySyscall(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    NTSTATUS status = Sw3NtProtectVirtualMemory(
        GetCurrentProcess(),
        &address,
        &size,
        newProtect,
        oldProtect
    );
    return NT_SUCCESS(status);
}

inline BOOL FreeMemorySyscall(LPVOID address) {
    SIZE_T size = 0;
    return NT_SUCCESS(Sw3NtFreeVirtualMemory(
        GetCurrentProcess(),
        &address,
        &size,
        MEM_RELEASE
    ));
}