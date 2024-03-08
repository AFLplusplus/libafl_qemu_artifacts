#include <iostream>
#include <cassert>

#include <windows.h>
#include <initguid.h>
#include <virtdisk.h>
#include <io.h>
#include <string.h>

#ifdef USE_NYX
#include "libloaderapi.h"
#include "nyx_api.h"
#else
#include "libafl_exit.h"
#endif

#pragma comment(lib, "virtdisk.lib")
#pragma comment(lib, "mpr.lib")

// {A36180F4-65BE-4E0E-AA2A-B2D449D4B056}
static const GUID GUID_VHD_FUZZ =
{ 0xa36180f4, 0x65be, 0x4e0e, { 0xaa, 0x2a, 0xb2, 0xd4, 0x49, 0xd4, 0xb0, 0x56 } };

#define WIDE2(x) L##x
#define WIDE1(x) WIDE2(x)
#define WIDE(x) WIDE1(x)

#define INPUT_MAX_SIZE (256 << 20)
#define CREATE_VHD  false
#define LOAD_VHD_NAME "\\ref.vhd"
#define LOAD_VHD_NAME_W WIDE(LOAD_VHD_NAME)
#define TARGET_VHD_PATH "V:\\ref.vhd"
#define TARGET_VHD_PATH_W WIDE(TARGET_VHD_PATH)

#define READ_VHD_PATH_LEN 512
WCHAR read_vhd_path[READ_VHD_PATH_LEN];

#ifdef USE_NYX
__declspec(align(4096)) uint8_t input[INPUT_MAX_SIZE + sizeof(kAFL_payload)];
#else
__declspec(align(4096)) uint8_t input[INPUT_MAX_SIZE];
#endif

static_assert(INPUT_MAX_SIZE % 512 == 0, "The input max size must be a multiple of 512.");

// Taken from https://stackoverflow.com/a/17387176
//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

void target_init() {
    DWORD ret;

    ret = GetCurrentDirectory(READ_VHD_PATH_LEN, read_vhd_path);

    if (ret == 0) {
        std::cout << "Error: " << GetLastErrorAsString() << std::endl;
        exit(1);
    }

    assert(ret + wcslen(LOAD_VHD_NAME_W) + 1 < READ_VHD_PATH_LEN);
    wcscpy(read_vhd_path + ret, LOAD_VHD_NAME_W);

    std::wcout << L"Copy ref.vhd from " << read_vhd_path << " to " << TARGET_VHD_PATH_W << std::endl;

    bool ret_copy = CopyFile(
        read_vhd_path,
        TARGET_VHD_PATH_W,
        false
    );

    if (!ret_copy) {
        std::cout << "Copy error: " << GetLastErrorAsString() << std::endl;
        exit(1);
    }

    // Make sure everything is mapped correctly in memory.
    for (UINT64 i = 0; i < INPUT_MAX_SIZE; i += 4096) {
        input[i] = 'A';
    }
}

#ifdef USE_NYX
void nyx_init() {
    hprintf("Initiate fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // Submit our CR3
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // Tell KAFL we're running in 64bit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilites (not optional) */
    volatile host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    if (host_config.host_magic != NYX_HOST_MAGIC ||
        host_config.host_version != NYX_HOST_VERSION) {
        hprintf("host_config magic/version mismatch!\n");
        habort("GET_HOST_CNOFIG magic/version mismatch!\n");
    }
    hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
    hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
    hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* reserved guest memory must be at least as large as host SHM view */
    if (INPUT_MAX_SIZE < host_config.payload_buffer_size) {
        habort("Insufficient guest payload buffer!\n");
    }

    /* submit agent configuration */
    volatile agent_config_t agent_config = { 0 };
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;

    agent_config.agent_tracing = 0; // trace by host!
    agent_config.agent_ijon_tracing = 0; // no IJON
    agent_config.agent_non_reload_mode = 1; // allow persistent
    agent_config.coverage_bitmap_size = host_config.bitmap_size;

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
}
#endif

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
#ifdef _WIN64
    ULONG				Reserved3;
#endif
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

void set_ip_range() {
    char target_drivers[][MAXIMUM_FILENAME_LENGTH] = {
        "Ntfs",
        "Fs_Rec",
        "partmgr.sys",
        "\\disk.sys",
        "volmgr.sys",
        "mountmgr.sys",
        "ACPI.sys",
        // "win32k.sys",
        // "win32kbase.sys",
        // "volume.sys",
        // "\\disk.sys"
    };

    UINT64 min_addr = 0;
    UINT64 max_addr = 0;
    UINT64 nb_modules_to_find = sizeof(target_drivers) / MAXIMUM_FILENAME_LENGTH;
    UINT64 nb_modules_found = 0;

    HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
    PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (query == NULL) {
        printf("GetProcAddress() failed.\n");
        return;
    }
    ULONG len = 0;
    query(SystemModuleInformation, NULL, 0, &len);

    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
    if (pModuleInfo == NULL) {
        printf("Could not allocate memory for module info.\n");
        return;
    }
    NTSTATUS status = query(SystemModuleInformation, pModuleInfo, len, &len);

    if (status != (NTSTATUS)0x0) {
        printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
        return;
    }
    for (unsigned int i = 0; i < pModuleInfo->ModulesCount; i++) {
        UINT64 kernelImageBase = (UINT64) pModuleInfo->Modules[i].ImageBaseAddress;
        PCHAR kernelImage = (PCHAR)pModuleInfo->Modules[i].Name;
        ULONG kernelImageLen = (ULONG)pModuleInfo->Modules[i + 1].ImageSize;

        printf("Mod name %s ", kernelImage);
#ifdef _WIN64
        printf("Base Addr 0x%llx Size %lx\r\n", (ULONGLONG)kernelImageBase, kernelImageLen);
#else
        printf("Base Addr 0x%X Size 0x%lx\r\n", kernelImageBase, kernelImageLen);
#endif
        for (unsigned int j = 0; j < nb_modules_to_find; j++) {
            if (strstr(kernelImage, target_drivers[j])) {
                printf("\tAdding %s to IP range.\n", kernelImage);
#ifdef USE_NYX
                hprintf("Found module %u\n", j);
#endif
                nb_modules_found++;

                if (kernelImageBase < min_addr || min_addr == 0) {
                    min_addr = kernelImageBase;
                }

                if (kernelImageBase + kernelImageLen > max_addr || max_addr == 0) {
                    max_addr = kernelImageBase + kernelImageLen;
                }
            }
        }
    }

    if (min_addr == 0 || max_addr == 0) {
        printf("Kernel driver not found.\n");
        exit(1);
    }

    if (min_addr > max_addr) {
        printf("Error: addr range not correct.\n");
        exit(1);
    }

#ifdef USE_NYX
    hprintf("Nb modules in range: %llu\n", nb_modules_found);
#endif

    if (nb_modules_found != nb_modules_to_find) {
        printf("Error: module(s) were not found.\n");
        exit(1);
    }

    uint64_t range[3];
    range[0] = (UINT64)min_addr;
    range[1] = (UINT64)max_addr;
    range[2] = 0;
#ifdef USE_NYX
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)range);
#else
    LIBAFL_EXIT_VADDR_FILTER_ALLOW(min_addr, max_addr);
#endif
}

bool target_run(uint8_t* buf, uint64_t len) {
    DWORD lenWritten;
    DWORD ret;
    HANDLE vhdHandle;
    VIRTUAL_STORAGE_TYPE storageType;
    OPEN_VIRTUAL_DISK_PARAMETERS openParameters;
    WCHAR physicalPath[MAX_PATH];
    DWORD pathSize = MAX_PATH;

    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
    storageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

    openParameters.Version = OPEN_VIRTUAL_DISK_VERSION_2;
    openParameters.Version2.GetInfoOnly = false;
    openParameters.Version2.ReadOnly = false;
    openParameters.Version2.ResiliencyGuid = GUID_NULL;

    HANDLE hVhdFile = CreateFile(
        TARGET_VHD_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hVhdFile == INVALID_HANDLE_VALUE) {
        std::cout << "Open error: " << GetLastErrorAsString() << std::endl;
        return false;
    }

    if (!WriteFile(hVhdFile, buf, (DWORD) len, &lenWritten, NULL)) {
        std::cout << "Write error: " << GetLastErrorAsString() << std::endl;
        return false;
    }

    CloseHandle(hVhdFile);

    ret = OpenVirtualDisk(
        &storageType,
        TARGET_VHD_PATH_W,
        VIRTUAL_DISK_ACCESS_ATTACH_RW | VIRTUAL_DISK_ACCESS_GET_INFO,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        NULL,
        &vhdHandle
    );

    if (ret != ERROR_SUCCESS) {
        std::string err = GetLastErrorAsString();
        std::cout << "Open error " << ret << ": " << err << std::endl;
#ifdef USE_NYX
        hprintf("open error %d: %s\n", ret, err.c_str());
#endif
        return false;
    } else {
#ifdef USE_NYX
        // hprintf("open success\n");
#endif
    }

    ATTACH_VIRTUAL_DISK_PARAMETERS vhdAttachParams;
    vhdAttachParams.Version = ATTACH_VIRTUAL_DISK_VERSION_2;
    vhdAttachParams.Version2.RestrictedLength = 0;
    vhdAttachParams.Version2.RestrictedOffset = 0;

    ret = AttachVirtualDisk(
        vhdHandle,
        NULL,
        ATTACH_VIRTUAL_DISK_FLAG_NONE,
        0,
        &vhdAttachParams,
        NULL
    );

    if (ret != ERROR_SUCCESS) {
#ifdef USE_NYX
        hprintf("attach error\n");
#endif
        std::cout << "Attach error " << ret << ": " << GetLastErrorAsString() << std::endl;
        return false;
    } else {
#ifdef USE_NYX
        // hprintf("attach success\n");
#endif
    }

    ret = GetVirtualDiskPhysicalPath(vhdHandle, &pathSize, physicalPath);

    // std::wcout << L"Path: " << physicalPath << std::endl;

    if (ret != ERROR_SUCCESS) {
#ifdef USE_NYX
        hprintf("get vdisk error\n");
#endif
        std::cout << "Get virtual disk physical path error " << ret << ": " << GetLastErrorAsString() << std::endl;
        DetachVirtualDisk(vhdHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(vhdHandle);
        return false;
    }
    else {
#ifdef USE_NYX
        // hprintf("get vdisk success\n");
#endif
    }

    if (!DefineDosDevice(DDD_RAW_TARGET_PATH, L"R:", physicalPath)) {
#ifdef USE_NYX
        hprintf("define dos device error\n");
#endif
        std::cerr << "Define DOS device error: " << ret << ": " << GetLastErrorAsString() << std::endl;
        DetachVirtualDisk(vhdHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(vhdHandle);
        return false;
    }
    else {
#ifdef USE_NYX
        // hprintf("define dos device success\n");
#endif
    }

#ifdef USE_NYX
    // hprintf("End of target\n");
#endif

    return true;
}

int main()
{
    uint8_t* payload;
    uint64_t payload_len;

    set_ip_range();

    target_init();

#ifdef USE_NYX
    std::cout << "Using NYX fuzzing" << std::endl;

    kAFL_payload* payload_buffer = (kAFL_payload*)input;

    nyx_init();
   
    /* this hypercall submits the current CR3 value */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
   
    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)input);
    
    // Submit PT ranges
    set_ip_range();

    // Snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

    /* request new payload (*blocking*) */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    payload = payload_buffer->data;
    payload_len = payload_buffer->size;
#else
    std::cout << "Using LibAFL QEMU fuzzing" << std::endl;

    set_ip_range();
    payload_len = _libafl_exit_call2(LIBAFL_EXIT_START_VIRT, (UINT64)input, INPUT_MAX_SIZE);

    payload = input;
#endif

    //std::cout << "Start done." << std::endl;
    //std::cout << "Input of length " << payload_len << std::endl;

    target_run(payload, payload_len);

    // Will reset back to start of snapshot here
#ifdef USE_NYX
    /* inform fuzzer about finished fuzzing iteration */
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#else
    _libafl_exit_call1(LIBAFL_EXIT_END, LIBAFL_EXIT_END_OK);
#endif
}
