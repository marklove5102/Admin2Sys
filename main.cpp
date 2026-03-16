#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

using namespace std;

// Enable SeDebugPrivilege for the current process
BOOL EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL res = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return res && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// Get token from a process by PID
HANDLE GetProcessToken(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return NULL;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);
    return hToken;
}

// Returns true if the token belongs to NT AUTHORITY\SYSTEM
BOOL IsSystemToken(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0)
        return FALSE;

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser)
        return FALSE;

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        free(pTokenUser);
        return FALSE;
    }

    // Compare against the well-known SYSTEM SID (S-1-5-18)
    PSID pSystemSid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        free(pTokenUser);
        return FALSE;
    }

    BOOL isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

    FreeSid(pSystemSid);
    free(pTokenUser);
    return isSystem;
}

// Spawn a process using a duplicated SYSTEM token
BOOL SpawnProcessAsSystem(HANDLE hToken, LPCWSTR lpApp) {
    HANDLE hDupToken = NULL;
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(STARTUPINFOW);

    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
        SecurityImpersonation, TokenPrimary, &hDupToken)) {
        return FALSE;
    }

    BOOL res = CreateProcessWithTokenW(
        hDupToken,
        LOGON_WITH_PROFILE,
        lpApp,
        NULL, 0, NULL, NULL,
        &si, &pi
    );

    if (res) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hDupToken);
    return res;
}

// Target process names known to run as SYSTEM and be accessible from admin
const vector<wstring> TARGET_PROCESSES = {
    L"winlogon.exe",
    L"services.exe",
    L"svchost.exe",
    L"lsass.exe"
};

BOOL IsTargetProcess(LPCWSTR processName) {
    for (const auto& target : TARGET_PROCESSES) {
        if (_wcsicmp(processName, target.c_str()) == 0)
            return TRUE;
    }
    return FALSE;
}

int wmain() {
    if (!EnableDebugPrivilege()) {
        wcerr << L"[!] Failed to enable SeDebugPrivilege. Run as admin.\n";
        return 1;
    }
    wcout << L"[+] SeDebugPrivilege enabled.\n";

    wstring app;
    wcout << L"[>] Enter path of application to run as SYSTEM: ";
    wcin >> app;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        wcerr << L"[!] CreateToolhelp32Snapshot failed.\n";
        return 1;
    }

    PROCESSENTRY32W pe32 = {};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnap, &pe32)) {
        CloseHandle(hSnap);
        return 1;
    }

    BOOL spawned = FALSE;

    do {
        if (!IsTargetProcess(pe32.szExeFile))
            continue;

        DWORD pid = pe32.th32ProcessID;
        wcout << L"[*] Trying: " << pe32.szExeFile << L" (PID " << pid << L")\n";

        HANDLE hToken = GetProcessToken(pid);
        if (!hToken) {
            wcout << L"    [-] Could not open token.\n";
            continue;
        }

        if (!IsSystemToken(hToken)) {
            wcout << L"    [-] Not a SYSTEM token, skipping.\n";
            CloseHandle(hToken);
            continue;
        }

        wcout << L"    [+] SYSTEM token acquired. Spawning process...\n";
        spawned = SpawnProcessAsSystem(hToken, app.c_str());
        CloseHandle(hToken);

        if (spawned) {
            wcout << L"[+] Process spawned successfully.\n";
            break;
        }
        else {
            wcout << L"    [-] CreateProcessWithTokenW failed: " << GetLastError() << L"\n";
        }

    } while (Process32NextW(hSnap, &pe32));

    CloseHandle(hSnap);

    if (!spawned)
        wcerr << L"[!] Failed to spawn process as SYSTEM.\n";

    return spawned ? 0 : 1;
}
