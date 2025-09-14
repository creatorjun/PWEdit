#include "WindowsUserManager.h"
#include <shlwapi.h>
#include <sddl.h>  // SID 처리용
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

WindowsUserManager::WindowsUserManager()
{
}

WindowsUserManager::~WindowsUserManager()
{
}

bool WindowsUserManager::isValidWindowsSystem(const std::wstring& windowsPath)
{
    if (windowsPath.empty()) {
        return false;
    }

    if (!PathFileExists(windowsPath.c_str())) {
        return false;
    }

    // 필수 시스템 파일들 확인
    std::vector<std::wstring> requiredFiles = {
        windowsPath + L"\\System32\\kernel32.dll",
        windowsPath + L"\\System32\\ntdll.dll",
        windowsPath + L"\\System32\\config\\SAM",
        windowsPath + L"\\System32\\config\\SYSTEM",
        windowsPath + L"\\System32\\config\\SOFTWARE"
    };

    for (const auto& file : requiredFiles) {
        if (!PathFileExists(file.c_str())) {
            return false;
        }
    }

    return true;
}

std::vector<std::wstring> WindowsUserManager::scanWindowsDrives()
{
    std::vector<std::wstring> windowsDrives;

    DWORD drives = GetLogicalDrives();

    for (wchar_t drive = L'A'; drive <= L'Z'; drive++) {
        if (drives & (1 << (drive - L'A'))) {
            std::wstring drivePath = std::wstring(1, drive) + L":\\";
            std::wstring windowsPath = drivePath + L"Windows";

            if (GetDriveType(drivePath.c_str()) == DRIVE_FIXED &&
                isValidWindowsSystem(windowsPath)) {

                std::wstring driveInfo = drivePath + L" (Windows)";
                windowsDrives.push_back(driveInfo);
            }
        }
    }

    return windowsDrives;
}

std::vector<WindowsUserInfo> WindowsUserManager::getLocalUsers(const std::wstring& windowsPath)
{
    if (!isValidWindowsSystem(windowsPath)) {
        return {};
    }

    std::map<std::wstring, WindowsUserInfo> userMap;

    // 1. ProfileList에서 사용자 정보 수집
    auto profileUsers = getUsersFromProfileList(windowsPath);
    for (const auto& user : profileUsers) {
        userMap[user.username] = user;
    }

    // 2. SAM에서 사용자 정보 수집 (로컬 계정)
    auto samUsers = getUsersFromSAM(windowsPath);
    for (const auto& user : samUsers) {
        if (userMap.find(user.username) != userMap.end()) {
            // 기존 정보와 병합
            userMap[user.username].isEnabled = user.isEnabled;
            userMap[user.username].isAdmin = user.isAdmin;
            userMap[user.username].sid = user.sid;
        }
        else {
            userMap[user.username] = user;
        }
    }

    // 3. Users 폴더에서 프로필 정보 보완
    std::wstring drivePath = windowsPath;
    size_t pos = drivePath.find(L"\\Windows");
    if (pos != std::wstring::npos) {
        drivePath = drivePath.substr(0, pos);
    }

    std::wstring usersPath = drivePath + L"\\Users";
    auto folderUsers = scanUsersFolder(usersPath);
    for (const auto& user : folderUsers) {
        if (userMap.find(user.username) != userMap.end()) {
            // 프로필 정보 보완
            userMap[user.username].hasProfile = true;
            userMap[user.username].profilePath = user.profilePath;
            if (!user.lastLogon.empty()) {
                userMap[user.username].lastLogon = user.lastLogon;
            }
        }
        else {
            // 새 사용자 추가 (레지스트리에 없지만 폴더는 있는 경우)
            auto newUser = user;
            newUser.hasProfile = true;
            userMap[user.username] = newUser;
        }
    }

    // 4. 비밀번호 변경 가능한 계정들만 필터링
    std::vector<WindowsUserInfo> result;
    for (const auto& pair : userMap) {
        const auto& user = pair.second;
        if (isPasswordChangeableAccount(user.username, user.sid)) {
            result.push_back(user);
        }
    }

    return result;
}

std::vector<WindowsUserInfo> WindowsUserManager::getUsersFromProfileList(const std::wstring& windowsPath)
{
    std::vector<WindowsUserInfo> users;

    std::wstring softwarePath = windowsPath + L"\\System32\\config\\SOFTWARE";
    if (!PathFileExists(softwarePath.c_str())) {
        return users;
    }

    // SOFTWARE 하이브 로드
    LONG result = RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSOFTWARE", softwarePath.c_str());
    if (result != ERROR_SUCCESS) {
        return users;
    }

    HKEY hKey;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"TempSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t sidName[256];
        DWORD sidNameSize = sizeof(sidName) / sizeof(wchar_t);

        while (RegEnumKeyEx(hKey, index, sidName, &sidNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hProfileKey;
            if (RegOpenKeyEx(hKey, sidName, 0, KEY_READ, &hProfileKey) == ERROR_SUCCESS) {
                // ProfileImagePath에서 사용자명 추출
                std::wstring profilePath = readRegistryString(hProfileKey, L"ProfileImagePath");

                if (!profilePath.empty()) {
                    size_t pos = profilePath.find_last_of(L"\\");
                    if (pos != std::wstring::npos) {
                        WindowsUserInfo userInfo;
                        userInfo.username = profilePath.substr(pos + 1);
                        userInfo.profilePath = profilePath;
                        userInfo.sid = sidName;
                        userInfo.hasProfile = PathFileExists(profilePath.c_str());
                        userInfo.isEnabled = true;
                        userInfo.isAdmin = isAdministratorAccount(userInfo.username);
                        userInfo.accountType = L"로컬";

                        // FullProfile 값 확인
                        DWORD fullProfile = readRegistryDWORD(hProfileKey, L"FullProfile", 0);
                        if (fullProfile == 1) {
                            users.push_back(userInfo);
                        }
                    }
                }

                RegCloseKey(hProfileKey);
            }

            sidNameSize = sizeof(sidName) / sizeof(wchar_t);
            index++;
        }

        RegCloseKey(hKey);
    }

    // 하이브 언로드
    RegUnLoadKey(HKEY_LOCAL_MACHINE, L"TempSOFTWARE");

    return users;
}

std::vector<WindowsUserInfo> WindowsUserManager::getUsersFromSAM(const std::wstring& windowsPath)
{
    std::vector<WindowsUserInfo> users;

    std::wstring samPath = windowsPath + L"\\System32\\config\\SAM";
    if (!PathFileExists(samPath.c_str())) {
        return users;
    }

    // SAM 하이브 로드
    LONG result = RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM", samPath.c_str());
    if (result != ERROR_SUCCESS) {
        return users;
    }

    HKEY hKey;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"TempSAM\\SAM\\Domains\\Account\\Users\\Names",
        0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t username[256];
        DWORD usernameSize = sizeof(username) / sizeof(wchar_t);

        while (RegEnumKeyEx(hKey, index, username, &usernameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            WindowsUserInfo userInfo;
            userInfo.username = username;
            userInfo.accountType = L"로컬";
            userInfo.isEnabled = true; // SAM에서 정확한 상태는 더 복잡한 분석 필요
            userInfo.isAdmin = isAdministratorAccount(username);
            userInfo.hasProfile = false; // ProfileList에서 보완됨

            users.push_back(userInfo);

            usernameSize = sizeof(username) / sizeof(wchar_t);
            index++;
        }

        RegCloseKey(hKey);
    }

    // 하이브 언로드
    RegUnLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM");

    return users;
}

std::vector<WindowsUserInfo> WindowsUserManager::scanUsersFolder(const std::wstring& usersPath)
{
    std::vector<WindowsUserInfo> users;

    if (!PathFileExists(usersPath.c_str())) {
        return users;
    }

    WIN32_FIND_DATA findData;
    std::wstring searchPath = usersPath + L"\\*";
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(findData.cFileName, L".") != 0 &&
                wcscmp(findData.cFileName, L"..") != 0) {

                std::wstring userProfilePath = usersPath + L"\\" + findData.cFileName;
                WindowsUserInfo userInfo = analyzeUserProfile(userProfilePath);
                userInfo.username = findData.cFileName;
                userInfo.hasProfile = true;

                users.push_back(userInfo);
            }
        } while (FindNextFile(hFind, &findData));
        FindClose(hFind);
    }

    return users;
}

WindowsUserInfo WindowsUserManager::analyzeUserProfile(const std::wstring& profilePath)
{
    WindowsUserInfo userInfo;
    userInfo.profilePath = profilePath;
    userInfo.isEnabled = true;
    userInfo.isAdmin = false;
    userInfo.accountType = L"로컬";

    // 폴더명에서 사용자명 추출
    size_t pos = profilePath.find_last_of(L"\\");
    std::wstring folderName = (pos != std::wstring::npos) ?
        profilePath.substr(pos + 1) : profilePath;

    // Administrator 계정 감지
    if (isAdministratorAccount(folderName)) {
        userInfo.isAdmin = true;
        userInfo.fullName = L"내장 관리자 계정";
    }

    if (!PathFileExists(profilePath.c_str())) {
        userInfo.isEnabled = false;
        return userInfo;
    }

    // NTUSER.DAT 파일 확인
    std::wstring ntuserPath = profilePath + L"\\NTUSER.DAT";
    if (PathFileExists(ntuserPath.c_str())) {
        WIN32_FIND_DATA findData;
        HANDLE hFind = FindFirstFile(ntuserPath.c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            SYSTEMTIME st;
            FileTimeToSystemTime(&findData.ftLastWriteTime, &st);

            wchar_t timeStr[64];
            wsprintf(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            userInfo.lastLogon = timeStr;

            FindClose(hFind);
        }
    }

    return userInfo;
}

bool WindowsUserManager::isAdministratorAccount(const std::wstring& username)
{
    // Administrator로 시작하는 모든 계정 인식
    if (_wcsnicmp(username.c_str(), L"Administrator", 13) == 0) {
        return true;
    }

    // 관리자 계정 패턴들
    std::vector<std::wstring> adminPatterns = {
        L"Admin"
    };

    for (const auto& pattern : adminPatterns) {
        if (username.find(pattern) == 0) {
            return true;
        }
    }

    return false;
}

bool WindowsUserManager::isSystemAccount(const std::wstring& username, const std::wstring& sid)
{
    // 시스템 계정들 (비밀번호 변경 불가)
    std::vector<std::wstring> systemAccounts = {
        L"SYSTEM", L"LOCAL SERVICE", L"NETWORK SERVICE",
        L"Authenticated Users", L"INTERACTIVE", L"Everyone"
    };

    for (const auto& sysAccount : systemAccounts) {
        if (_wcsicmp(username.c_str(), sysAccount.c_str()) == 0) {
            return true;
        }
    }

    // SID 기반 시스템 계정 판별
    if (!sid.empty()) {
        // S-1-5-18 (SYSTEM), S-1-5-19 (LOCAL SERVICE), S-1-5-20 (NETWORK SERVICE)
        if (sid == L"S-1-5-18" || sid == L"S-1-5-19" || sid == L"S-1-5-20") {
            return true;
        }
    }

    return false;
}

bool WindowsUserManager::isPasswordChangeableAccount(const std::wstring& username, const std::wstring& sid)
{
    // 시스템 계정은 제외
    if (isSystemAccount(username, sid)) {
        return false;
    }

    // 특별한 계정들 제외
    std::vector<std::wstring> excludeAccounts = {
        L"Public", L"Default", L"Default User", L"All Users"
    };

    for (const auto& exclude : excludeAccounts) {
        if (_wcsicmp(username.c_str(), exclude.c_str()) == 0) {
            return false;
        }
    }

    // 그 외 모든 계정은 비밀번호 변경 가능
    return true;
}

std::wstring WindowsUserManager::readRegistryString(HKEY hKey, const std::wstring& valueName)
{
    DWORD dataSize = 0;
    LONG result = RegQueryValueEx(hKey, valueName.c_str(), nullptr, nullptr, nullptr, &dataSize);

    if (result == ERROR_SUCCESS && dataSize > 0) {
        std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t));
        result = RegQueryValueEx(hKey, valueName.c_str(), nullptr, nullptr,
            (LPBYTE)buffer.data(), &dataSize);

        if (result == ERROR_SUCCESS) {
            return std::wstring(buffer.data());
        }
    }

    return L"";
}

DWORD WindowsUserManager::readRegistryDWORD(HKEY hKey, const std::wstring& valueName, DWORD defaultValue)
{
    DWORD value = defaultValue;
    DWORD dataSize = sizeof(DWORD);
    RegQueryValueEx(hKey, valueName.c_str(), nullptr, nullptr, (LPBYTE)&value, &dataSize);
    return value;
}
