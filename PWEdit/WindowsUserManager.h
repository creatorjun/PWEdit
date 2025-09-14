#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>

struct WindowsUserInfo {
    std::wstring username;
    std::wstring fullName;
    std::wstring profilePath;
    std::wstring sid;
    bool isEnabled;
    bool isAdmin;
    bool hasProfile;
    std::wstring lastLogon;
    std::wstring accountType;
};

class WindowsUserManager
{
public:
    WindowsUserManager();
    ~WindowsUserManager();

    bool isValidWindowsSystem(const std::wstring& windowsPath);
    std::vector<WindowsUserInfo> getLocalUsers(const std::wstring& windowsPath);
    std::vector<std::wstring> scanWindowsDrives();

private:
    // 실제 구현된 함수들만 선언
    std::vector<WindowsUserInfo> getUsersFromProfileList(const std::wstring& windowsPath);
    std::vector<WindowsUserInfo> getUsersFromSAM(const std::wstring& windowsPath);
    std::vector<WindowsUserInfo> scanUsersFolder(const std::wstring& usersPath);
    WindowsUserInfo analyzeUserProfile(const std::wstring& profilePath);

    bool isSystemAccount(const std::wstring& username, const std::wstring& sid);
    bool isAdministratorAccount(const std::wstring& username);
    bool isPasswordChangeableAccount(const std::wstring& username, const std::wstring& sid);

    std::wstring readRegistryString(HKEY hKey, const std::wstring& valueName);
    DWORD readRegistryDWORD(HKEY hKey, const std::wstring& valueName, DWORD defaultValue = 0);
};