#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "WindowsUserManager.h"

// ��Ʈ�� ID ����
#define IDC_DRIVE_COMBO             1001
#define IDC_BROWSE_BUTTON           1002
#define IDC_USER_LIST               1005
#define IDC_STATUS_BAR              1006
#define IDC_PROGRESS_BAR            1007
#define IDC_SYSTEM_INFO             1008
#define IDC_USERS_GROUP             1009
#define IDC_AUTO_SCAN               1010
#define IDC_PASSWORD_CHANGE_BUTTON  1011

class UIComponents
{
public:
    UIComponents();
    ~UIComponents();

    // �ʱ�ȭ
    void Initialize(HWND hParent, HINSTANCE hInstance);

    // UI ������Ʈ
    void PopulateDriveCombo(const std::vector<std::wstring>& drives);
    void UpdateUserList(const std::vector<WindowsUserInfo>& users);
    void UpdateSystemInfo(const std::wstring& windowsPath);
    void AddManualSelection(const std::wstring& path);

    // ���� ����
    void SetStatusText(const std::wstring& text);
    void ShowProgress(bool show);
    void EnablePasswordChangeButton(bool enable);

    // ���� ��������
    std::wstring GetSelectedWindowsPath();
    std::wstring GetSelectedUser();
    HWND GetUserListHandle() const { return m_hUserList; }

    // �̺�Ʈ ó��
    void OnWindowResize();

private:
    // UI ����
    void CreateFonts();
    void CreateControls();
    void SetupListView();

    // ���̾ƿ� ����
    void AdjustListViewHeight(const std::vector<WindowsUserInfo>& users);
    void ResizeWindowToContent();

private:
    HWND m_hParent;
    HINSTANCE m_hInstance;

    // ��Ʈ
    HFONT m_hFontNormal;
    HFONT m_hFontBold;
    HFONT m_hFontSmall;

    // ��Ʈ�� �ڵ�
    HWND m_hDriveCombo;
    HWND m_hUserList;
    HWND m_hStatusBar;
    HWND m_hProgressBar;
    HWND m_hSystemInfo;
    HWND m_hPasswordChangeButton;
    HWND m_hUsersGroup;
};
