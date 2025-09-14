#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include "WindowsUserManager.h"

// 컨트롤 ID 정의
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

    // 초기화
    void Initialize(HWND hParent, HINSTANCE hInstance);

    // UI 업데이트
    void PopulateDriveCombo(const std::vector<std::wstring>& drives);
    void UpdateUserList(const std::vector<WindowsUserInfo>& users);
    void UpdateSystemInfo(const std::wstring& windowsPath);
    void AddManualSelection(const std::wstring& path);

    // 상태 관리
    void SetStatusText(const std::wstring& text);
    void ShowProgress(bool show);
    void EnablePasswordChangeButton(bool enable);

    // 정보 가져오기
    std::wstring GetSelectedWindowsPath();
    std::wstring GetSelectedUser();
    HWND GetUserListHandle() const { return m_hUserList; }

    // 이벤트 처리
    void OnWindowResize();

private:
    // UI 생성
    void CreateFonts();
    void CreateControls();
    void SetupListView();

    // 레이아웃 조정
    void AdjustListViewHeight(const std::vector<WindowsUserInfo>& users);
    void ResizeWindowToContent();

private:
    HWND m_hParent;
    HINSTANCE m_hInstance;

    // 폰트
    HFONT m_hFontNormal;
    HFONT m_hFontBold;
    HFONT m_hFontSmall;

    // 컨트롤 핸들
    HWND m_hDriveCombo;
    HWND m_hUserList;
    HWND m_hStatusBar;
    HWND m_hProgressBar;
    HWND m_hSystemInfo;
    HWND m_hPasswordChangeButton;
    HWND m_hUsersGroup;
};
