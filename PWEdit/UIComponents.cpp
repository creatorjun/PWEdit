#include "UIComponents.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

UIComponents::UIComponents()
    : m_hParent(nullptr)
    , m_hInstance(nullptr)
    , m_hFontNormal(nullptr)
    , m_hFontBold(nullptr)
    , m_hFontSmall(nullptr)
    , m_hDriveCombo(nullptr)
    , m_hUserList(nullptr)
    , m_hStatusBar(nullptr)
    , m_hProgressBar(nullptr)
    , m_hSystemInfo(nullptr)
    , m_hPasswordChangeButton(nullptr)
    , m_hUsersGroup(nullptr)
{
}

UIComponents::~UIComponents()
{
    if (m_hFontNormal) DeleteObject(m_hFontNormal);
    if (m_hFontBold) DeleteObject(m_hFontBold);
    if (m_hFontSmall) DeleteObject(m_hFontSmall);
}

void UIComponents::Initialize(HWND hParent, HINSTANCE hInstance)
{
    m_hParent = hParent;
    m_hInstance = hInstance;

    CreateFonts();
    CreateControls();
    SetupListView();
}

void UIComponents::CreateFonts()
{
    m_hFontNormal = CreateFont(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");

    m_hFontBold = CreateFont(
        16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");

    m_hFontSmall = CreateFont(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
}

void UIComponents::CreateControls()
{
    // === 드라이브 선택 그룹박스 ===
    HWND hDriveGroup = CreateWindow(L"BUTTON", L"대상 Windows 시스템 선택",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        15, 10, 860, 70, m_hParent, nullptr, m_hInstance, nullptr);
    SendMessage(hDriveGroup, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    // 드라이브 라벨
    HWND hDriveLabel = CreateWindow(L"STATIC", L"Windows 시스템:",
        WS_VISIBLE | WS_CHILD | SS_LEFT | SS_CENTERIMAGE,
        30, 35, 110, 25, m_hParent, nullptr, m_hInstance, nullptr);
    SendMessage(hDriveLabel, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);

    // 드라이브 콤보박스
    m_hDriveCombo = CreateWindow(L"COMBOBOX", nullptr,
        WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
        145, 35, 450, 200, m_hParent, (HMENU)IDC_DRIVE_COMBO, m_hInstance, nullptr);
    SendMessage(m_hDriveCombo, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);

    // 폴더 선택 버튼
    HWND hBrowseBtn = CreateWindow(L"BUTTON", L"폴더 선택...",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP,
        610, 35, 100, 25, m_hParent, (HMENU)IDC_BROWSE_BUTTON, m_hInstance, nullptr);
    SendMessage(hBrowseBtn, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);

    // === 시스템 정보 그룹박스 ===
    HWND hSystemGroup = CreateWindow(L"BUTTON", L"시스템 정보",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        15, 90, 860, 60, m_hParent, nullptr, m_hInstance, nullptr);
    SendMessage(hSystemGroup, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    // 시스템 정보 텍스트
    m_hSystemInfo = CreateWindow(L"STATIC",
        L"선택된 경로: (없음)",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        30, 115, 830, 25, m_hParent, (HMENU)IDC_SYSTEM_INFO, m_hInstance, nullptr);
    SendMessage(m_hSystemInfo, WM_SETFONT, (WPARAM)m_hFontSmall, TRUE);

    // === 사용자 계정 그룹박스 ===
    m_hUsersGroup = CreateWindow(L"BUTTON", L"로컬 사용자 계정",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        15, 160, 860, 150, m_hParent, (HMENU)IDC_USERS_GROUP, m_hInstance, nullptr);
    SendMessage(m_hUsersGroup, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    // 사용자 리스트뷰
    m_hUserList = CreateWindow(WC_LISTVIEW, nullptr,
        WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL |
        WS_BORDER | WS_TABSTOP | LVS_SHOWSELALWAYS,
        30, 185, 830, 70, m_hParent, (HMENU)IDC_USER_LIST, m_hInstance, nullptr);
    SendMessage(m_hUserList, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);

    // === 비밀번호 변경 버튼 ===
    m_hPasswordChangeButton = CreateWindow(L"BUTTON", L"선택된 사용자의 비밀번호 변경",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP | WS_DISABLED,
        30, 265, 200, 30, m_hParent, (HMENU)IDC_PASSWORD_CHANGE_BUTTON, m_hInstance, nullptr);
    SendMessage(m_hPasswordChangeButton, WM_SETFONT, (WPARAM)m_hFontNormal, TRUE);

    // === 상태 표시 ===
    m_hStatusBar = CreateWindow(STATUSCLASSNAME, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, m_hParent, (HMENU)IDC_STATUS_BAR, m_hInstance, nullptr);
    SendMessage(m_hStatusBar, WM_SETFONT, (WPARAM)m_hFontSmall, TRUE);

    m_hProgressBar = CreateWindow(PROGRESS_CLASS, nullptr,
        WS_CHILD | PBS_SMOOTH,
        0, 0, 0, 0, m_hStatusBar, (HMENU)IDC_PROGRESS_BAR, m_hInstance, nullptr);
}

void UIComponents::SetupListView()
{
    ListView_SetExtendedListViewStyle(m_hUserList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM | LVCF_FMT;
    lvc.fmt = LVCFMT_LEFT;

    lvc.pszText = const_cast<LPWSTR>(L"사용자명");
    lvc.cx = 140;
    lvc.iSubItem = 0;
    ListView_InsertColumn(m_hUserList, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"프로필 경로");
    lvc.cx = 360;
    lvc.iSubItem = 1;
    ListView_InsertColumn(m_hUserList, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"마지막 로그온");
    lvc.cx = 140;
    lvc.iSubItem = 2;
    ListView_InsertColumn(m_hUserList, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"상태");
    lvc.cx = 80;
    lvc.fmt = LVCFMT_CENTER;
    lvc.iSubItem = 3;
    ListView_InsertColumn(m_hUserList, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"관리자");
    lvc.cx = 80;
    lvc.fmt = LVCFMT_CENTER;
    lvc.iSubItem = 4;
    ListView_InsertColumn(m_hUserList, 4, &lvc);
}

void UIComponents::PopulateDriveCombo(const std::vector<std::wstring>& drives)
{
    SendMessage(m_hDriveCombo, CB_RESETCONTENT, 0, 0);

    if (drives.empty()) {
        SendMessage(m_hDriveCombo, CB_ADDSTRING, 0, (LPARAM)L"Windows 시스템을 찾을 수 없습니다");
    }
    else {
        for (const auto& drive : drives) {
            SendMessage(m_hDriveCombo, CB_ADDSTRING, 0, (LPARAM)drive.c_str());
        }
        SendMessage(m_hDriveCombo, CB_SETCURSEL, 0, 0);
    }
}

void UIComponents::UpdateUserList(const std::vector<WindowsUserInfo>& users)
{
    ListView_DeleteAllItems(m_hUserList);

    // 실제 사용자 데이터 추가
    for (size_t i = 0; i < users.size(); i++) {
        const WindowsUserInfo& user = users[i];

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(user.username.c_str());
        ListView_InsertItem(m_hUserList, &lvi);

        // 프로필 경로
        std::wstring profileDisplay = user.hasProfile ? user.profilePath : L"프로필 없음";
        ListView_SetItemText(m_hUserList, static_cast<int>(i), 1, const_cast<LPWSTR>(profileDisplay.c_str()));

        // 마지막 로그온
        std::wstring lastLogon = user.lastLogon.empty() ? L"알 수 없음" : user.lastLogon;
        ListView_SetItemText(m_hUserList, static_cast<int>(i), 2, const_cast<LPWSTR>(lastLogon.c_str()));

        // 계정 상태
        std::wstring status = user.isEnabled ? L"활성화" : L"비활성화";
        ListView_SetItemText(m_hUserList, static_cast<int>(i), 3, const_cast<LPWSTR>(status.c_str()));

        // 관리자 여부
        std::wstring adminStatus = user.isAdmin ? L"예" : L"아니오";
        ListView_SetItemText(m_hUserList, static_cast<int>(i), 4, const_cast<LPWSTR>(adminStatus.c_str()));
    }

    // 최소 3줄을 위해 빈 행 추가 (선택사항)
    const int MIN_ROWS = 3;
    for (size_t i = users.size(); i < MIN_ROWS; i++) {
        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(L""); // 빈 행
        ListView_InsertItem(m_hUserList, &lvi);

        // 모든 컬럼을 빈 값으로 설정
        for (int col = 1; col < 5; col++) {
            ListView_SetItemText(m_hUserList, static_cast<int>(i), col, const_cast<LPWSTR>(L""));
        }
    }

    AdjustListViewHeight(users);
}

void UIComponents::UpdateSystemInfo(const std::wstring& windowsPath)
{
    std::wstring info = L"선택된 경로: " + windowsPath;
    SetWindowText(m_hSystemInfo, info.c_str());
}

void UIComponents::AddManualSelection(const std::wstring& path)
{
    std::wstring displayText = L"수동 선택: " + path;
    SendMessage(m_hDriveCombo, CB_ADDSTRING, 0, (LPARAM)displayText.c_str());
    SendMessage(m_hDriveCombo, CB_SETCURSEL,
        SendMessage(m_hDriveCombo, CB_GETCOUNT, 0, 0) - 1, 0);
}

void UIComponents::SetStatusText(const std::wstring& text)
{
    std::wstring statusText = L"  " + text;
    SendMessage(m_hStatusBar, SB_SETTEXT, 0, (LPARAM)statusText.c_str());
}

void UIComponents::ShowProgress(bool show)
{
    if (m_hProgressBar) {
        ShowWindow(m_hProgressBar, show ? SW_SHOW : SW_HIDE);
        if (show) {
            SendMessage(m_hProgressBar, PBM_SETMARQUEE, TRUE, 30);
        }
        else {
            SendMessage(m_hProgressBar, PBM_SETMARQUEE, FALSE, 0);
        }
    }
}

void UIComponents::EnablePasswordChangeButton(bool enable)
{
    EnableWindow(m_hPasswordChangeButton, enable ? TRUE : FALSE);
}

std::wstring UIComponents::GetSelectedWindowsPath()
{
    wchar_t selectedText[512] = { 0 }; // 널 종료 보장
    int sel = static_cast<int>(SendMessage(m_hDriveCombo, CB_GETCURSEL, 0, 0));
    if (sel == CB_ERR) return L"";

    SendMessage(m_hDriveCombo, CB_GETLBTEXT, sel, (LPARAM)selectedText);

    std::wstring selText = selectedText;
    if (selText.find(L"찾을 수 없습니다") != std::wstring::npos) {
        return L"";
    }

    if (selText.find(L"수동 선택:") == 0) {
        // 수동 선택된 경우는 별도 처리 필요
        return L""; // MainWindow에서 m_currentWindowsPath 사용
    }
    else {
        if (selText.length() >= 3 && selText[1] == L':' && selText[2] == L'\\') {
            return selText.substr(0, 3) + L"Windows";
        }
    }

    return L"";
}

std::wstring UIComponents::GetSelectedUser()
{
    int sel = ListView_GetNextItem(m_hUserList, -1, LVNI_SELECTED);
    if (sel == -1) return L"";

    wchar_t username[256] = { 0 }; // 널 종료 보장
    ListView_GetItemText(m_hUserList, sel, 0, username, 255); // 버퍼 크기 -1
    return std::wstring(username);
}

void UIComponents::OnWindowResize()
{
    if (m_hStatusBar) {
        SendMessage(m_hStatusBar, WM_SIZE, 0, 0);

        RECT rcStatus;
        GetClientRect(m_hStatusBar, &rcStatus);
        if (m_hProgressBar) {
            SetWindowPos(m_hProgressBar, nullptr,
                rcStatus.right - 220, 2, 200, rcStatus.bottom - 4,
                SWP_NOZORDER);
        }
    }
}

void UIComponents::AdjustListViewHeight(const std::vector<WindowsUserInfo>& users)
{
    const int ROW_HEIGHT = 22;
    const int HEADER_HEIGHT = 25;
    const int GROUP_MARGIN = 80; // 비밀번호 변경 버튼 공간 포함
    const int MIN_ROWS = 3;      // 최소 3줄로 변경
    const int MAX_ROWS = 15;

    int userCount = static_cast<int>(users.size());

    // 최소 3줄 보장
    int displayRows = (userCount < MIN_ROWS) ? MIN_ROWS : userCount;
    if (displayRows > MAX_ROWS) displayRows = MAX_ROWS;

    int listHeight = ROW_HEIGHT * displayRows + HEADER_HEIGHT;
    int groupHeight = listHeight + GROUP_MARGIN;

    if (m_hUsersGroup) {
        SetWindowPos(m_hUsersGroup, nullptr,
            15, 160, 860, groupHeight,
            SWP_NOZORDER);
    }

    SetWindowPos(m_hUserList, nullptr,
        30, 185, 830, listHeight,
        SWP_NOZORDER);

    // 비밀번호 변경 버튼 위치 조정
    SetWindowPos(m_hPasswordChangeButton, nullptr,
        30, 185 + listHeight + 10, 200, 30,
        SWP_NOZORDER);

    ResizeWindowToContent();
}


void UIComponents::ResizeWindowToContent()
{
    if (m_hUsersGroup) {
        RECT rcGroup;
        GetWindowRect(m_hUsersGroup, &rcGroup);
        ScreenToClient(m_hParent, (POINT*)&rcGroup.left);
        ScreenToClient(m_hParent, (POINT*)&rcGroup.right);

        RECT rcStatus;
        GetWindowRect(m_hStatusBar, &rcStatus);
        int statusHeight = rcStatus.bottom - rcStatus.top;

        int contentHeight = rcGroup.bottom + 20 + statusHeight;

        RECT rcWindow, rcClient;
        GetWindowRect(m_hParent, &rcWindow);
        GetClientRect(m_hParent, &rcClient);

        int borderHeight = (rcWindow.bottom - rcWindow.top) - (rcClient.bottom - rcClient.top);
        int totalHeight = contentHeight + borderHeight;

        int minHeight = 400;
        int maxHeight = 800;
        if (totalHeight < minHeight) totalHeight = minHeight;
        if (totalHeight > maxHeight) totalHeight = maxHeight;

        SetWindowPos(m_hParent, nullptr,
            0, 0, rcWindow.right - rcWindow.left, totalHeight,
            SWP_NOMOVE | SWP_NOZORDER);
    }
}
