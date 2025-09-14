#include "MainWindow.h"
#include <shlobj.h>
#include "resource.h"

// ���� �귯�� �ʱ�ȭ
HBRUSH MainWindow::s_hBackgroundBrush = nullptr;

MainWindow::MainWindow(HINSTANCE hInstance)
    : m_hInstance(hInstance)
    , m_hWnd(nullptr)
    , m_pUIComponents(std::make_unique<UIComponents>())
    , m_pUserManager(std::make_unique<WindowsUserManager>())
    , m_pPasswordChanger(std::make_unique<PasswordChanger>())
{
    // ��� �귯�� ����
    if (!s_hBackgroundBrush) {
        s_hBackgroundBrush = CreateSolidBrush(RGB(240, 240, 240));
    }
}

MainWindow::~MainWindow()
{
    // ���� �귯�ô� ���α׷� ���� �ÿ��� ����
}

int MainWindow::Run(int nCmdShow)
{
    // ������ Ŭ���� ���
    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = m_hInstance;
    wcex.hIcon = LoadIcon(nullptr, IDI_APPLICATION); // ���ҽ� ID ���� ����
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = s_hBackgroundBrush;
    wcex.lpszClassName = L"PWEditMainWindow";
    wcex.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wcex)) {
        return FALSE;
    }

    // ���� ������ ����
    m_hWnd = CreateWindow(
        L"PWEditMainWindow",
        L"PWEdit - Windows PE ��й�ȣ ���� ���� v1.0",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 400,
        nullptr, nullptr, m_hInstance, this
    );

    if (!m_hWnd) {
        return FALSE;
    }

    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);

    // ���� �� �ڵ� ����̺� ��ĵ
    PostMessage(m_hWnd, WM_COMMAND, MAKEWPARAM(IDC_AUTO_SCAN, 0), 0);

    // �޽��� ����
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK MainWindow::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    MainWindow* pThis = nullptr;

    if (message == WM_NCCREATE) {
        CREATESTRUCT* pcs = (CREATESTRUCT*)lParam;
        pThis = (MainWindow*)pcs->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->m_hWnd = hWnd;
    }
    else {
        pThis = (MainWindow*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMessage(message, wParam, lParam);
    }

    return DefWindowProc(hWnd, message, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_CREATE:
        OnCreate();
        break;

    case WM_COMMAND:
        OnCommand(wParam, lParam);
        break;

    case WM_NOTIFY:
        OnNotify(lParam);
        break;

    case WM_SIZE:
        OnSize();
        break;

    case WM_CTLCOLORSTATIC:
        return OnCtlColorStatic((HDC)wParam); // LRESULT ��ȯ

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(m_hWnd, message, wParam, lParam);
    }
    return 0;
}

void MainWindow::OnCreate()
{
    m_pUIComponents->Initialize(m_hWnd, m_hInstance);
    SetStatus(L"PWEdit ��й�ȣ ���� ���� �غ� �Ϸ�");
}

void MainWindow::OnSize()
{
    m_pUIComponents->OnWindowResize();
}

void MainWindow::OnCommand(WPARAM wParam, LPARAM lParam)
{
    switch (LOWORD(wParam)) {
    case IDC_BROWSE_BUTTON:
        BrowseFolder();
        break;
    case IDC_DRIVE_COMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE) {
            RefreshUserList();
        }
        break;
    case IDC_PASSWORD_CHANGE_BUTTON:
        OnPasswordChange();
        break;
    case IDC_AUTO_SCAN:
        ScanDrives();
        break;
    }
}

void MainWindow::OnNotify(LPARAM lParam)
{
    LPNMHDR pnmh = (LPNMHDR)lParam;
    if (pnmh->idFrom == IDC_USER_LIST && pnmh->code == LVN_ITEMCHANGED) {
        LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
        if (pnmv->uNewState & LVIS_SELECTED) {
            wchar_t username[256] = { 0 }; // �� ���� ����
            ListView_GetItemText(m_pUIComponents->GetUserListHandle(), pnmv->iItem, 0, username, 255); // ���� ũ�� -1
            SetStatus(std::wstring(L"���õ� �����: ") + username);

            // ��й�ȣ ���� ��ư Ȱ��ȭ
            m_pUIComponents->EnablePasswordChangeButton(true);
        }
    }
}

LRESULT MainWindow::OnCtlColorStatic(HDC hdc)
{
    SetBkColor(hdc, RGB(240, 240, 240));
    return (LRESULT)s_hBackgroundBrush; // ���� �귯�� ��ȯ
}

void MainWindow::ScanDrives()
{
    SetStatus(L"����̺긦 ��ĵ�ϴ� ��...");
    ShowProgress(true);

    std::vector<std::wstring> windowsDrives = m_pUserManager->scanWindowsDrives();
    m_pUIComponents->PopulateDriveCombo(windowsDrives);

    if (windowsDrives.empty()) {
        SetStatus(L"Windows �ý����� ã�� �� �����ϴ�.");
    }
    else {
        SetStatus(std::wstring(L"PWEdit: ") + std::to_wstring(windowsDrives.size()) + L"���� Windows �ý����� ã�ҽ��ϴ�.");
        RefreshUserList();
    }

    ShowProgress(false);
}

void MainWindow::BrowseFolder()
{
    BROWSEINFO bi = { 0 };
    bi.hwndOwner = m_hWnd;
    bi.lpszTitle = L"Windows ������ �����ϼ���";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH] = { 0 }; // �� ���� ����
        if (SHGetPathFromIDList(pidl, path)) {
            if (m_pUserManager->isValidWindowsSystem(path)) {
                m_currentWindowsPath = path;
                m_pUIComponents->UpdateSystemInfo(path);
                m_pUIComponents->AddManualSelection(path);
                RefreshUserList();
                SetStatus(L"Windows �ý����� ���õǾ����ϴ�.");
            }
            else {
                MessageBox(m_hWnd,
                    L"���õ� ������ ��ȿ�� Windows �ý����� �ƴմϴ�.\nWindows ������ �����ߴ��� Ȯ���ϼ���.",
                    L"PWEdit - ���", MB_OK | MB_ICONWARNING);
            }
        }
        CoTaskMemFree(pidl);
    }
}

void MainWindow::RefreshUserList()
{
    std::wstring windowsPath = m_pUIComponents->GetSelectedWindowsPath();
    if (windowsPath.empty()) {
        windowsPath = m_currentWindowsPath; // ���� ���õ� ��� ���
    }

    if (windowsPath.empty()) return;

    m_currentWindowsPath = windowsPath;
    m_pUIComponents->UpdateSystemInfo(windowsPath);

    SetStatus(L"����� ������ �˻��ϴ� ��...");
    ShowProgress(true);

    std::vector<WindowsUserInfo> users = m_pUserManager->getLocalUsers(windowsPath);
    m_pUIComponents->UpdateUserList(users);
    m_pUIComponents->EnablePasswordChangeButton(false); // ����� ���� ������ ��Ȱ��ȭ

    ShowProgress(false);
    SetStatus(std::wstring(L"PWEdit: ") + std::to_wstring(users.size()) + L"���� ����� ������ ã�ҽ��ϴ�.");
}

void MainWindow::OnPasswordChange()
{
    std::wstring selectedUser = m_pUIComponents->GetSelectedUser();
    if (selectedUser.empty()) {
        MessageBox(m_hWnd, L"����ڸ� �������ּ���.", L"PWEdit - �˸�", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // ��й�ȣ ���� ���̾�α� ǥ��
    bool result = m_pPasswordChanger->ShowPasswordChangeDialog(m_hWnd, m_currentWindowsPath, selectedUser);

    if (result) {
        SetStatus(L"��й�ȣ�� ���������� ����Ǿ����ϴ�.");
        MessageBox(m_hWnd,
            L"��й�ȣ�� ���������� ����Ǿ����ϴ�!\n�ý����� ������ϰ� �� ��й�ȣ�� �α����ϼ���.",
            L"PWEdit - ����", MB_OK | MB_ICONINFORMATION);
    }
}

void MainWindow::SetStatus(const std::wstring& text)
{
    m_pUIComponents->SetStatusText(text);
}

void MainWindow::ShowProgress(bool show)
{
    m_pUIComponents->ShowProgress(show);
}
