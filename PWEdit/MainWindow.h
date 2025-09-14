#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include "UIComponents.h"
#include "WindowsUserManager.h"
#include "PasswordChanger.h"

class MainWindow
{
public:
    MainWindow(HINSTANCE hInstance);
    ~MainWindow();

    int Run(int nCmdShow);

private:
    // ������ ���ν���
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    // �̺�Ʈ �ڵ鷯
    void OnCreate();
    void OnSize();
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnNotify(LPARAM lParam);
    LRESULT OnCtlColorStatic(HDC hdc); // void���� LRESULT�� ����

    // ����Ͻ� ����
    void ScanDrives();
    void BrowseFolder();
    void RefreshUserList();
    void OnPasswordChange();

    // ���� �Լ�
    void SetStatus(const std::wstring& text);
    void ShowProgress(bool show);

private:
    HINSTANCE m_hInstance;
    HWND m_hWnd;
    std::wstring m_currentWindowsPath;

    // ���� �귯�� (�޸� ���� ����)
    static HBRUSH s_hBackgroundBrush;

    // ������Ʈ��
    std::unique_ptr<UIComponents> m_pUIComponents;
    std::unique_ptr<WindowsUserManager> m_pUserManager;
    std::unique_ptr<PasswordChanger> m_pPasswordChanger;
};
