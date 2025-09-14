#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include "MainWindow.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // COM 초기화
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // Common Controls 초기화
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    // 메인 윈도우 생성 및 실행
    MainWindow mainWindow(hInstance);
    int result = mainWindow.Run(nCmdShow);

    CoUninitialize();
    return result;
}
