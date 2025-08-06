#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <time.h>
#include <commctrl.h> //窗口控件，备用
#include <process.h>  //多线程
#include <stdbool.h>
#include <locale.h>
#include "cJSON.h"
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

#define BUFSIZE 1024
#define SHA256_LEN 32
#define WM_APP_LOG_MESSAGE (WM_APP + 1)

HWND hWnd;
HWND hEdit;
HANDLE hConsoleOutput;
int num;
FILE *file;
char url[1024];
char outputFileName[256];
char cwd[1024];
bool g_bRunning = true;
HANDLE hMutex;  // 用于线程同步
bool g_bWindowReady = false;

void process_downloads(cJSON *download_array);
void process_copies(cJSON *copy_array);
void process_deletes(cJSON *delete_array);
BOOL verify_sha256(const char *file_path, const char *expected_hash);
char* calculate_sha256(const char *file_path);
HRESULT download_file(const char *url, const char *temp_path, const char *final_path, const char *sha256);

void InitGUI();
void LogMessage(const char* format, ...);
void AppendToEditControl(const wchar_t* text);
void InitGUI();
void LogMessage(const char* format, ...);

//图形进程
unsigned __stdcall WindowThread(void* pArg) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    InitGUI();  //GUI初始化

    //通知主线程窗口已就绪
    g_bWindowReady = true;

    MSG msg;
    while (g_bRunning) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                g_bRunning = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        //防止CPU占用过高，
        Sleep(10);
    }

    CoUninitialize();
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    _wsetlocale(LC_ALL, L"zh_CN.UTF-8");
    SetConsoleOutputCP(65001);

    //互斥
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if (!hMutex) {
        MessageBoxW(NULL, L"WARN:创建互斥量失败", L"错误", MB_ICONERROR);
        return 1;
    }
    //窗口线程
    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, WindowThread, NULL, 0, NULL);
    if (!hThread) {
        MessageBoxW(NULL, L"WARN:GUI线程创建失败", L"错误", MB_ICONERROR);
        CloseHandle(hMutex);
        return 1;
    }
    //等待窗口初始化
    while (!g_bWindowReady) {
        Sleep(100);
    }

    //确保窗口创建成功
    int waitCount = 0;
    while (hWnd == NULL && waitCount < 50) {  //等5秒
        Sleep(100);
        waitCount++;
    }

    if (hWnd == NULL) {
        MessageBoxW(NULL, L"WARN:窗口创建超时", L"错误", MB_ICONERROR);
        g_bRunning = false;
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hMutex);
        return 1;
    }
    AllocConsole();

    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    LogMessage("已启动更新检查程序\n");
    LogMessage("当前版本v1.2.2\n");
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        LogMessage("请注意，程序当前工作在这个目录==> %s\n", cwd);
        LogMessage("如果您在非minecraft版本目录执行该程序，可能造成其他不可预料的后果！\n");
    } else {
        perror("getcwd() 获取工作目录失败，为安全起见，本更新程序将会退出以保护您的系统，请您手动检查程序运行目录。");
        return 10;
    }

    LogMessage("正在尝试连接硬编码更新服务器地址\n");
    char json_full_url[2048];
    srand((unsigned int)time(NULL)); //时间种子生成器
        //硬编码url
        const char* json_url = "https://web.nyauru.cn/update.json";
        sprintf(json_full_url, "%s?rand=%d", json_url, rand());

        HRESULT hr = URLDownloadToFileA(
            NULL,                       //COM 接口
            json_full_url,              //URL
            "update.json",
            0,
            NULL                        //回调
        );

        if (hr == S_OK) {
            LogMessage("连接成功！\n");
        } else {
            LogMessage("连接失败，错误代码: 0x%08X\n", hr);
            return 2;
        }

        LogMessage("开始执行更新\n");
        //这里尝试打开json，如果打开失败退出报错1
        FILE *file = fopen("update.json", "rb");
        if (!file) {
            LogMessage("错误: 无法打开更新列表\n");
            return 1;
        }

        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *json_data = (char *)malloc(file_size + 1);
        //内存分配错误处理
        if (!json_data) {
            fclose(file);
            LogMessage("错误: 内存分配失败\n");
            return 11;
        }

        fread(json_data, 1, file_size, file);
        json_data[file_size] = '\0';
        fclose(file);

        //尝试解析json
        cJSON *root = cJSON_Parse(json_data);
        if (!root) {
            const char *error_ptr = cJSON_GetErrorPtr();
            LogMessage("JSON解析错误: %s\n", error_ptr ? error_ptr : "未知错误");
            free(json_data);
            return 1;
        }

        //调用下载函数，执行操作
        LogMessage("\n开始下载操作\n");
        cJSON *downloads = cJSON_GetObjectItem(root, "download");
        process_downloads(downloads);

        //调用复制函数，执行操作
        LogMessage("\n开始将更新应用到目标\n");
        cJSON *copies = cJSON_GetObjectItem(root, "copy");
        process_copies(copies);

        //调用删除函数，执行操作
        LogMessage("\n正在清理缓存\n");
        cJSON *deletes = cJSON_GetObjectItem(root, "delete");
        process_deletes(deletes);

        //清除程序的json缓存，
        cJSON_Delete(root);
        free(json_data);

        LogMessage("\n所有操作已完成！\n");
        LogMessage("程序将等待5s自动退出\n");
    //使用sleep等待5s，让用户看清发生了什么，不然执行速度太快了，用户会有疑问
    sleep(5);
    CloseHandle(hThread);
    CloseHandle(hMutex);
    return 0;
}

BOOL copy_file(const char *source, const char *destination) {
    LogMessage("正在复制: %s -> %s\n", source, destination);

    //这里检查文件在不在，不在就跳
    if (!PathFileExistsA(source)) {
        LogMessage("并未下载或下载失败，跳过: %s\n", source);
        return FALSE;
    }

    //执行文件复制
    if (CopyFileA(source, destination, FALSE)) {
        LogMessage("复制成功: %s\n", destination);
        return TRUE;
    } else {
        DWORD err = GetLastError();
        LogMessage("复制失败: %s -> %s (错误代码: %lu)\n", source, destination, err);
        return FALSE;
    }
}

BOOL delete_file(const char *file_path) {
    LogMessage("正在清除缓存 -> %s\n", file_path);

    if (DeleteFileA(file_path)) {
        return TRUE;
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) {
            LogMessage("并未下载或下载失败，跳过 -> %s\n", file_path);
            return TRUE;
        }
        LogMessage("WARN:清除失败！-> %s (错误代码: %lu)\n", file_path, err);
        return FALSE;
    }
}

BOOL verify_sha256(const char *file_path, const char *expected_hash) {
    if (!expected_hash || strlen(expected_hash) != SHA256_LEN * 2) {
        LogMessage("WARN:无效的SHA256哈希值\n");
        return FALSE;
    }

    char *actual_hash = calculate_sha256(file_path);
    if (!actual_hash) {
        LogMessage("无法计算文件SHA256: %s\n", file_path);
        return FALSE;
    }

    //如果那个写json的baka用大写的sha256，会让程序爆炸，这事转换器，兼容大小写的sha256
    char lower_expected[SHA256_LEN * 2 + 1];
    char lower_actual[SHA256_LEN * 2 + 1];

    for (int i = 0; i < SHA256_LEN * 2; i++) {
        lower_expected[i] = tolower(expected_hash[i]);
        lower_actual[i] = tolower(actual_hash[i]);
    }
    lower_expected[SHA256_LEN * 2] = '\0';
    lower_actual[SHA256_LEN * 2] = '\0';

    BOOL result = (strcmp(lower_expected, lower_actual) == 0);
    //输出验证成果
    if (!result) {
        LogMessage("SHA256不一致: %s\n", file_path);
        LogMessage("  预期值: %s\n", lower_expected);
        LogMessage("  实际值: %s\n", lower_actual);
    } else {
        LogMessage("SHA256验证成功: %s\n", file_path);
    }

    free(actual_hash);
    return result;
}

HRESULT download_file(const char *url, const char *temp_path, const char *final_path, const char *sha256) {
    LogMessage("目标文件: %s\n", final_path);

    //检查文件在不在，sha是不是差不多
    if (PathFileExistsA(final_path)) {
        if (sha256 && verify_sha256(final_path, sha256)) {
            LogMessage("目标文件SHA256匹配，跳过下载\n");
            return S_OK;
        } else if (sha256) {
            LogMessage("目标文件SHA256不匹配，尝试重新下载\n");
        }
    }
    //和上面是一样的方法，用时间作为种子，添加在url内，防止系统或cdn的缓存策略或劫持
    char full_url[2048];
    srand((unsigned int)time(NULL)); //使用当前时间作为随机种子，生成随机数
    sprintf(full_url, "%s?rand=%d", url, rand());

    LogMessage("正在下载: %s -> %s\n", full_url, temp_path);
    //调用winhttpapi下载
    HRESULT hr = URLDownloadToFileA(
        NULL,
        full_url,
        temp_path,
        0,
        NULL
    );
    //错误处理
    if (hr != S_OK) {
        LogMessage("下载失败: %s (错误代码: 0x%08X)\n", temp_path, hr);
        return hr;
    }
    LogMessage("下载成功: %s\n", temp_path);

    //下载后验证下载到的货是不是假的
    if (sha256 && !verify_sha256(temp_path, sha256)) {
        LogMessage("下载文件SHA256不匹配，删除获取到的文件\n");
        DeleteFileA(temp_path);
        return E_FAIL;
    }

    return S_OK;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_APP_LOG_MESSAGE: {
            wchar_t* msg = (wchar_t*)lParam;
            if (msg && hEdit) {
                int len = GetWindowTextLengthW(hEdit);
                SendMessageW(hEdit, EM_SETSEL, len, len);
                SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)msg);
                SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
                free(msg);
            }
            return 0;
        }
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void process_downloads(cJSON *download_array) {
    //如果那个写json的baka把json填错了，这个检查可以饶他一命
    if (download_array == NULL || !cJSON_IsArray(download_array)) {
        LogMessage("WARN: 无下载项或下载项格式错误\n");
        return;
    }
    //json数据获取器，直接使用cJSON库获取数据
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, download_array) {
        cJSON *name = cJSON_GetObjectItem(item, "name");
        cJSON *url = cJSON_GetObjectItem(item, "url");
        cJSON *path = cJSON_GetObjectItem(item, "path");
        cJSON *sha256 = cJSON_GetObjectItem(item, "sha256");

        if (cJSON_IsString(name) && cJSON_IsString(url) && cJSON_IsString(path)) {
            const char *hash = sha256 && cJSON_IsString(sha256) ? sha256->valuestring : NULL;
            download_file(url->valuestring, name->valuestring, path->valuestring, hash);
        } else {
            LogMessage("WARN: 跳过无效的下载项\n");
        }
    }
}

void process_copies(cJSON *copy_array) {
    //看看，json都填不对的baka，不如丢进河里喂鱼
    //看看，我考虑的多周到
    if (copy_array == NULL || !cJSON_IsArray(copy_array)) {
        LogMessage("WARN: 无复制项或复制项格式错误\n");
        return;
    }

    cJSON *item = NULL;
    cJSON_ArrayForEach(item, copy_array) {
        cJSON *file = cJSON_GetObjectItem(item, "file");
        cJSON *path = cJSON_GetObjectItem(item, "path");

        if (cJSON_IsString(file) && cJSON_IsString(path)) {
            copy_file(file->valuestring, path->valuestring);
        } else {
            LogMessage("WARN: 跳过无效的复制项\n");
        }
    }
}

void process_deletes(cJSON *delete_array) {
    //json填不对建议再练习两年半
    if (delete_array == NULL || !cJSON_IsArray(delete_array)) {
        LogMessage("WARN:无删除项或删除项格式错误\n");
        return;
    }

    cJSON *item = NULL;
    cJSON_ArrayForEach(item, delete_array) {
        cJSON *deletefile = cJSON_GetObjectItem(item, "deletefile");

        if (cJSON_IsString(deletefile)) {
            delete_file(deletefile->valuestring);
        } else {
            LogMessage("WARN:跳过无效的删除项\n");
        }
    }
}

void InitGUI() {
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"UpdateClient";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    hWnd = CreateWindowExW(
        0, L"UpdateClient", L"更新工具",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, GetModuleHandleW(NULL), NULL
    );

    if (!hWnd) {
        MessageBoxW(NULL, L"WARN:窗口创建失败", L"错误", MB_ICONERROR);
        return;
    }

    hEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
        ES_AUTOVSCROLL | ES_READONLY | ES_WANTRETURN,
        0, 0, 800, 600,
        hWnd, (HMENU)1, GetModuleHandleW(NULL), NULL
    );

    HFONT hFont = CreateFontW(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        GB2312_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Microsoft YaHei"
    );
    SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);
}

void LogMessage(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    printf("%s", buffer);

    if (hWnd && g_bRunning) {
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
        if (wide_len > 0) {
            wchar_t* wide_buf = (wchar_t*)malloc(wide_len * sizeof(wchar_t));
            if (wide_buf) {
                MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wide_buf, wide_len);

                if (!PostMessageW(hWnd, WM_APP_LOG_MESSAGE, 0, (LPARAM)wide_buf)) {
                    free(wide_buf);
                    printf("PostMessage failed: %lu\n", GetLastError());
                }
            }
        }
    }
}

char* calculate_sha256(const char *file_path) {
    //这里是邪恶的SHA256验证器
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[SHA256_LEN];
    DWORD cbHash = SHA256_LEN;
    char *hex_hash = NULL;

    //打开文件，开不了就肘击用户
    hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage("WARN:无法打开文件 -> %s (错误代码: %lu)\n", file_path, GetLastError());
        return NULL;
    }

    //获取加密上下文
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        LogMessage("WARN:无法获取加密上下文 -> (错误代码: %lu)\n", GetLastError());
        return NULL;
    }

    //创建哈希对象
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        LogMessage("WARN:无法创建哈希对象 -> (错误代码: %lu)\n", GetLastError());
        return NULL;
    }

    //读取文件并更新哈希
    while (ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL) && cbRead > 0) {
        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            LogMessage("WARN:无法更新哈希 -> (错误代码: %lu)\n", GetLastError());
            return NULL;
        }
    }

    //获取哈希值
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        LogMessage("无法获取哈希值 (错误代码: %lu)\n", GetLastError());
        return NULL;
    }

    //将哈希转换为十六进制字符串待用
    hex_hash = (char*)malloc(SHA256_LEN * 2 + 1);
    if (hex_hash) {
        for (DWORD i = 0; i < cbHash; i++) {
            sprintf(hex_hash + (i * 2), "%02x", rgbHash[i]);
        }
        hex_hash[SHA256_LEN * 2] = '\0';
    }

    //清理缓存，防止爆炸
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return hex_hash;
}

void AppendToEditControl(const wchar_t* text) {
    int len = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, len, len);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
}
