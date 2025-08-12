#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <process.h>  //多线程
#include <stdbool.h>
#include <locale.h>
#include <ctype.h> //验证url
#include "cJSON.h"
#include "ui.h"
#include "ui_windows.h"
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

#define BUFSIZE 1024
#define SHA256_LEN 32
#define WM_APP_LOG_MESSAGE (WM_APP + 1)
//日志等级
//#define LOG_LEVEL_INFO 1
//#define LOG_LEVEL_WARNING 2
//#define LOG_LEVEL_ERROR 3
//是的，做日志等级需要大规模重写，懒得写

//都是史山，删了可能会增加红色感叹号
HWND hWnd; //不知道干什么的，反正和windowsapi有关
HWND hEdit; //同上
HANDLE hConsoleOutput; //不知道干什么的
int num;
FILE *file;
FILE* g_logFile = NULL;
char g_logFilePath[MAX_PATH];
char url[1024];  //url缓存字符串
char outputFileName[256];  //文件输出缓存字符串
char cwd[1024];  //路径缓存字符串
const char *DEFAULT_JSON_URL = "https://web.nyauru.cn/update.json";  //如果您喜欢免命令行输入参数启动，那么您不得不品品这个东西，至尊硬编码url，忘记说了，头文件你自己配，cmake也自己配
char* json_url[1024]; //jsonurl的最终版本

#define MAX_LOG_LINES 10000
char g_logBuffer[MAX_LOG_LINES][1024];
int g_logLineCount = 0;
HANDLE g_logMutex = NULL;
//史山结束
//下面是函数的史山，您都可以在主函数后面找到它们
void process_downloads(cJSON *download_array); //下载处理函数
void process_copies(cJSON *copy_array); //复制处理函数
void process_deletes(cJSON *delete_array);  //删除处理函数
BOOL verify_sha256(const char *file_path, const char *expected_hash);  //sha256验证器
char* calculate_sha256(const char *file_path);  //sha256计算器
HRESULT download_file(const char *url, const char *temp_path, const char *final_path, const char *sha256);  //p2p糕树下崽器
void LogMessage(const char* format, ...);  //printf+log+gui3合1，您不得不选的好物，用它替代您丑陋的printf
void InitLogFile();  //初始化日志文件
void CloseLogFile();  //关闭日志文件
void WriteToLog(const char* format, va_list args);  //写数据到日志
bool IsValidHttpUrl(const char *url); //http url检查
//不要尝试修改史山，会崩塌
//这个下面是gui相关的代码，建议折叠
//全局控件指针
static uiWindow *mainwin;
static uiMultilineEntry *logEntry;
static uiButton *button;
//追加log到gui
static void appendToLog(void *data) {
    char *text = (char *)data;
    uiMultilineEntryAppend(logEntry, text);
    free(text);
}
//关闭gui线程的函数
static int onClosing(uiWindow *w, void *data) {
    uiQuit();
    return 1;
}
//按钮被点击之后的回调
static void onButtonClicked(uiButton *b, void *data) {

}
//初始化gui，及运行逻辑
void setupUI() {
    mainwin = uiNewWindow("更新工具", 800, 600, 0);
    uiWindowSetMargined(mainwin, 1);
    //垂直布局容器
    uiBox *vbox = uiNewVerticalBox();
    uiBoxSetPadded(vbox, 1);
    uiWindowSetChild(mainwin, uiControl(vbox));
    //输出日志用的多行文本框
    logEntry = uiNewMultilineEntry();
    uiMultilineEntrySetReadOnly(logEntry, 1);
    uiBoxAppend(vbox, uiControl(logEntry), 1);
    //水平布局容器
    uiBox *hbox = uiNewHorizontalBox();
    uiBoxSetPadded(hbox, 1);
    uiBoxAppend(vbox, uiControl(hbox), 0);  //忘记说了，0表示不伸缩，1代表可伸缩
    //按钮组件
    button = uiNewButton("打开日志");
    uiButtonOnClicked(button, onButtonClicked, NULL);
    uiBoxAppend(hbox, uiControl(button), 0);
    //第二个按钮
    button = uiNewButton("退出更新");
    uiButtonOnClicked(button, onButtonClicked, NULL);
    uiBoxAppend(hbox, uiControl(button), 0);

    uiLabel *label = uiNewLabel("Ciallo～ (∠・ω< )⌒☆");
    uiBoxAppend(hbox, uiControl(label), 1);
    //窗口关闭回调
    uiWindowOnClosing(mainwin, onClosing, NULL);
    uiControlShow(uiControl(mainwin));
}
//单独的图形进程
unsigned __stdcall WindowThread(void* pArg) {
    #ifdef _WIN32
        SetProcessDPIAware();  //DPI 感知，make程序清晰の能力
    #endif
    uiInitOptions options = {0};
    const char *err = uiInit(&options);
    if (err) {
        fprintf(stderr, "初始化失败: %s\n", err);
        uiFreeInitError(err);
        return 1;
    }

    setupUI();

    LogMessage("GUI线程已启动！\n");

    uiMain();
    uiUninit();
    return 0;
}
//gui相关代码结束

int main(int argc, char *argv[]) {
    //先这么干，输出中文先
    _wsetlocale(LC_ALL, L"zh_CN.UTF-8");
    SetConsoleOutputCP(65001);
    AllocConsole(); //开启终端
    //我等不及了，抓紧启动gui线程吧，只要启动了gui线程，一切都会好起来的，只要能够到达那个地方
    _beginthreadex(NULL, 0, WindowThread, NULL, 0, NULL);
    //处理传入参数
    const char *json_url = DEFAULT_JSON_URL; //将内部url先作为默认值
    if (argc >= 2) {
        //如果第一个参数不是空字符串，就用用户给出的
        if (argv[1][0] != '\0') {
            json_url = argv[1];
            LogMessage("使用自定义的jsonURL\n");
        } else {
            LogMessage("参数为空，使用默认jsonURL\n");
        }
        if (!IsValidHttpUrl(argv[1])) {
            fprintf(stderr, "WARN:URL必须以 http:// 或 https:// 开头！且包含域名，你这个baka！再去练习两年半吧!\n");
            fprintf(stderr, "示例: %s \"https://example.com/update.json\"\n", argv[0]);
            return 9;
        }
    } else {
        printf("未提供参数，使用默认jsonURL\n");
    }

    LogMessage("最终jsonURL: %s\n", json_url);
    InitLogFile(); //在启动gui之前尝试初始化log函数，当然，log没有起单独线程，绑定在主线程内。

    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    LogMessage("已启动更新检查程序\n");
    LogMessage("当前版本v1.2.4\n");
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        LogMessage("请注意，程序当前工作在这个目录==> %s\n", cwd);
        LogMessage("如果您在非minecraft版本目录执行该程序，可能造成其他不可预料的后果！\n");
    } else {
        perror("获取工作目录失败，为安全起见，本更新程序将会退出以保护您的系统，请您手动检查程序运行目录。");
        return 10;
    }

    LogMessage("正在尝试获取清单:\n");
    char json_full_url[2048];
    srand((unsigned int)time(NULL)); //时间种子生成器
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
    sleep(10);
    CloseLogFile();
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

void LogMessage(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    va_start(args, format);
    WriteToLog(format, args);
    va_end(args);

    printf("%s", buffer);

    uiQueueMain(appendToLog, strdup(buffer));//提交log到gui线程
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

void InitLogFile() {
    //获取当前日期时间作为文件名
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(g_logFilePath, MAX_PATH, "updatetool_%Y%m%d_%H%M%S.log", tm_info);

    //打开日志文件
    g_logFile = fopen(g_logFilePath, "a");
    if (!g_logFile) {
        MessageBoxW(NULL, L"无法创建日志文件", L"错误", MB_ICONERROR);
        return;
    }

    //日志标题
    fprintf(g_logFile, "#Update tool log file\n");
    fprintf(g_logFile, "#Create time: %s", ctime(&now));
    fprintf(g_logFile, "#Ciallo～ (∠・ω< )⌒☆\n\n");
    fflush(g_logFile);
}

void CloseLogFile() {
    if (g_logFile) {
        fprintf(g_logFile, "\n#End of log\n");
        fclose(g_logFile);
        g_logFile = NULL;
    }
}

void WriteToLog(const char* format, va_list args) {
    if (!g_logFile) return;
    //反正是一堆时间，懒得写注释
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, 20, "%H:%M:%S", tm_info);

    fprintf(g_logFile, "[%s] ", time_buf);

    vfprintf(g_logFile, format, args);
    fflush(g_logFile);
}

bool IsValidHttpUrl(const char *url) {
    if (url == NULL || url[0] == '\0') {
        return false;
    }

    //检查协议头
    const char *p = url;
    if (strncasecmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncasecmp(p, "https://", 8) == 0) {
        p += 8;
    } else {
        return false;
    }

    //检查至少有一个域名字符
    if (*p == '\0' || *p == '/') {
        return false;
    }

    return true;
}//怕用户是春竹，填错http地址，暴力检查