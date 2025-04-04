// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works
// posting this on github to show the "LGTBQ++ Supporters<3" groupchat it works

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#define _WINSOCKAPI_ // Prevent inclusion of winsock.h in windows.h
// sys calls
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <algorithm>
// win api
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
// file system shit
#include <filesystem>

namespace fs = std::filesystem;
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void setColor(WORD color) {
    SetConsoleTextAttribute(hConsole, color);
}

void resetColor() {
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::string currentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
    std::tm* local = std::localtime(&timeNow);

    std::ostringstream oss;
    oss << std::put_time(local, "%H:%M:%S"); // simple time logging 
    return oss.str();
}

int getConsoleWidth() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
    return 80; // default fallback
}

void printCentered(const std::string& text) {
    int consoleWidth = getConsoleWidth();
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        int padding = (consoleWidth - static_cast<int>(line.length())) / 2;
        if (padding < 0) padding = 0;
        std::cout << std::string(padding, L' ') << line << std::endl;
    }
}

std::vector<DWORD> findProgramProcesses(const std::wstring& programName) {
    std::vector<DWORD> pids;
    PROCESSENTRY32 pe;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (programName == pe.szExeFile) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pids;
}

void forceCloseProcesses(const std::vector<DWORD>& pids) {
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            WaitForSingleObject(hProcess, INFINITE);
            CloseHandle(hProcess);
        }
    }
}

std::wstring getExePathFromPid(DWORD pid) {
    wchar_t path[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess) {
        DWORD length = MAX_PATH;
        if (QueryFullProcessImageName(hProcess, 0, path, &length)) {
            CloseHandle(hProcess);
            return std::wstring(path, length);
        }
        setColor(FOREGROUND_RED);
        std::cerr << "[" << currentTime() << "] Failed to get path for PID " << pid << std::endl;
        resetColor();
        CloseHandle(hProcess);
    }
    else {
        setColor(FOREGROUND_RED);
        std::cerr << "[" << currentTime() << "] Failed to open PID " << pid << std::endl;
        resetColor();
    }
    return L"";
}

void binaryReplace(std::vector<char>& data, const std::vector<char>& from, const std::vector<char>& to) {
    size_t pos = 0;
    while ((pos = std::search(data.begin() + pos, data.end(), from.begin(), from.end()) - data.begin()) != data.size()) {
        data.erase(data.begin() + pos, data.begin() + pos + from.size());
        data.insert(data.begin() + pos, to.begin(), to.end());
        pos += to.size();
    }
}

void saveEditedFile(const fs::path& path, const std::vector<char>& content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        setColor(FOREGROUND_RED);
        throw std::runtime_error("[" + currentTime() + "] Failed to write: " + path.string());
        resetColor();
    }
    out.write(content.data(), content.size());
}

void createToggledDllFiles(const fs::path& dllPath, const std::vector<char>& originalContent) {
    std::vector<char> onContent = originalContent;
    std::vector<char> offContent = originalContent;

    binaryReplace(onContent, { '\x00','v','i','p','_','p','o','r','n','h','u','b','\x00' },  // for the memes @humbleness
        { '\x00','f','u','c','k','_','p','e','o','p','l','e','\x00' });

    binaryReplace(offContent, { '\x00','v','i','p','_','p','o','r','n','h','u','b','\x00' }, // for the memes @humbleness
        { '\x00','f','u','c','k','_','s','k','i','d','s','\x00' });

    saveEditedFile(dllPath.string() + "_On.dll", onContent);
    saveEditedFile(dllPath.string() + "_Off.dll", offContent);
}

void editDllFile(const fs::path& dllPath, const std::string& toggle) {
    try {
        fs::path onPath = dllPath.string() + "_On.dll";
        fs::path offPath = dllPath.string() + "_Off.dll";
        fs::path selected = (toggle == "on") ? onPath : offPath;

        if (fs::exists(onPath) && fs::exists(offPath)) {
            fs::copy_file(selected, dllPath, fs::copy_options::overwrite_existing);
            setColor(FOREGROUND_GREEN);
            std::cout << "[" << currentTime() << "] DLL applied." << std::endl;
            resetColor();
            return;
        }

        std::ifstream in(dllPath, std::ios::binary);
        if (!in) throw std::runtime_error("[" + currentTime() + "] Failed to open DLL.");
        std::vector<char> content((std::istreambuf_iterator<char>(in)), {});
        in.close();

        createToggledDllFiles(dllPath, content);
        fs::copy_file(selected, dllPath, fs::copy_options::overwrite_existing);

        setColor(FOREGROUND_GREEN);
        std::cout << "[" << currentTime() << "] DLL created and applied." << std::endl;
        resetColor();
    }
    catch (const std::exception& e) {
        setColor(FOREGROUND_RED);
        std::cerr << "[" << currentTime() << "] Error: " << e.what() << std::endl;
        resetColor();
    }
}

void checkAdmin() {
    HANDLE hToken = NULL;
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) &&
        GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
        if (!Elevation.TokenIsElevated) exit(0);
    }
    if (hToken) CloseHandle(hToken);
}

int main() {
    checkAdmin(); // checks its being ran as admin for this to work
    system("mode con cols=117 lines=28"); // console sizing
    SetConsoleTitleA("Capcut Premium Patcher <> github.com/disbuted");; 

    const std::wstring programName = L"CapCut.exe";
    std::string toggle;

    printCentered(R"(
  ______                                             __     
 /      \                                           /  |    
/$$$$$$  |  ______    ______    _______  __    __  _$$ |_   
$$ |  $$/  /      \  /      \  /       |/  |  /  |/ $$   |  
$$ |       $$$$$$  |/$$$$$$  |/$$$$$$$/ $$ |  $$ |$$$$$$/   
$$ |   __  /    $$ |$$ |  $$ |$$ |      $$ |  $$ |  $$ | __ 
$$ \__/  |/$$$$$$$ |$$ |__$$ |$$ \_____ $$ \__$$ |  $$ |/  |
$$    $$/ $$    $$ |$$    $$/ $$       |$$    $$/   $$  $$/ 
 $$$$$$/   $$$$$$$/ $$$$$$$/   $$$$$$$/  $$$$$$/     $$$$/  
                    $$ |                                    
                    $$ |                                    
                    $$/                                     
---------------------------------------------------------------------------------
              CapCut Premium Patcher by Disbuted (github.com/disbuted)          
                   Type "on" or "off" to toggle premium features              
    )"); 

    std::cin >> toggle;

    auto pids = findProgramProcesses(programName);
    std::set<fs::path> dllPaths;

    if (!pids.empty()) {
        for (DWORD pid : pids) {
            fs::path exePath = getExePathFromPid(pid); // C:\Users\PCUSERNAME\AppData\Local\CapCut\Apps\5.9.1.2256 (at the time of coding this)
            fs::path folder = exePath.parent_path();
            fs::path dll = folder / "VECreator.dll"; // the .dll for the prem
            fs::path watermark = folder / "Resources" / "watermark"; // fuck the watermark bro on god

            if (fs::exists(dll)) dllPaths.insert(dll);

            std::error_code ec;
            fs::remove_all(watermark, ec);
        }

        forceCloseProcesses(pids);
        while (!findProgramProcesses(programName).empty()) Sleep(100);

        for (const auto& path : dllPaths) editDllFile(path, toggle);
	}

	else if (toggle == "on" || toggle == "off") {
		setColor(FOREGROUND_RED | FOREGROUND_GREEN);
		std::cout << "[" << currentTime() << "] CapCut.exe not running. Open it and try again." << std::endl;
		resetColor();
	}

    setColor(FOREGROUND_GREEN);
    std::cout << "[" << currentTime() << "] Done! Press any key to exit..." << std::endl;
    resetColor();
    std::cin.ignore();
    std::cin.get();
    return 0;
}
