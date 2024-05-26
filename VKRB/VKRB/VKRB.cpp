#define NOMINMAX // Отключаем макросы min и max из Windows.h

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <locale>
#include <algorithm>
#include <set>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <mutex>
#include <codecvt>

using namespace std;
using namespace std::chrono;

// Структура, представляющая процесс
struct Process {
    DWORD processID;
    wstring processName;
    SIZE_T memoryUsage;
    BOOL isActive;
    LPVOID baseAddress;
};

// Структура для хранения результатов поиска
struct SearchResult {
    size_t index;
    LPVOID address;
    wstring value;
    wstring type;
};

vector<SearchResult> foundAddresses; // Общий вектор для хранения результатов

// Список известных системных процессов
const set<wstring> systemProcesses = {
    L"System",
    L"System Idle Process",
    L"svchost.exe",
    L"vshost.exe",
    L"sihost.exe",
    L"taskhostw.exe",
    L"explorer.exe",
    L"conhost.exe",
    L"dllhost.exe",
    L"msedgewebview2.exe",
    L"RuntimeBroker.exe"
};

// Объявления функций
vector<Process> getProcesses();
void printProcessInfo(const Process& process);
vector<SearchResult> searchMemoryNumeric(DWORD processID, DWORD alignment, int intValue);
vector<SearchResult> searchMemoryString(DWORD processID, const wstring& value, DWORD alignment);
void printSearchResults(const vector<SearchResult>& results, size_t count);
vector<uint16_t> convertToUtf16(const wstring& input);
vector<SearchResult> filterSearchResults(const vector<SearchResult>& results, const wstring& filterValue, HANDLE hProcess, const wstring& type);
void monitorProcess(DWORD processID);
void clearScreen();
wstring addressToWstring(LPVOID address);
LPVOID wstringToAddress(const wstring& addressStr);

int main();

// Функция для преобразования строки в последовательность UTF-16
std::vector<uint16_t> convertToUtf16(const wstring& input) {
    std::vector<uint16_t> utf16Sequence;
    for (wchar_t wc : input) {
        utf16Sequence.push_back(static_cast<uint16_t>(wc));
    }
    return utf16Sequence;
}

// Функция для преобразования строки в адрес
LPVOID wstringToAddress(const wstring& addressStr) {
    wstringstream ws;
    ws << L"00000000" << addressStr;
    LPVOID address;
    ws >> hex >> address;
    return address;
}

// Функция для получения списка несистемных процессов
vector<Process> getProcesses() {
    vector<Process> processes;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Создаем снимок всех процессов в системе
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        cerr << "Ошибка создания снимка процессов." << endl;
        return processes;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        cerr << "Ошибка получения информации о процессе." << endl;
        CloseHandle(hProcessSnap);
        return processes;
    }

    do {
        if (systemProcesses.find(pe32.szExeFile) == systemProcesses.end()) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    processes.push_back(Process{ pe32.th32ProcessID, pe32.szExeFile, pmc.WorkingSetSize, TRUE, nullptr });
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    sort(processes.begin(), processes.end(), [](const Process& a, const Process& b) {
        return a.processName < b.processName;
        });

    return processes;
}

// Функция для вывода информации о процессе
void printProcessInfo(const Process& process) {
    wcout << L"Процесс: " << process.processName << endl;
    wcout << L"PID: " << process.processID << endl;
    wcout << L"Область занимаемой ОП: " << process.memoryUsage << L" байт" << endl;
    wcout << L"Активен: " << (process.isActive ? L"Да" : L"Нет") << endl;
    wcout << L"Адрес первой занимаемой ячейки в ОП: " << process.baseAddress << endl;
}

// Функция для преобразования адреса в строку
wstring addressToWstring(LPVOID address) {
    wstringstream ws;
    ws << hex << address;
    wstring addrStr = ws.str();
    if (addrStr.size() > 8) {
        return addrStr.substr(addrStr.size() - 8);
    }
    else {
        return addrStr;
    }
}

// Функция для поиска числового значения в памяти процесса
vector<SearchResult> searchMemoryNumeric(DWORD processID, DWORD alignment, int intValue) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        wcout << L"Не удалось открыть процесс с PID: " << processID << endl;
        return {};
    }

    wcout << L"Выполнение поиска..." << endl;

    auto start = high_resolution_clock::now();

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPBYTE startAddress = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE endAddress = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    foundAddresses.clear(); // Очистка предыдущих результатов

    MEMORY_BASIC_INFORMATION mbi;
    for (LPBYTE address = startAddress; VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi); address += mbi.RegionSize) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, address, buffer.data(), buffer.size(), &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - sizeof(int); i += alignment) {
                    LPVOID currentAddress = address + i;
                    if (memcmp(&buffer[i], &intValue, sizeof(int)) == 0) {
                        foundAddresses.push_back({ foundAddresses.size() + 1, currentAddress, to_wstring(intValue), L"n" });
                    }
                }
            }
        }
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    wcout << L"Поиск завершен за " << duration.count() << L" миллисекунд." << endl;
    wcout << L"Искомое значение: " << intValue << endl;
    wcout << L"Найдено совпадений: " << foundAddresses.size() << endl;

    CloseHandle(hProcess);
    return foundAddresses;
}

// Функция для поиска строкового значения в памяти процесса
vector<SearchResult> searchMemoryString(DWORD processID, const wstring& value, DWORD alignment) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        wcout << L"Не удалось открыть процесс с PID: " << processID << endl;
        return {};
    }

    wcout << L"Выполнение поиска..." << endl;

    // Преобразование введенного значения в последовательность UTF-16
    vector<uint16_t> utf16Sequence(value.begin(), value.end());

    auto start = high_resolution_clock::now();

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPBYTE startAddress = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE endAddress = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    foundAddresses.clear(); // Очистка предыдущих результатов

    MEMORY_BASIC_INFORMATION mbi;
    for (LPBYTE address = startAddress; VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi); address += mbi.RegionSize) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, address, buffer.data(), buffer.size(), &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - utf16Sequence.size() * sizeof(uint16_t); i += alignment) {
                    LPVOID currentAddress = address + i;
                    if (memcmp(&buffer[i], utf16Sequence.data(), utf16Sequence.size() * sizeof(uint16_t)) == 0) {
                        foundAddresses.push_back({ foundAddresses.size() + 1, currentAddress, value, L"s" });
                    }
                }
            }
        }
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    wcout << L"Поиск завершен за " << duration.count() << L" миллисекунд." << endl;
    wcout << L"Искомое значение: " << value << endl;
    wcout << L"Найдено совпадений: " << foundAddresses.size() << endl;

    CloseHandle(hProcess);
    return foundAddresses;
}

// Функция для вывода результатов поиска
void printSearchResults(const vector<SearchResult>& results, size_t count) {
    wcout << setw(6) << L"Номер" << setw(20) << L"Адрес" << setw(20) << L"Значение" << setw(10) << L"Тип" << endl;
    wcout << setfill(L'-') << setw(56) << L"" << setfill(L' ') << endl;
    for (size_t i = 0; i < count; ++i) {
        const auto& result = results[i];
        wcout << setw(6) << result.index
            << setw(20) << addressToWstring(result.address)
            << setw(20) << result.value
            << setw(10) << result.type << endl;
    }
}

// Функция для отслеживания завершения процесса
void monitorProcess(DWORD processID) {
    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, processID);
    if (hProcess == NULL) {
        wcout << L"Не удалось открыть процесс с PID: " << processID << endl;
        return;
    }

    WaitForSingleObject(hProcess, INFINITE);
    CloseHandle(hProcess);

    wcout << L"Процесс с PID " << processID << L" завершен." << endl;

    char choice;
    while (true) {
        wcout << L"Желаете продолжить? (y/n): ";
        cin >> choice;

        if (choice == 'y' || choice == 'Y' || choice == 'Д' || choice == 'д') {
            return;
        }
        else if (choice == 'n' || choice == 'N' || choice == 'Н' || choice == 'н') {
            exit(0);
        }
        else {
            wcout << L"Некорректный ответ. Попробуйте снова." << endl;
        }
    }
}

// Функция для очистки экрана
void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// Функция для фильтрации результатов поиска
vector<SearchResult> filterSearchResults(const vector<SearchResult>& results, const wstring& filterValue, HANDLE hProcess, const wstring& type) {
    vector<SearchResult> filteredResults;

    for (const auto& result : results) {
        SIZE_T bytesRead;
        if (type == L"n") {
            int intValue;
            if (ReadProcessMemory(hProcess, result.address, &intValue, sizeof(int), &bytesRead)) {
                if (to_wstring(intValue) == filterValue) {
                    filteredResults.push_back({ result.index, result.address, filterValue, result.type });
                }
            }
        }
        else if (type == L"s") {
            size_t bufferSize = filterValue.size() * sizeof(wchar_t);
            vector<wchar_t> buffer(filterValue.size());
            if (ReadProcessMemory(hProcess, result.address, buffer.data(), bufferSize, &bytesRead)) {
                wstring readValue(buffer.begin(), buffer.end());
                if (readValue == filterValue) {
                    filteredResults.push_back({ result.index, result.address, filterValue, result.type });
                }
            }
        }
    }

    return filteredResults;
}

enum State {
    SHOW_PROCESSES,
    SHOW_PROCESS_INFO,
    SEARCH_MEMORY,
    FILTER_RESULTS,
    EXIT
};

State currentState = SHOW_PROCESSES;
vector<Process> processes;
vector<SearchResult> searchResults;
int currentProcessIndex = -1;
wstring currentType;
DWORD currentAlignment;
wstring currentValue;

void transition(State nextState) {
    clearScreen();
    currentState = nextState;
}

void showProcesses() {
    processes = getProcesses();

    for (size_t i = 0; i < processes.size(); ++i) {
        wcout << i + 1 << L". " << processes[i].processName << L" (PID: " << processes[i].processID << L")" << endl;
    }

    wcout << L"Введите номер процесса для отображения информации (0 для выхода, r для обновления списка): ";
    wstring input;
    wcin >> input;

    if (input == L"0") {
        transition(EXIT);
    }
    else if (input == L"r" || input == L"R") {
        transition(SHOW_PROCESSES);
    }
    else {
        try {
            currentProcessIndex = stoi(input) - 1;
            if (currentProcessIndex >= 0 && currentProcessIndex < processes.size()) {
                transition(SHOW_PROCESS_INFO);
            }
            else {
                wcout << L"Неверный номер процесса. Попробуйте снова." << endl;
            }
        }
        catch (exception& e) {
            wcout << L"Неверный ввод. Попробуйте снова." << endl;
        }
    }
}

void showProcessInfo() {
    printProcessInfo(processes[currentProcessIndex]);

    while (true) {
        wcout << L"Введите тип искомого значения (s - строка, n - число, a - все типы, ! - назад): ";
        wcin >> currentType;

        if (currentType == L"!") {
            transition(SHOW_PROCESSES);
            return;
        }

        if (currentType == L"s" || currentType == L"n" || currentType == L"a") {
            break;
        }
        else {
            wcout << L"Некорректный ввод. Попробуйте снова." << endl;
        }
    }

    wcout << L"Введите кратность адреса: ";
    wcin >> currentAlignment;

    if (wcin.fail()) {
        wcin.clear();
        wcin.ignore(numeric_limits<streamsize>::max(), '\n');
        wcout << L"Некорректный ввод. Кратность адреса должна быть числом. Попробуйте снова." << endl;
        return;
    }

    wcout << L"Введите значение для поиска: ";
    wcin.ignore();
    getline(wcin, currentValue);

    if (currentType == L"n") {
        try {
            int intValue = stoi(currentValue);
            searchResults = searchMemoryNumeric(processes[currentProcessIndex].processID, currentAlignment, intValue);
        }
        catch (exception& e) {
            wcout << L"Некорректный ввод. Значение должно быть числом. Попробуйте снова." << endl;
            return;
        }
    }
    else {
        searchResults = searchMemoryString(processes[currentProcessIndex].processID, currentValue, currentAlignment);
    }

    if (!searchResults.empty()) {
        transition(SEARCH_MEMORY);
    }
    else {
        wcout << L"Значение не найдено в памяти процесса." << endl;
        wcout << L"Введите 1 для повторного поиска или ! для возврата к выбору процесса: ";
        wstring choice;
        wcin >> choice;

        if (choice == L"!") {
            transition(SHOW_PROCESSES);
        }
    }
}

void searchMemory() {
    wcout << L"Найдено совпадений: " << searchResults.size() << endl;

    size_t count;
    while (true) {
        wcout << L"Сколько совпадений вывести? ";
        wcin >> count;

        if (wcin.fail() || count > searchResults.size()) {
            wcin.clear();
            wcin.ignore(numeric_limits<streamsize>::max(), '\n');
            wcout << L"Некорректный ввод. Попробуйте снова." << endl;
        }
        else {
            break;
        }
    }

    printSearchResults(searchResults, count);

    wcout << L"Введите значение для отсеивания (!, чтобы вернуться назад): ";
    wstring filterValue;
    wcin.ignore();
    getline(wcin, filterValue);

    if (filterValue == L"!") {
        transition(SHOW_PROCESS_INFO);
        return;
    }

    // Вызов функции фильтрации
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[currentProcessIndex].processID);
    if (hProcess == NULL) {
        wcout << L"Не удалось открыть процесс с PID: " << processes[currentProcessIndex].processID << endl;
        transition(SHOW_PROCESSES);
        return;
    }

    searchResults = filterSearchResults(searchResults, filterValue, hProcess, currentType);
    CloseHandle(hProcess);

    transition(FILTER_RESULTS);
}

void filterResults() {
    wcout << L"Найдено совпадений: " << searchResults.size() << endl;

    size_t count;
    while (true) {
        wcout << L"Сколько совпадений вывести? ";
        wcin >> count;

        if (wcin.fail() || count > searchResults.size()) {
            wcin.clear();
            wcin.ignore(numeric_limits<streamsize>::max(), '\n');
            wcout << L"Некорректный ввод. Попробуйте снова." << endl;
        }
        else {
            break;
        }
    }

    printSearchResults(searchResults, count);

    wcout << L"Желаете продолжить отсеивание значений? (y/n): ";
    wstring response;
    wcin >> response;

    if (response == L"n" || response == L"N" || response == L"н" || response == L"Н") {
        transition(SHOW_PROCESS_INFO);
    }
    else if (response == L"y" || response == L"Y" || response == L"д" || response == L"Д") {
        transition(SEARCH_MEMORY);
    }
    else {
        wcout << L"Некорректный ввод. Пожалуйста, введите y или n." << endl;
    }
}

int main() {
    _wsetlocale(LC_ALL, L"Russian");

    while (currentState != EXIT) {
        switch (currentState) {
        case SHOW_PROCESSES:
            showProcesses();
            break;
        case SHOW_PROCESS_INFO:
            showProcessInfo();
            break;
        case SEARCH_MEMORY:
            searchMemory();
            break;
        case FILTER_RESULTS:
            filterResults();
            break;
        case EXIT:
            break;
        }
    }

    return 0;
}
