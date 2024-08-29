#include <windows.h>
#include <TlHelp32.h>
#include <memoryapi.h>
#include <iostream>
#include <vector>
#include <functional>
#include <set>

std::string process_name = "ProcessName";
DWORD pid;
HANDLE process_handle;

using SearchType = int;

DWORD GetProcessByName(const std::string &name) { //wstring if pInfo.szExeFile - wchar_t[];
  HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 pInfo = {0};
  pInfo.dwSize = sizeof(PROCESSENTRY32);
  while (Process32Next(snapShot, &pInfo)) {
    if (std::string(pInfo.szExeFile).find(name) != -1) {
      CloseHandle(snapShot);
      return pInfo.th32ProcessID;
    }
  }
  CloseHandle(snapShot);
  return 0;
}

BOOL RunProcess(const char *lpApplicationName, DWORD dwWaitMilliseconds) {
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);
  if (!CreateProcessA(NULL, const_cast<LPSTR>(lpApplicationName), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    std::cout << "CreateProcess failed [" << GetLastError() << "]\n";
    return FALSE;
  }
  WaitForSingleObject(pi.hProcess, dwWaitMilliseconds);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return TRUE;
}

void scan_memory(char *start, char *end, std::vector<char *> &adr, bool clear, const std::function<bool(void *)> &cmp) {
  if (clear) {
    adr.clear();
  }
  char *cur = start;
  std::cout << (void*)start << " " << (void*)end << std::endl;
  while (cur < end) {
    MEMORY_BASIC_INFORMATION m_i;
    VirtualQueryEx(process_handle, cur, &m_i, sizeof(m_i));
    if (m_i.RegionSize > (1ll << 30)) {
      cur += m_i.RegionSize;
      continue;
      //m_i.RegionSize = 1ll << 29;
    }
    //std::cout << m_i.RegionSize << " " << (void*)cur << std::endl;
    std::vector<char> read_buffer(m_i.RegionSize);
    size_t read_byte;
    if (ReadProcessMemory(process_handle, cur, read_buffer.data(), m_i.RegionSize, (SIZE_T *) &read_byte)) {
      //std::cout << "Success" << std::endl;
      char *cur_page_ptr = read_buffer.data();
      char *end_page_ptr = read_buffer.data() + read_buffer.size() - sizeof(SearchType) + 1;
      while (cur_page_ptr < end_page_ptr) {
        if (cmp(cur_page_ptr)) {
          adr.push_back((char *) m_i.BaseAddress + (cur_page_ptr - read_buffer.data()));
        }
        cur_page_ptr += 4;
      }
    } else {
        int error_code = GetLastError();
        std::cout << "Error: " << error_code << " " << (void*)cur << " " << m_i.RegionSize << std::endl;
    }
    unsigned long long tmp = (unsigned long long) cur + m_i.RegionSize;
    if (tmp > (1ull << (sizeof(char *) * 8)) - 1) {
      break;
    }
    cur += m_i.RegionSize;
  }
}

void get_start_end_ptr(char *&start_ptr, char *&end_ptr) {
  SYSTEM_INFO s_i;
  GetSystemInfo(&s_i);
  start_ptr = (char *) s_i.lpMinimumApplicationAddress;
  end_ptr = (char *) s_i.lpMaximumApplicationAddress;
  //end_ptr = (char *) 0xFFFFFFFF;
}

void scan_full_memory(std::vector<char *> &adr, bool clear, const std::function<bool(void *)> &cmp) {
  char *start_ptr;
  char *end_ptr;
  get_start_end_ptr(start_ptr, end_ptr);
  scan_memory(start_ptr, end_ptr, adr, clear, cmp);
}

std::vector<char *> scan_addresses(const std::vector<char *> &adr, const std::function<bool(void *)> &cmp) {
  std::vector<char *> res;
  SearchType value;
  for (int i = 0; i < adr.size(); ++i) {
    size_t read_byte;
    ReadProcessMemory(process_handle, adr[i], &value, sizeof(SearchType), (SIZE_T *) &read_byte);
    if (cmp(&value)) {
      res.push_back(adr[i]);
    }
  }
  return res;
}

std::vector<char *> get_mod_addresses(const std::vector<char *> &adr, long long mod) {
  std::vector<char *> res;
  for (int i = 0; i < adr.size(); ++i) {
    if ((long long) adr[i] % mod == 0) {
      res.push_back(adr[i]);
    }
  }
  return res;
}

void set_addresses(std::vector<char *> &adr, SearchType value) {
  for (int i = 0; i < adr.size(); ++i) {
    size_t read_byte;
    WriteProcessMemory(process_handle, adr[i], &value, sizeof(value), (SIZE_T *) &read_byte);
  }
}

std::vector<SearchType> get_values(std::vector<char *> &adr) {
  std::vector<SearchType> res;
  SearchType value;
  for (int i = 0; i < adr.size(); ++i) {
    size_t read_byte;
    ReadProcessMemory(process_handle, adr[i], &value, sizeof(SearchType), (SIZE_T *) &read_byte);
    res.push_back(value);
  }
  return res;
}

void read_process_handle() {
  process_handle = nullptr;
  while (!process_handle) {
    std::cout << "Write process name\n";
    std::cin >> process_name;
    pid = GetProcessByName(process_name);
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    std::cout << pid << " " << process_handle << "\n";
  }
}

void interact() {
  read_process_handle();

  std::string operation;
  int sleep_time = 0;
  std::vector<char *> adr;
  while (true) {
    std::cout << "Write operation (for help write help)\n";
    std::cin >> operation;

    if (operation == "set_sleep") {
      std::cin >> sleep_time;
    }
    if (operation == "new_scan") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return (*(SearchType *) (ptr)) == value;
      };

      Sleep(sleep_time);
      scan_full_memory(adr, true, function);
    }
    if (operation == "new_scan_between") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return (*(SearchType *) (ptr)) == value;
      };

      char *start_ptr;
      char *end_ptr;
      long long start, end;
      std::cin >> start >> end;
      start_ptr = (char*)((void*)start);
      end_ptr = (char*)((void*)end);

      Sleep(sleep_time);

      scan_memory(start_ptr, end_ptr, adr, true, function);
    }
    if (operation == "scan_equal") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return *(SearchType *) (ptr) == value;
      };

      Sleep(sleep_time);
      adr = scan_addresses(adr, function);
    }

    if (operation == "scan_not_equal") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return *(SearchType *) (ptr) != value;
      };

      Sleep(sleep_time);
      adr = scan_addresses(adr, function);
    }

    if (operation == "set") {
      SearchType value;
      std::cin >> value;
      set_addresses(adr, value);
    }

    if (operation == "scan_less") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return *(SearchType *) (ptr) < value;
      };

      Sleep(sleep_time);
      adr = scan_addresses(adr, function);
    }

    if (operation == "scan_higher") {
      SearchType value;
      std::cin >> value;

      auto function = [value](void *ptr) {
        return *(SearchType *) (ptr) > value;
      };

      Sleep(sleep_time);
      adr = scan_addresses(adr, function);
    }

    if (operation == "add") {
      void *ptr;
      std::cin >> ptr;
      adr.push_back((char *) ptr);
    }
    if (operation == "read") {
      void *ptr;
      std::cin >> ptr;
      adr.clear();
      adr.push_back((char *) ptr);
    }
    if (operation == "write") {
      SearchType value;
      for (int i = 0; i < adr.size(); ++i) {
        size_t read_byte;
        ReadProcessMemory(process_handle, adr[i], &value, sizeof(SearchType), (SIZE_T *) &read_byte);
        std::cout << (void*)adr[i] << " = " << value << "\n";
      }
    }
    if (operation == "delete_copies") {
      std::set<char *> q;
      for (auto a: adr) {
        q.insert(a);
      }
      adr.clear();
      for (auto a: q) {
        adr.push_back(a);
      }
    }
    if (operation == "mod") {
      long long mod;
      std::cin >> mod;
      adr = get_mod_addresses(adr, mod);
    }

    if (operation == "help") {
      std::cout << "set_sleep(time)\nnew_scan(value)\nnew_scan_between(value, start, end)\nscan_equal(value)\nscan_not_equal(value)\n";
      std::cout << "set(value)\nscan_less(value)\nscan_higher(value)\n";
      std::cout << "add(ptr)\nread(ptr)\nwrite()\ndelete_copies()\nmod(mod)\n";
      std::cout << "help()\nexit()\n";
    }

    if (operation == "exit") {
      break;
    }

    std::cout << "Addresses count: " << adr.size() << "\n\n";
  }
}

int main() {
  interact();
}
