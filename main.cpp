#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <ctime>

static const int    TC = 10;
static const SIZE_T PGSZ = 0x1000;
static const SIZE_T CSZ = PGSZ * 128;
static const SIZE_T OVL = 512;
static const SIZE_T MSL = 512;
static const char   RC[] = "abcdefghijklmnopqrstuvwxyz0123456789";

struct KW { std::vector<uint8_t> s; size_t l; };
struct SR { DWORD addr; size_t el; };
struct RG { DWORD base; SIZE_T size; };

static std::vector<KW> g_kw;

DWORD GetPID() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) }; DWORD pid = 0;
    if (Process32FirstW(h, &pe))
        do { if (!_wcsicmp(pe.szExeFile, L"hl.exe")) { pid = pe.th32ProcessID; break; } } while (Process32NextW(h, &pe));
    CloseHandle(h); return pid;
}

std::string GetExeDir() {
    char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
    char* s = strrchr(p, '\\'); if (s) *s = 0; return p;
}

std::string FindDll(const std::string& dir) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\*.dll").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string r = dir + "\\" + fd.cFileName; FindClose(h); return r;
}

void BuildKW(const std::string& path) {
    srand((unsigned)time(NULL)); g_kw.clear();
    std::string full = path.substr(path.find_last_of("\\/") + 1);
    std::string base = full.substr(0, full.find_last_of('.'));
    auto add = [](const std::string& s) {
        g_kw.push_back({ std::vector<uint8_t>(s.begin(), s.end()), s.size() });
        std::vector<uint8_t> w; for (char c : s) { w.push_back((uint8_t)c); w.push_back(0); }
        g_kw.push_back({ w, w.size() });
        };
    add(path); add(full); add(base);
    std::sort(g_kw.begin(), g_kw.end(), [](const KW& a, const KW& b) { return a.l > b.l; });
}

DWORD  AlignDn(DWORD a) { return a & ~(DWORD)(PGSZ - 1); }
SIZE_T AlignUp(SIZE_T s) { return (s + PGSZ - 1) & ~(SIZE_T)(PGSZ - 1); }

SIZE_T StrEndA(const char* b, SIZE_T p, SIZE_T m) {
    SIZE_T l = (p + MSL < m) ? p + MSL : m;
    while (p < l && b[p] != '\0' && b[p] != '\n' && b[p] != '\r') p++; return p;
}
SIZE_T StrEndW(const char* b, SIZE_T p, SIZE_T m) {
    SIZE_T l = (p + MSL * 2 < m) ? p + MSL * 2 : m;
    while (p + 1 < l && !(b[p] == '\0' && b[p + 1] == '\0')) p += 2; return p;
}

SIZE_T SafeRead(HANDLE proc, DWORD addr, SIZE_T size, char* buf) {
    SIZE_T off = 0;
    while (off < size) {
        SIZE_T tr = size - off, br = 0;
        if (ReadProcessMemory(proc, (LPVOID)(uintptr_t)(addr + off), buf + off, tr, &br) && br > 0) { off += br; continue; }
        if (tr > PGSZ) {
            tr = PGSZ - ((addr + off) & (PGSZ - 1)); if (!tr || tr > PGSZ) tr = PGSZ; if (tr > size - off) tr = size - off; br = 0;
            if (ReadProcessMemory(proc, (LPVOID)(uintptr_t)(addr + off), buf + off, tr, &br) && br > 0) { off += br; continue; }
        }
        memset(buf + off, 0, tr); off += tr;
    }
    return size;
}

void Fill(HANDLE proc, DWORD addr, size_t len) {
    if (!len) return;
    std::vector<char> p(len);
    for (size_t j = 0; j < len; j++) p[j] = RC[rand() % (sizeof(RC) - 1)];
    SIZE_T off = 0;
    while (off < len) {
        SIZE_T tw = len - off, wr = 0;
        if (WriteProcessMemory(proc, (LPVOID)(uintptr_t)(addr + off), p.data() + off, tw, &wr) && wr > 0) { off += wr; continue; }
        if (tw > PGSZ) { tw = PGSZ - ((addr + off) & (PGSZ - 1)); if (!tw || tw > PGSZ) tw = PGSZ; if (tw > len - off) tw = len - off; }
        DWORD al = AlignDn((DWORD)(addr + off)), old = 0;
        SIZE_T sp = AlignUp(tw + ((addr + off) - al));
        if (VirtualProtectEx(proc, (LPVOID)(uintptr_t)al, sp, PAGE_EXECUTE_READWRITE, &old)) {
            wr = 0; WriteProcessMemory(proc, (LPVOID)(uintptr_t)(addr + off), p.data() + off, tw, &wr);
            DWORD tmp; VirtualProtectEx(proc, (LPVOID)(uintptr_t)al, sp, old, &tmp);
            if (wr > 0) { off += wr; continue; }
        }
        off += tw;
    }
}

std::vector<RG> GetRegions(HANDLE proc) {
    std::vector<RG> out; MEMORY_BASIC_INFORMATION mbi; DWORD addr = 0x1000;
    while (addr < 0x7FFF0000) {
        if (!VirtualQueryEx(proc, (LPVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) { addr += 0x1000; continue; }
        DWORD next = (DWORD)(uintptr_t)mbi.BaseAddress + (DWORD)mbi.RegionSize;
        if (next <= addr) break;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 && (mbi.Protect & 0xFF) != PAGE_NOACCESS)
            out.push_back({ (DWORD)(uintptr_t)mbi.BaseAddress, mbi.RegionSize });
        addr = next;
    }
    return out;
}

void ScanBuf(DWORD base, const char* buf, SIZE_T len, std::vector<SR>& out) {
    SIZE_T i = 0;
    while (i < len) {
        bool m = false;
        for (auto& kw : g_kw) {
            if (i + kw.l > len || (uint8_t)buf[i] != kw.s[0] || memcmp(buf + i, kw.s.data(), kw.l)) continue;
            bool wide = kw.l >= 4 && kw.s[1] == 0;
            SIZE_T end = wide ? StrEndW(buf, i + kw.l, len) : StrEndA(buf, i + kw.l, len);
            size_t el = end - i; if (el < kw.l) el = kw.l;
            out.push_back({ base + (DWORD)i, el }); i += el; m = true; break;
        }
        if (!m) i++;
    }
}

void ProcResults(HANDLE proc, const std::vector<SR>& res, DWORD rb, SIZE_T rs) {
    DWORD re = rb + (DWORD)rs;
    for (auto r : res) {
        if (r.addr < rb || r.addr >= re) continue;
        if (r.addr + (DWORD)r.el > re) r.el = (size_t)(re - r.addr);
        if (r.el) Fill(proc, r.addr, r.el);
    }
}

void WorkerFn(HANDLE proc, std::vector<RG>& regions, std::atomic<size_t>& nr) {
    char* buf = (char*)VirtualAlloc(NULL, CSZ + OVL, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) return;
    while (true) {
        size_t idx = nr.fetch_add(1); if (idx >= regions.size()) break;
        DWORD base = regions[idx].base; SIZE_T size = regions[idx].size, off = 0;
        while (off < size) {
            SIZE_T tr = size - off; if (tr > CSZ) tr = CSZ;
            SIZE_T ex = off + tr < size ? (OVL < size - off - tr ? OVL : size - off - tr) : 0;
            SafeRead(proc, base + (DWORD)off, tr + ex, buf);
            std::vector<SR> res; ScanBuf(base + (DWORD)off, buf, tr + ex, res);
            ProcResults(proc, res, base, size); off += tr;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
}

void Erase(HANDLE proc) {
    auto regions = GetRegions(proc); std::atomic<size_t> nr(0);
    std::vector<std::thread> threads;
    for (int t = 0; t < TC; t++) threads.emplace_back(WorkerFn, proc, std::ref(regions), std::ref(nr));
    for (auto& t : threads) if (t.joinable()) t.join();
}

bool Inject(const std::string& dll) {
    DWORD pid = GetPID(); if (!pid) { printf("hl.exe not running\n"); return false; }
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { printf("OpenProcess failed\n"); return false; }
    LPVOID rp = VirtualAllocEx(proc, NULL, dll.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rp) { printf("VirtualAllocEx failed\n"); CloseHandle(proc); return false; }
    WriteProcessMemory(proc, rp, dll.c_str(), dll.size() + 1, NULL);
    LPVOID fn = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE t = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)fn, rp, 0, NULL);
    if (!t) { printf("CreateRemoteThread failed: %lu\n", GetLastError()); VirtualFreeEx(proc, rp, 0, MEM_RELEASE); CloseHandle(proc); return false; }
    WaitForSingleObject(t, 8000); CloseHandle(t); VirtualFreeEx(proc, rp, 0, MEM_RELEASE);
    for (int i = 0; i < 4; i++) { Sleep(500); Erase(proc); }
    CloseHandle(proc); return true;
}

int main() {
    SetConsoleTitleA("injector"); srand((unsigned)time(NULL));
    std::string dir = GetExeDir(), dll = FindDll(dir);
    if (dll.empty()) { printf("no dll found\n"); Sleep(3000); return 1; }
    std::string name = dll.substr(dll.find_last_of("\\/") + 1), szStr;
    HANDLE hf = CreateFileA(dll.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fs; char buf[64];
        if (GetFileSizeEx(hf, &fs)) {
            double mb = fs.QuadPart / (1024.0 * 1024.0), kb = fs.QuadPart / 1024.0;
            sprintf(buf, mb >= 1.0 ? "%.1f MB" : "%.1f KB", mb >= 1.0 ? mb : kb); szStr = buf;
        }
        CloseHandle(hf);
    }
    printf("%s (%s)\n", name.c_str(), szStr.c_str());
    BuildKW(dll);
    if (!GetPID()) { printf("hl.exe not running\n"); Sleep(3000); return 1; }
    printf(Inject(dll) ? "ok\n" : "failed\n");
    printf("closing in 5s...\n"); Sleep(5000);
    return 0;
}