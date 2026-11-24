// tt_selftest — known-answer tests for tiny_tracer's input parsers (the code the fuzz targets reach):
// the INI/list loaders in Settings.cpp + FuncWatch.cpp and the PE export parser in ExportsInfo.cpp.
// Each check prints "PASS <name>" or "FAIL <name>: <why>"; mayhem/test.sh compares the PASS lines
// against the expected list, so a program that prints nothing (or exits early) fails the suite.
//
// Usage: tt_selftest <repo root> <scratch dir>
//        tt_selftest --write-pe <path>     (writes the sample DLL used by the exports test)
#include "Settings.h"
#include "ExportsInfo.h"
#include "mini_pe.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static int g_failed = 0;
static void check(const std::string& name, bool ok, const std::string& why = "")
{
    if (ok) std::cout << "PASS " << name << "\n";
    else { std::cout << "FAIL " << name << ": " << why << "\n"; g_failed++; }
}

static std::string g_scratch;
static std::string writeFile(const std::string& name, const std::string& content)
{
    std::string p = g_scratch + "/" + name;
    std::ofstream f(p, std::ios::binary);
    f << content;
    return p;
}

template <class T> static std::string str(T v) { std::ostringstream ss; ss << v; return ss.str(); }

// A minimal 32-bit PE DLL: one section at RVA 0x1000 holding an export directory with two names.
static std::vector<char> makePE()
{
    std::vector<char> f(0x400, 0);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)&f[0];
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)&f[0x40];
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x14c;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x2102;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt->OptionalHeader.ImageBase = 0x10000000;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x1000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x80;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".edata", 6);
    sec->Misc.VirtualSize = 0x200;
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = 0x200;
    sec->Characteristics = 0x40000040;

    char* s = &f[0x200]; // RVA 0x1000
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)s;
    ed->Name = 0x1060;
    ed->Base = 1;
    ed->NumberOfFunctions = 2;
    ed->NumberOfNames = 2;
    ed->AddressOfFunctions = 0x1028;
    ed->AddressOfNames = 0x1030;
    ed->AddressOfNameOrdinals = 0x1038;
    DWORD funcs[2] = { 0x1100, 0x1180 };
    DWORD names[2] = { 0x1040, 0x1050 };
    WORD ords[2] = { 1, 0 };
    memcpy(s + 0x28, funcs, sizeof(funcs));
    memcpy(s + 0x30, names, sizeof(names));
    memcpy(s + 0x38, ords, sizeof(ords));
    strcpy(s + 0x40, "AlphaFunc");
    strcpy(s + 0x50, "BetaFunc");
    strcpy(s + 0x60, "tt_sample.dll");
    return f;
}

static void testIni(const std::string& root)
{
    Settings s;
    std::string p = writeFile("custom.ini",
        "FOLLOW_SHELLCODES=3\n"
        "HEXDUMP_SIZE = 16 ; trailing comment\n"
        "TRACE_RDTSC=yes\n"
        "TRACE_SYSCALL=off\n"
        "VOLUME_ID=ABCD\n"
        "SLEEP_TIME=42\n"
        "ANTIDEBUG=7\n"
        "FLUSH_INTERVAL=(-1)\n"
        "not a setting\n"
        "#HOOK_SLEEP=True\n");
    bool filled = s.loadINI(p);
    check("ini_filled", filled);
    check("ini_follow_shellcodes", (int)s.followShellcode == 3, str((int)s.followShellcode));
    check("ini_hexdump_size", s.hexdumpSize == 16, str(s.hexdumpSize));
    check("ini_bool_yes_off", s.traceRDTSC && !s.traceSYSCALL);
    check("ini_volume_id_hex", s.volumeID == 0xABCD, str(s.volumeID));
    check("ini_sleep_time", s.sleepTime == 42, str(s.sleepTime));
    check("ini_antidebug_clamped", (int)s.antidebug == 2, str((int)s.antidebug));
    check("ini_flush_paren_negative", s.flushInterval == -1, str(s.flushInterval));
    check("ini_comment_ignored", s.hookSleep == false);

    Settings d;
    bool ok = d.loadINI(root + "/install32_64/TinyTracer.ini");
    check("ini_shipped_defaults", ok && d.sleepTime == 10 && d.stopOffsetTime == 30 && (int)d.disasmDepth == 3
        && d.logSectTrans && !d.parseExports && (int)d.followShellcode == 1,
        str(d.sleepTime) + "/" + str(d.stopOffsetTime) + "/" + str((int)d.disasmDepth));
}

static void testWatchList(const std::string& root)
{
    Settings s;
    size_t n = s.funcWatch.loadList((root + "/install32_64/params.txt").c_str(), &s.excludedFuncs);
    check("params_shipped_count", n == 5 && s.funcWatch.funcs.size() == 5, str(n));
    check("params_shipped_first", s.funcWatch.funcs.size() > 0 && s.funcWatch.funcs[0].dllName == "kernel32"
        && s.funcWatch.funcs[0].funcName == "LoadLibraryW" && s.funcWatch.funcs[0].paramCount == 1);

    Settings e;
    std::string ex = writeFile("excluded.txt", "ntdll\n  user32.dll  \nkernel32;Sleep\n\n");
    size_t en = e.loadExcluded(ex.c_str());
    check("excluded_count", en == 3, str(en));
    check("excluded_dlls", e.excludedDll.count("ntdll") == 1 && e.excludedDll.count("user32.dll") == 1);
    check("excluded_func", e.excludedFuncs.contains("C:\\Windows\\System32\\KERNEL32.dll", "Sleep"));

    std::string wl = writeFile("watch.txt",
        "# comment\n"
        "kernel32;Sleep;1\n"
        "advapi32;RegOpenKeyExW;5\n"
        "ADVAPI32;regopenkeyexw;2\n"
        "<SYSCALL>;0x55;4\n"
        "<SYSCALL>;0x55;6\n"
        "justonefield\n");
    size_t wn = e.funcWatch.loadList(wl.c_str(), &e.excludedFuncs);
    check("watch_excluded_skipped", wn == 1 && e.funcWatch.funcs.size() == 1, str(wn));
    check("watch_merge_param_count", e.funcWatch.funcs.size() == 1 && e.funcWatch.funcs[0].paramCount == 5);
    check("watch_syscall", e.funcWatch.syscalls.size() == 1 && e.funcWatch.syscalls.count(0x55)
        && e.funcWatch.syscalls[0x55].paramCount == 6);
}

static void testTables()
{
    Settings s;
    std::string sp = writeFile("syscalls.txt", "0x10,NtOpenFile\n2a,NtClose\nnocomma\n");
    size_t sn = s.syscallsTable.load(sp);
    check("syscalls_count", sn == 2, str(sn));
    check("syscalls_lookup", s.syscallsTable.getName(0x2a) == "NtClose" && s.syscallsTable.getName(0x10) == "NtOpenFile"
        && s.syscallsTable.getName(0x11) == "");

    std::string cp = writeFile("defs.tag", "0x1000,start\n# skip\n2000,second\n");
    size_t cn = Settings::loadCustomDefs(cp.c_str(), s.customDefs);
    check("customdefs", cn == 2 && s.customDefs[0x1000] == "start" && s.customDefs[0x2000] == "second", str(cn));

    std::string dp = writeFile("ranges.csv", "0x10,0x20,myrange\n0x30,0x40\n0,0x50\n");
    size_t dn = Settings::loadDisasmRanges(dp.c_str(), s.disasmRanges);
    std::string label;
    check("disasm_ranges_count", dn == 2, str(dn));
    check("disasm_ranges_lookup", s.findInDisasmRange(0x15, &label) == DISASM_IN_RANGE && label == "myrange"
        && s.findInDisasmRange(0x30, &label) == DISASM_START && label == "Range_1"
        && s.findInDisasmRange(0x45) == DISASM_NONE);

    std::string op = writeFile("stop_offsets.txt", "0x100;3\n#0x150\n200\n0;5\n");
    size_t on = Settings::loadStopOffsetsList(op.c_str(), s.stopOffsets);
    bool times = false;
    for (auto& so : s.stopOffsets) if (so.rva == 0x100) times = (so.times == 3);
    check("stop_offsets", on == 2 && times, str(on));
}

static void testExports()
{
    std::vector<char> pe = makePE();
    std::string p = writeFile("tt_sample.dll", std::string(pe.begin(), pe.end()));
    g_pin_stub_created_rtns.clear();
    IMG img;
    img.path = p;
    img.base = 0x400000;
    size_t n = ExportsInfo::addFromFile(img);
    check("exports_count", n == 2, str(n));
    bool alpha = false, beta = false;
    for (auto& r : g_pin_stub_created_rtns) {
        if (r.second == "AlphaFunc") alpha = (r.first == 0x400000 + 0x1180);
        if (r.second == "BetaFunc") beta = (r.first == 0x400000 + 0x1100);
    }
    check("exports_names_addresses", alpha && beta && g_pin_stub_created_rtns.size() == 2);

    pe[0] = 'X';
    std::string bad = writeFile("bad.dll", std::string(pe.begin(), pe.end()));
    img.path = bad;
    check("exports_reject_bad_magic", ExportsInfo::addFromFile(img) == 0);
}

int main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--write-pe") {
        std::vector<char> pe = makePE();
        std::ofstream f(argv[2], std::ios::binary);
        f.write(&pe[0], pe.size());
        return f ? 0 : 1;
    }
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <repo root> <scratch dir>\n";
        return 2;
    }
    g_scratch = argv[2];
    testIni(argv[1]);
    testWatchList(argv[1]);
    testTables();
    testExports();
    return g_failed ? 1 : 0;
}
