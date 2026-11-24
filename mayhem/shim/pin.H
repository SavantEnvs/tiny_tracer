// mayhem/shim/pin.H — a minimal stand-in for Intel Pin's pin.H, used ONLY by the fuzz harnesses and
// the self-test in mayhem/. It lets tiny_tracer's input parsers (Settings.cpp, FuncWatch.cpp,
// Util.cpp, ExportsInfo.cpp) compile and run outside a Pin-instrumented process. The Pin kit is a
// proprietary download whose runtime JITs a traced child process, which cannot host a sanitized
// in-process fuzzer, so the real pin.H is not used here.
//
// It is force-included (-include) because upstream's FuncWatch.h/Util.h use uint8_t/uint32_t and
// Pin typedefs without including them (in the real build pin.H always comes first).
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>  // the real pin.H pulls in the C string API; ExportsInfo.cpp relies on it
#include <string>
#include <vector>

typedef uintptr_t ADDRINT;
typedef void VOID;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint32_t THREADID;
typedef char CHAR;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef bool BOOL;
typedef uint64_t UINT64;
#ifndef TRUE
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

struct CONTEXT;
struct SEC {};
struct INS {};
// IMG: the loaded module. In this stub the module is a file on disk named by `path`, loaded at `base`.
struct IMG { std::string path; ADDRINT base = 0x10000; bool valid = true; };
// RTN: a routine at an address; `valid` is false for "not found".
struct RTN { ADDRINT addr = 0; bool valid = false; };

// Routines created via RTN_CreateAt (Pin would add them to the image's symbol list).
inline std::vector<std::pair<ADDRINT, std::string>> g_pin_stub_created_rtns;

// Pin: "returns TRUE if the address is readable" — the parsers only run on process memory we own.
static inline bool PIN_CheckReadAccess(void*) { return true; }

static inline BOOL IMG_Valid(IMG img) { return img.valid; }
static inline ADDRINT IMG_LoadOffset(IMG img) { return img.base; }
static inline ADDRINT IMG_LowAddress(IMG img) { return img.base; }
static inline const std::string& IMG_Name(const IMG& img) { return img.path; }

static inline RTN RTN_FindByAddress(ADDRINT addr)
{
    for (const auto& r : g_pin_stub_created_rtns) {
        if (r.first == addr) return RTN{ addr, true };
    }
    return RTN{};
}
static inline ADDRINT RTN_Address(RTN rtn) { return rtn.valid ? rtn.addr : 0; }
// Pin's signature: RTN RTN_CreateAt(ADDRINT address, std::string name) — the caller builds the
// std::string from its const char*, exactly as in the real Pin build.
static inline RTN RTN_CreateAt(ADDRINT addr, std::string name)
{
    g_pin_stub_created_rtns.emplace_back(addr, name);
    return RTN{ addr, true };
}
