// fuzz_exports — tiny_tracer's manual PE export parser (ExportsInfo::addFromFile), which the Pintool
// runs on every loaded module's file when PARSE_EXPORTS is on. The input is the module file: it is
// written to a scratch file and handed over as the IMG's name, exactly as Pin reports a module path.
// The routine list kept by the pin.H stub is cleared before every input.
#include "pin.H"
#include "ExportsInfo.h"
#include "mini_pe.h"

#include <cstdlib>
#include <string>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Precondition from the caller's contract: Pin hands addFromFile only modules the OS loader has
    // mapped, and the loader rejects any file too short to hold the IMAGE_DOS_HEADER (it reads
    // e_magic/e_lfanew first). Shorter files cannot reach this code in a traced process.
    // Everything past the DOS header (e_lfanew, NT headers, sections, export directory) is fuzzed.
    if (size < sizeof(IMAGE_DOS_HEADER)) return -1;
    const char* tmp = getenv("TMPDIR");
    std::string tmpl = std::string((tmp && *tmp) ? tmp : "/tmp") + "/tt_moduleXXXXXX";
    int fd = mkstemp(&tmpl[0]);
    if (fd < 0) return 0;
    const uint8_t* p = data;
    size_t left = size;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) break;
        p += w;
        left -= (size_t)w;
    }
    close(fd);

    g_pin_stub_created_rtns.clear();
    IMG img;
    img.path = tmpl;
    ExportsInfo::addFromFile(img);
    unlink(tmpl.c_str());
    return 0;
}
