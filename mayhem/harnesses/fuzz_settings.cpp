// fuzz_settings — tiny_tracer's configuration/list loaders, as the Pintool runs them at startup on the
// files next to the tracer (TinyTracer.ini, params.txt watch list, excluded.txt, the syscalls table,
// <module>.tag-style custom defs, *.disasm_range.csv and stop_offsets.txt).
// The first byte picks the loader; the rest is written to a scratch file and passed by path, which is
// the loaders' public interface. Every input gets a fresh Settings object; nothing is kept between runs.
#include "Settings.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

static std::string scratch_template()
{
    const char* tmp = getenv("TMPDIR");
    std::string dir = (tmp && *tmp) ? tmp : "/tmp";
    return dir + "/tt_settingsXXXXXX";
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1) return -1;
    std::string tmpl = scratch_template();
    int fd = mkstemp(&tmpl[0]);
    if (fd < 0) return 0;
    const uint8_t* p = data + 1;
    size_t left = size - 1;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) break;
        p += w;
        left -= (size_t)w;
    }
    close(fd);
    const char* path = tmpl.c_str();

    Settings s;
    switch (data[0] % 7) {
    case 0: s.loadINI(path); break;
    case 1: s.funcWatch.loadList(path, &s.excludedFuncs); break;
    case 2: s.loadExcluded(path); break;
    case 3: s.syscallsTable.load(path); break;
    case 4: Settings::loadCustomDefs(path, s.customDefs); break;
    case 5: Settings::loadDisasmRanges(path, s.disasmRanges); break;
    case 6: Settings::loadStopOffsetsList(path, s.stopOffsets); break;
    }
    unlink(path);
    return 0;
}
