// No-OpenFHE stand-in for real_timing_driver.cpp (Work 5 Sub-phase 5.4).
//
// CMakeLists.txt compiles this translation unit into bench_real_datasets
// instead of real_timing_driver.cpp whenever OpenFHE is not available, so
// the bench_real_datasets executable keeps building unconditionally (see
// the comment above its add_executable() call) even on a machine without a
// usable OpenFHE install. --mode=accuracy is completely unaffected: it
// never links this file's caller path differently.
#include "real_timing_driver.h"

#include <stdexcept>

namespace piccard::bench {

int RunRealTimingMode(const RealTimingCliArgs&) {
    throw std::runtime_error(
        "bench_real_datasets was built without OpenFHE support; "
        "--mode=timing is unavailable in this build");
}

}  // namespace piccard::bench
