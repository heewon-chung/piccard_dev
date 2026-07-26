#pragma once

#include "baselines/group.h"

#include <memory>

namespace piccard {
namespace baselines {

// NIST P-256 group (OpenSSL-backed). 128-bit security (FIPS 186-4), the
// modern/fastest-reasonable secondary backend alongside the FF group.
std::unique_ptr<Group> MakeEcGroup();

}  // namespace baselines
}  // namespace piccard
