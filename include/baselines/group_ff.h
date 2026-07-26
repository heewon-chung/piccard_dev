#pragma once

#include "baselines/group.h"

#include <memory>

namespace piccard {
namespace baselines {

// DSA-style Z_p^* group (|p|=3072, |q|=256), GMP-backed. Faithful to BCG12's
// (EsPRESSo) own cost model, at NIST SP 800-57 Pt.1 Rev.5 Table 2's 128-bit
// security level (the paper's original was 80-bit, 1024/160).
std::unique_ptr<Group> MakeFiniteFieldGroup();

}  // namespace baselines
}  // namespace piccard
