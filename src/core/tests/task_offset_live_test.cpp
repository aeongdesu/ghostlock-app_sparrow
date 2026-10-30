/*
 * Directly exercises require_task_offset() from the real header, with the
 * session profile populated and then cleared, to prove the accessor rejects a
 * missing value instead of substituting the retired 6.6 default.
 */
#include "kernel/constants.hpp"
#include "kernel/runtime_struct_offsets.h"
#include "session/exploit_session.hpp"
#include "support/fatal_error.hpp"

#include <cstdio>

namespace ghostlock::profile {
    [[noreturn]] void fatal_missing_task_offset(const char *name) {
        std::printf("rejected %s\n", name);
        throw ghostlock::FatalError{};
    }
} // namespace ghostlock::profile

int main() {
    using namespace ghostlock;

    profile::kernel_offsets decoded = {};
    decoded.uname_r = "test-release";
    decoded.task.prio = 0x84;
    decoded.task.cred = 0x880;
    /* seccomp deliberately left 0 */

    session::g_exploit_session.profile = profile::TargetProfile::from(&decoded);

    if (profile::fake_task_prio_off() != 0x84) {
        std::printf("FAIL prio\n");
        return 1;
    }
    if (profile::task_cred_off() != 0x880) {
        std::printf("FAIL cred\n");
        return 1;
    }
    bool threw = false;
    try {
        (void) profile::task_seccomp_off();
    } catch (const FatalError &) {
        threw = true;
    }
    if (!threw) {
        std::printf("FAIL: missing seccomp did not fail closed\n");
        return 1;
    }
    std::printf("pass\n");
    return 0;
}
