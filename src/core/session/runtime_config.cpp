#include "common.h"
#include "session/runtime_config.h"
#include "session/runtime_paths.h"

using namespace ghostlock;

/* Pick the first two CPUs the current process may run on. */
static bool runtime_config_pick_allowed_cpus(int32_t *main_cpu, int32_t *consumer_cpu) {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        return false;
    }

    int32_t first = -1;
    int32_t second = -1;
    for (int32_t cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &allowed)) { // NOLINT(clang-analyzer-security.ArrayBound)
            continue;
        }
        if (first < 0) {
            first = cpu;
        } else {
            second = cpu;
            break;
        }
    }
    if (first < 0 || second < 0) {
        return false;
    }
    *main_cpu = first;
    *consumer_cpu = second;
    return true;
}

static void runtime_config_init_cpus(config::RuntimeConfig *config) {
    config->main_cpu = 0;
    config->consumer_cpu = 1;

    int32_t main_cpu = 0;
    int32_t consumer_cpu = 1;
    if (runtime_config_pick_allowed_cpus(&main_cpu, &consumer_cpu)) {
        config->main_cpu = main_cpu;
        config->consumer_cpu = consumer_cpu;
    }
    if (config->main_cpu != 0 || config->consumer_cpu != 1) {
        pr_warning("using allowed CPU pair %d/%d\n",
                   config->main_cpu, config->consumer_cpu);
    }
}

static int32_t runtime_config_validate_cpus(config::RuntimeConfig *config) {
    if (config->main_cpu == config->consumer_cpu) {
        pr_warning("main and consumer cores are the same (%d)\n", config->main_cpu);
        return -1;
    }
    if (config->main_cpu < 0 || config->main_cpu >= CPU_SETSIZE ||
        config->consumer_cpu < 0 || config->consumer_cpu >= CPU_SETSIZE) {
        pr_warning("profile cores %d/%d are outside the supported CPU range\n",
                   config->main_cpu, config->consumer_cpu);
        return -1;
    }
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
        (!CPU_ISSET(config->main_cpu, &allowed) || // NOLINT(clang-analyzer-security.ArrayBound)
         !CPU_ISSET(config->consumer_cpu, &allowed))) { // NOLINT(clang-analyzer-security.ArrayBound)
        pr_warning("profile cores %d/%d not in allowed cpuset\n",
                   config->main_cpu, config->consumer_cpu);
        return -1;
    }
    return 0;
}

/* Apply profile CPU recommendations only where Kotlin/environment did not
 * make an explicit selection. Existing explicit choices remain authoritative. */
int32_t ghostlock::config::RuntimeConfig::apply_profile(const profile::TargetProfile *profile) {
    const profile::execution_settings *e = profile->execution();
    if (!e) return -1;
    int32_t old_main = main_cpu;
    int32_t old_consumer = consumer_cpu;
    main_cpu = static_cast<int32_t>(profile->recommended_main_cpu());
    consumer_cpu = static_cast<int32_t>(profile->recommended_consumer_cpu());
    if (runtime_config_validate_cpus(this) != 0) {
        main_cpu = old_main;
        consumer_cpu = old_consumer;
    }
    return 0;
}

/* Android moves the process between cpusets, so re-check right before the race. */
int32_t ghostlock::config::RuntimeConfig::revalidate_cpus() {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        pr_warning("cannot read cpuset; keeping cpu pair %d/%d\n",
                   main_cpu, consumer_cpu);
        return 0;
    }
    if (main_cpu >= 0 && main_cpu < CPU_SETSIZE &&
        consumer_cpu >= 0 && consumer_cpu < CPU_SETSIZE &&
        CPU_ISSET(main_cpu, &allowed) && CPU_ISSET(consumer_cpu, &allowed)) {
        return 0;
    }

    int32_t first = -1;
    int32_t second = -1;
    for (int32_t cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &allowed)) { // NOLINT(clang-analyzer-security.ArrayBound)
            continue;
        }
        if (first < 0) {
            first = cpu;
        } else {
            second = cpu;
            break;
        }
    }
    if (first < 0 || second < 0) {
        pr_error("cpuset %d/%d no longer allowed and no replacement pair exists\n",
                 main_cpu, consumer_cpu);
        return -1;
    }
    pr_warning("cpuset changed: cpu pair %d/%d -> %d/%d\n",
               main_cpu, consumer_cpu, first, second);
    main_cpu = first;
    consumer_cpu = second;
    return 0;
}

static void runtime_config_init_paths(config::RuntimeConfig *config) {
    const char *home = getenv("GHOSTLOCK_HOME");
    if (!home || !home[0]) home = getenv("TMPDIR");
    if (!home || !home[0]) home = "/data/local/tmp";

    config->home_dir = ghostlock::config::normalize_home_dir(home);
    config->root_script_path =
            ghostlock::config::root_script_file(config->home_dir);

    const char *ksu_log = getenv("GHOSTLOCK_KSU_LOG");
    config->ksu_log_path = (ksu_log && ksu_log[0])
                               ? std::string(ksu_log)
                               : config->home_dir + "/.ghostlock_ksu.log";

    /* The value is embedded in shell single quotes by write_root_script;
     * escape ' so a quote in the path cannot break the script. */
    const char *ksud = getenv("GHOSTLOCK_KSUD");
    if (ksud && ksud[0]) {
        std::string escaped;
        for (const char *p = ksud; *p; p++) {
            if (*p == '\'') escaped += "'\\''";
            else escaped += *p;
        }
        config->ksud_path = std::move(escaped);
    }
}

/* Capture all process environment and CPU/path choices exactly once. Input:
 * writable config; output: 0/-1 with the validated CPU pair. */
int32_t ghostlock::config::RuntimeConfig::init() {
    main_cpu = 0;
    consumer_cpu = 1;
    home_dir.clear();
    root_script_path.clear();
    ksu_log_path.clear();
    ksud_path.clear();
    debug_dir.clear();

    runtime_config_init_cpus(this);
    runtime_config_init_paths(this);

    return 0;
}

/* Log the immutable runtime snapshot. Input: initialized config; output: logs. */
void ghostlock::config::RuntimeConfig::log() const {
    pr_info("cpu pair: main=%d consumer=%d\n", main_cpu, consumer_cpu);
    pr_info("runtime home=%s script=%s\n", home_dir.c_str(),
            root_script_path.c_str());
}
