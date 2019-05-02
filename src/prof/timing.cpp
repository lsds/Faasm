#include "prof/prof.h"

#include <util/logging.h>

namespace prof {
    util::TimePoint startTimer() {
        util::Clock &clock = util::getGlobalClock();
        return clock.now();
    }

    void logEndTimer(const std::string &label, const util::TimePoint &begin) {
        util::Clock &clock = util::getGlobalClock();
        util::TimePoint end = clock.now();

        long micros = clock.timeDiffMicro(end, begin);
        double millis = ((double) micros) / 1000;

        const std::shared_ptr<spdlog::logger> &l = util::getLogger();
        l->info("TIME = {:.2f}ms ({})", millis, label);
    }
}