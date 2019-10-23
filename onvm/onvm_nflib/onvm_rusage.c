#include "onvm_rusage.h"

static struct timeval time_usage_delta(struct onvm_nf *nf);
static double timeval_to_double(struct timeval t);

void onvm_rusage_update(struct onvm_nf *nf) {
        struct timespec time;
        clock_gettime(CLOCK_REALTIME, &time);
        long t = (long)time.tv_sec + round(time.tv_nsec / 1.0e9);

        long update_interval = t - nf->resource_usage.last_update;

        if (update_interval >= RUSAGE_UPDATE_INTERVAL) {
                nf->resource_usage.last_rusage = nf->resource_usage.rusage;
                getrusage(RUSAGE_SELF, &nf->resource_usage.rusage);
                nf->resource_usage.last_update = t;
                nf->resource_usage.time_usage_delta = time_usage_delta(nf);
                nf->resource_usage.cpu_time_proportion = 
                    timeval_to_double(nf->resource_usage.time_usage_delta) / (double)update_interval;
        }
}

static struct timeval time_usage_delta(struct onvm_nf *nf) {
        struct timeval last_time;
        timeradd(&nf->resource_usage.last_rusage.ru_utime,
                 &nf->resource_usage.last_rusage.ru_stime,
                 &last_time);
        struct timeval this_time;
        timeradd(&nf->resource_usage.rusage.ru_utime,
                 &nf->resource_usage.rusage.ru_stime,
                 &this_time);

        if (!timercmp(&last_time, &this_time, <))
                return (struct timeval) {0, 0};

        struct timeval time_difference;
        timersub(&this_time, &last_time, &time_difference);

        return time_difference;
}

static double
timeval_to_double(struct timeval t) {
        return (double)t.tv_sec + ((double)t.tv_usec / 1.0e6);
}
