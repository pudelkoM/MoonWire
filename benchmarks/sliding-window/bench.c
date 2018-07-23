#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <assert.h>

struct rfc2401_window {
    uint64_t bitmap;
    uint64_t lastSeq; 
};

/* Returns false if packet disallowed, true if packet permitted */
bool rfc2401_is_valid(const struct rfc2401_window* window, uint64_t seq);

/* Updates the window */
void rfc2401_update(struct rfc2401_window* window, uint64_t seq);

static void handler(union sigval sv) {
    volatile sig_atomic_t *flag = sv.sival_ptr;
    *flag = false;
}

static timer_t setup_timer(void *flag) {
    timer_t timerid;

    struct sigevent sev = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_signo = 0,
        .sigev_value.sival_ptr = flag,
        .sigev_notify_function = handler,
        .sigev_notify_attributes = NULL,
    };

    int err = timer_create(CLOCK_MONOTONIC, &sev, &timerid);
    if (err) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    return timerid;
}

static void reset_timer(timer_t timerid) {
    struct itimerspec its = {
        .it_value.tv_sec = 2,
        .it_value.tv_nsec = 0
    };
    int err = timer_settime(timerid, 0, &its, NULL);
    if (err) {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }
}

int main() {
    printf("%lu\n", 1ul << 63);

    printf("# implementation, check_ops_per_second, update_ops_per_second\n");

    volatile sig_atomic_t running = true;
    timer_t t = setup_timer((void*) &running);
    struct timespec t1, t2;

    struct bench {
        const char* name;
        void* obj;
        bool (*check_fn)(const void*, uint64_t);
        void (*update_fn)(void*, uint64_t);
    };

    struct rfc2401_window w = {};
    rfc2401_update(&w, 164);
    rfc2401_update(&w, 162);
    rfc2401_update(&w, 102);
    rfc2401_update(&w, 120);
    rfc2401_update(&w, 145);
    printf("%lu %lx\n", w.lastSeq, w.bitmap);

    struct bench b[] = {
        {"rfc_2401", &w, rfc2401_is_valid, rfc2401_update}
    };

    // TODO: bench failure/success/mixed cases

    for (size_t i = 0; i < sizeof(b) / sizeof(*b); ++i) {
        uint64_t runs;

        // 0% valid
        runs = 0;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            assert(!b[i].check_fn(&w, 164 - 64));
            assert(!b[i].check_fn(&w, 164 - 100));
            assert(!b[i].check_fn(&w, 164 - 65));
            assert(!b[i].check_fn(&w, 162));
            assert(!b[i].check_fn(&w, 164 - 70));
            assert(!b[i].check_fn(&w, 164 - 80));
            assert(!b[i].check_fn(&w, 164 - 80));
            assert(!b[i].check_fn(&w, 164));
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        uint64_t elapsed_check = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        double secs_check = elapsed_check / 1e9;
        double ops_check = runs / secs_check;

        runs = 0;
        running = true;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            b[i].update_fn(&w, 164 - 64);
            b[i].update_fn(&w, 164 - 100);
            b[i].update_fn(&w, 164 - 65);
            b[i].update_fn(&w, 162);
            b[i].update_fn(&w, 164 - 70);
            b[i].update_fn(&w, 164 - 80);
            b[i].update_fn(&w, 164 - 80);
            b[i].update_fn(&w, 164);
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        uint64_t elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        double secs_up = elapsed_up / 1e9;
        double ops_up = runs / secs_up;

        printf("%s_0%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);


        // 50% valid
        runs = 0;
        running = true;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            assert(b[i].check_fn(&w, 164 - 10));
            assert(!b[i].check_fn(&w, 164 - 100));
            assert(b[i].check_fn(&w, 164 - 30));
            assert(b[i].check_fn(&w, 163));
            assert(!b[i].check_fn(&w, 164 - 70));
            assert(!b[i].check_fn(&w, 162));
            assert(b[i].check_fn(&w, 165));
            assert(!b[i].check_fn(&w, 164));
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        elapsed_check = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        secs_check = elapsed_check / 1e9;
        ops_check = runs / secs_check;

        runs = 0;
        running = true;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            b[i].update_fn(&w, runs + 164 + 1);
            b[i].update_fn(&w, 0);
            b[i].update_fn(&w, runs + 164 - 2);
            b[i].update_fn(&w, runs + 164 + 3);
            b[i].update_fn(&w, runs + 164 - 4);
            b[i].update_fn(&w, runs + 164 + 5);
            b[i].update_fn(&w, runs + 164 - 6);
            b[i].update_fn(&w, runs + 164 + 7);
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        secs_up = elapsed_up / 1e9;
        ops_up = runs / secs_up;

        printf("%s_50%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);


        // 100% valid
        w = (struct rfc2401_window) {};
        rfc2401_update(&w, 164);
        rfc2401_update(&w, 162);
        rfc2401_update(&w, 102);
        rfc2401_update(&w, 120);
        rfc2401_update(&w, 145);
        runs = 0;
        running = true;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            assert(b[i].check_fn(&w, 800));
            assert(b[i].check_fn(&w, 144));
            assert(b[i].check_fn(&w, 163));
            assert(b[i].check_fn(&w, 400));
            assert(b[i].check_fn(&w, 101));
            assert(b[i].check_fn(&w, 260));
            assert(b[i].check_fn(&w, 121));
            assert(b[i].check_fn(&w, 169));
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        elapsed_check = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        secs_check = elapsed_check / 1e9;
        ops_check = runs / secs_check;

        runs = 0;
        running = true;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            runs += 8;
            b[i].update_fn(&w, runs + 0);
            b[i].update_fn(&w, runs + 1);
            b[i].update_fn(&w, runs - 2);
            b[i].update_fn(&w, runs - 3);
            b[i].update_fn(&w, runs + 4);
            b[i].update_fn(&w, runs - 5);
            b[i].update_fn(&w, runs + 6);
            b[i].update_fn(&w, runs - 7);
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        secs_up = elapsed_up / 1e9;
        ops_up = runs / secs_up;

        printf("%s_100%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);
    }
    
}