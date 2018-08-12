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

struct rfc6479_window;

size_t rfc6479_sizeof();

int rfc6479_check_replay_window(const struct rfc6479_window *w, uint64_t sequence_number);

int rfc6479_update_replay_window(struct rfc6479_window *w, uint64_t sequence_number);

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

static void bench_rfc2401() {
    volatile sig_atomic_t running = true;
    timer_t t = setup_timer((void*) &running);
    struct timespec t1, t2;
    uint64_t runs;

    // 0% hit
    struct rfc2401_window w = {};
    rfc2401_update(&w, 164);
    rfc2401_update(&w, 162);
    rfc2401_update(&w, 102);
    rfc2401_update(&w, 120);
    rfc2401_update(&w, 145);
    runs = 0;
    reset_timer(t);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    while (running) {
        assert(!rfc2401_is_valid(&w, 164 - 64));
        assert(!rfc2401_is_valid(&w, 164 - 100));
        assert(!rfc2401_is_valid(&w, 164 - 65));
        assert(!rfc2401_is_valid(&w, 162));
        assert(!rfc2401_is_valid(&w, 164 - 70));
        assert(!rfc2401_is_valid(&w, 164 - 80));
        assert(!rfc2401_is_valid(&w, 164 - 80));
        assert(!rfc2401_is_valid(&w, 164));
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
        rfc2401_update(&w, 164 - 64);
        rfc2401_update(&w, 164 - 100);
        rfc2401_update(&w, 164 - 65);
        rfc2401_update(&w, 162);
        rfc2401_update(&w, 164 - 70);
        rfc2401_update(&w, 164 - 80);
        rfc2401_update(&w, 164 - 80);
        rfc2401_update(&w, 164);
        runs += 8;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    uint64_t elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
    double secs_up = elapsed_up / 1e9;
    double ops_up = runs / secs_up;

    printf("%s_0%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);


    // 50% hit
    runs = 0;
    running = true;
    reset_timer(t);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    while (running) {
        assert(rfc2401_is_valid(&w, 164 - 10));
        assert(!rfc2401_is_valid(&w, 164 - 100));
        assert(rfc2401_is_valid(&w, 164 - 30));
        assert(rfc2401_is_valid(&w, 163));
        assert(!rfc2401_is_valid(&w, 164 - 70));
        assert(!rfc2401_is_valid(&w, 162));
        assert(rfc2401_is_valid(&w, 165));
        assert(!rfc2401_is_valid(&w, 164));
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
        rfc2401_update(&w, runs + 164 + 1);
        rfc2401_update(&w, 0);
        rfc2401_update(&w, runs + 164 - 2);
        rfc2401_update(&w, runs + 164 + 3);
        rfc2401_update(&w, runs + 164 - 4);
        rfc2401_update(&w, runs + 164 + 5);
        rfc2401_update(&w, runs + 164 - 6);
        rfc2401_update(&w, runs + 164 + 7);
        runs += 8;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
    secs_up = elapsed_up / 1e9;
    ops_up = runs / secs_up;

    printf("%s_50%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);


    // 100% hit
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
        assert(rfc2401_is_valid(&w, 800));
        assert(rfc2401_is_valid(&w, 144));
        assert(rfc2401_is_valid(&w, 163));
        assert(rfc2401_is_valid(&w, 400));
        assert(rfc2401_is_valid(&w, 101));
        assert(rfc2401_is_valid(&w, 260));
        assert(rfc2401_is_valid(&w, 121));
        assert(rfc2401_is_valid(&w, 169));
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
        rfc2401_update(&w, runs + 0);
        rfc2401_update(&w, runs + 1);
        rfc2401_update(&w, runs - 2);
        rfc2401_update(&w, runs - 3);
        rfc2401_update(&w, runs + 4);
        rfc2401_update(&w, runs - 5);
        rfc2401_update(&w, runs + 6);
        rfc2401_update(&w, runs - 7);
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
    secs_up = elapsed_up / 1e9;
    ops_up = runs / secs_up;

    printf("%s_100%%, %.2lf, %.2lf\n", "rfc2401", ops_check, ops_up);
}

static void bench_rfc6479() {
    volatile sig_atomic_t running = true;
    timer_t t = setup_timer((void*) &running);
    struct timespec t1, t2;
    uint64_t runs;

    // 0% hit
    struct rfc6479_window *w = calloc(rfc6479_sizeof(), 1);
    rfc6479_update_replay_window(w, 2000);
    rfc6479_update_replay_window(w, 2000 - 512);
    rfc6479_update_replay_window(w, 2000 - 1);
    rfc6479_update_replay_window(w, 2000 - 10);
    rfc6479_update_replay_window(w, 2000 - 100);
    runs = 0;
    reset_timer(t);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    while (running) {
        assert(!rfc6479_check_replay_window(w, 2000 - 1024 - 1));
        assert(!rfc6479_check_replay_window(w, 164 - 100));
        assert(!rfc6479_check_replay_window(w, 164 - 65));
        assert(!rfc6479_check_replay_window(w, 162));
        assert(!rfc6479_check_replay_window(w, 164 - 70));
        assert(!rfc6479_check_replay_window(w, 164 - 80));
        assert(!rfc6479_check_replay_window(w, 164 - 80));
        assert(!rfc6479_check_replay_window(w, 164));
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
        assert(!rfc6479_update_replay_window(w, 2000));
        assert(!rfc6479_update_replay_window(w, 2000 - 1024 - 1));
        assert(!rfc6479_update_replay_window(w, 2000 - 512));
        assert(!rfc6479_update_replay_window(w, 2000 - 1));
        assert(!rfc6479_update_replay_window(w, 2000 - 10));
        assert(!rfc6479_update_replay_window(w, 2000 - 100));
        runs += 6;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    uint64_t elapsed_up = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
    double secs_up = elapsed_up / 1e9;
    double ops_up = runs / secs_up;

    printf("%s_0%%, %.2lf, %.2lf\n", "rfc6479", ops_check, ops_up);
}

int main() {
    printf("# implementation, check_ops_per_second, update_ops_per_second\n");
    bench_rfc6479();
    bench_rfc2401();
}
