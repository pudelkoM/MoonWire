#include <stdint.h>
#include <stddef.h>

// Naive replay check with sorted array of seen sequence numbers

#define NUMBER_OF_SLOTS 1024

struct sorted_array {
    uint64_t slots[NUMBER_OF_SLOTS];
};

int sorted_array_check_replay_window(const struct sorted_array *w, uint64_t sequence_number);
int sorted_array_update_replay_window(struct sorted_array *w, uint64_t sequence_number);
