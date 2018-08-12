/**
 * Copyright (c) 2012 IETF Trust and the persons identified as
 * authors of the code. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted pursuant to, and subject to the license
 * terms contained in, the Simplified BSD License set forth in Section
 * 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
 * (http://trustee.ietf.org/license-info).
 *
 */

/**
 * In this algorithm, the hidden window size must be a power of two,
 * for example, 1024 bits.  The redundant bits must also be a power of
 * two, for example 32 bits.  Thus, the supported anti-replay window
 * size is the hidden window size minus the redundant bits.  It is 992
 * in this example.  The size of the integer depends on microprocessor
 * architecture.  In this example, we assume that the software runs on
 * a 32-bit microprocessor.  So the size of the integer is 32.  In order
 * to convert the bitmap into an array of integers, the total number of
 * integers is the hidden window size divided by the size of the
 * integer.
 *
 * struct rfc6479_window contains the window and window related parameters,
 * such as the window size and the last acknowledged sequence number.
 *
 * all the value of macro can be changed, but must follow the rule
 * defined in the algorithm.
 */

#include <stdint.h>
#include <stddef.h>

#define SIZE_OF_INTEGER sizeof(uint64_t)
#define REPLAY_WINDOW_SIZE 1024
#define BITMAP_LEN (REPLAY_WINDOW_SIZE / SIZE_OF_INTEGER)
#define BITMAP_INDEX_MASK (BITMAP_LEN - 1)
#define REDUNDANT_BITS (SIZE_OF_INTEGER * 8u) /* Redundant for index calculation */
#define REDUNDANT_BIT_SHIFTS 6u /** log2(REDUNDANT_BITS) */
#define BITMAP_LOC_MASK (REDUNDANT_BITS - 1)

_Static_assert(REPLAY_WINDOW_SIZE && ((REPLAY_WINDOW_SIZE & (REPLAY_WINDOW_SIZE - 1)) == 0), "Window size is not a power of 2");
_Static_assert(1 << REDUNDANT_BIT_SHIFTS == REDUNDANT_BITS, "Bit calculations do not match up");

struct rfc6479_window {
    uint64_t replaywin_lastseq;
    uint64_t replaywin_bitmap[BITMAP_LEN];
};

/* Helper function for LuaJIT bindings */
size_t rfc6479_sizeof() {
    return sizeof(struct rfc6479_window);
}

int rfc6479_check_replay_window(const struct rfc6479_window *w, uint64_t sequence_number) {
    uint32_t bit_location;
    uint32_t index;

    /* first check if the sequence number is in the range */
    if (sequence_number > w->replaywin_lastseq) {
        return 1; /** larger is always good */
    }

    /* The packet is too old and out of the window */
    if ((sequence_number + REPLAY_WINDOW_SIZE) < w->replaywin_lastseq) {
        return 0;
    }

    /**
     * The sequence is inside the sliding window
     * now check the bit in the bitmap
     * bit location only depends on the sequence number
     */
    bit_location = sequence_number & BITMAP_LOC_MASK;
    index = (sequence_number >> REDUNDANT_BIT_SHIFTS) & BITMAP_INDEX_MASK;

    /* this packet has already been received */
    if (w->replaywin_bitmap[index] & (1 << bit_location)) {
        return 0;
    }

    return 1;
}

int rfc6479_update_replay_window(struct rfc6479_window *w, uint64_t sequence_number) {
    uint32_t bit_location;
    uint32_t index, index_cur, id;
    uint32_t diff;

    // the packet is too old, no need to update
    if ((sequence_number + REPLAY_WINDOW_SIZE) < w->replaywin_lastseq) {
        return 0;
    }

    // now update the bit
    index = (sequence_number >> REDUNDANT_BIT_SHIFTS);

    // first check if the sequence number is in the range
    if (sequence_number > w->replaywin_lastseq) {
        index_cur = w->replaywin_lastseq >> REDUNDANT_BIT_SHIFTS;
        diff = index - index_cur;
        if (diff > BITMAP_LEN) { /* something unusual in this case */
            diff = BITMAP_LEN;
        }

        for (id = 0; id < diff; ++id) {
            w->replaywin_bitmap[(id + index_cur + 1) & BITMAP_INDEX_MASK] = 0;
        }

        w->replaywin_lastseq = sequence_number;
    }

    index &= BITMAP_INDEX_MASK;
    bit_location = sequence_number & BITMAP_LOC_MASK;

    /* this packet has already been received */
    if (w->replaywin_bitmap[index] & (1 << bit_location)) {
        return 0;
    }

    w->replaywin_bitmap[index] |= (1 << bit_location);

    return 1;
}
