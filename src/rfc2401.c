/*   
   This appendix contains a routine that implements a bitmask check for
   a 32 packet window.  It was provided by James Hughes
   (jim_hughes@stortek.com) and Harry Varnis (hgv@anubis.network.com)
   and is intended as an implementation example.  Note that this code
   both checks for a replay and updates the window.  Thus the algorithm,
   as shown, should only be called AFTER the packet has been
   authenticated.  Implementers might wish to consider splitting the
   code to do the check for replays before computing the ICV.  If the
   packet is not a replay, the code would then compute the ICV, (discard
   any bad packets), and if the packet is OK, update the window.
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

enum {
    rfc2401_replay_window_size = sizeof(uint64_t) * 8
};

struct rfc2401_window {
    uint64_t bitmap;
    uint64_t lastSeq; 
};

/* Returns false if packet disallowed, true if packet permitted */
bool rfc2401_is_valid(const struct rfc2401_window* window, uint64_t seq);

/* Updates the window */
void rfc2401_update(struct rfc2401_window* window, uint64_t seq);

bool rfc2401_is_valid(const struct rfc2401_window* window, uint64_t seq) {
    if (seq > window->lastSeq) /* larger than already seen */
        return true;
    uint64_t diff = window->lastSeq - seq;
    if (diff >= rfc2401_replay_window_size) /* too old or wrapped */
        return false;
    if (window->bitmap & (UINT64_C(1) << diff)) /* already seen */
        return false;

    return true;
}

void rfc2401_update(struct rfc2401_window* window, uint64_t seq) {
    uint64_t diff;

    if (seq > window->lastSeq) { /* new larger sequence number */
        diff = seq - window->lastSeq;
        if (diff < rfc2401_replay_window_size) { /* In window */
            window->bitmap <<= diff;
            window->bitmap |= UINT64_C(1); /* set bit for this packet */
        } else {
            window->bitmap = UINT64_C(1); /* This packet has a "way larger" */
        }
        window->lastSeq = seq;
    } else {
        diff = window->lastSeq - seq;
        if (diff >= rfc2401_replay_window_size)
            return; /* too old or wrapped */
        if (window->bitmap & (UINT64_C(1) << diff))
            return; /* already seen */
        window->bitmap |= (UINT64_C(1) << diff); /* mark as seen */
    }
}
