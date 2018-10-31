#include <rte_mbuf.h>
#include <rte_spinlock.h>

uint16_t rte_pktmbuf_headroom_export(const struct rte_mbuf *m) {
    return rte_pktmbuf_headroom(m);
}

uint16_t rte_pktmbuf_tailroom_export(const struct rte_mbuf *m) {
    return rte_pktmbuf_tailroom(m);
}

void rte_pktmbuf_reset_headroom_export(struct rte_mbuf *m) {
    rte_pktmbuf_reset_headroom(m);
}

char *rte_pktmbuf_prepend_export(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_prepend(m, len);
}

char *rte_pktmbuf_append_export(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_append(m, len);
}

char *rte_pktmbuf_adj_export(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_adj(m, len);
}

int rte_pktmbuf_trim_export(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_trim(m, len);
}


void rte_spinlock_init_export(rte_spinlock_t *sl) {
    rte_spinlock_init(sl);
}

void rte_spinlock_lock_export(rte_spinlock_t *sl) {
    rte_spinlock_lock(sl);
}

void rte_spinlock_unlock_export(rte_spinlock_t *sl) {
    rte_spinlock_unlock(sl);
}

int rte_spinlock_trylock_export(rte_spinlock_t *sl) {
    return rte_spinlock_trylock(sl);
}
int rte_spinlock_is_locked_export(rte_spinlock_t *sl) {
    return rte_spinlock_is_locked(sl);
}

int rte_mempool_get_bulk_export(struct rte_mempool *mp, void **obj_table, unsigned int n) {
    return rte_mempool_get_bulk(mp, obj_table, n);
}

void rte_mempool_put_bulk_export(struct rte_mempool *mp, void *const *obj_table, unsigned int n) {
    rte_mempool_put_bulk(mp, obj_table, n);
}

void rte_mempool_put_export(struct rte_mempool *mp, void *obj) {
    rte_mempool_put(mp, obj);
}
