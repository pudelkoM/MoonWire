local ffi = require "ffi"
local dpdk_export_lib = ffi.load("./build/dpdk-pktmbuf-export")

ffi.cdef[[
    uint16_t rte_pktmbuf_headroom_export(const struct rte_mbuf *m);
    uint16_t rte_pktmbuf_tailroom_export(const struct rte_mbuf *m);
    void rte_pktmbuf_reset_headroom_export(struct rte_mbuf *m);
    char *rte_pktmbuf_prepend_export(struct rte_mbuf *m, uint16_t len);
    char *rte_pktmbuf_append_export(struct rte_mbuf *m, uint16_t len);
    char *rte_pktmbuf_adj_export(struct rte_mbuf *m, uint16_t len);
    int rte_pktmbuf_trim_export(struct rte_mbuf *m, uint16_t len);

    typedef struct rte_spinlock {
        volatile int locked;
    } rte_spinlock_t;
    void rte_spinlock_init_export(rte_spinlock_t *sl);
    void rte_spinlock_lock_export(rte_spinlock_t *sl);
    void rte_spinlock_unlock_export(rte_spinlock_t *sl);
    int rte_spinlock_trylock_export(rte_spinlock_t *sl);
    int rte_spinlock_is_locked_export(rte_spinlock_t *sl);

    int rte_mempool_get_bulk_export(struct rte_mempool *mp, void **obj_table, unsigned int n);
    void rte_mempool_put_bulk_export(struct rte_mempool *mp, void *const *obj_table, unsigned int n);
    void rte_mempool_put_export(struct rte_mempool *mp, void *obj);
]]

return dpdk_export_lib
