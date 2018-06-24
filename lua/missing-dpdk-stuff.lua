local ffi = require "ffi"
local dpdk_export_lib = ffi.load("../build/dpdk-pktmbuf-export")

ffi.cdef[[
    uint16_t rte_pktmbuf_headroom_export(const struct rte_mbuf *m);
    uint16_t rte_pktmbuf_tailroom_export(const struct rte_mbuf *m);
    void rte_pktmbuf_reset_headroom_export(struct rte_mbuf *m);
    char *rte_pktmbuf_prepend_export(struct rte_mbuf *m, uint16_t len);
    char *rte_pktmbuf_append_export(struct rte_mbuf *m, uint16_t len);
    char *rte_pktmbuf_adj_export(struct rte_mbuf *m, uint16_t len);
    int rte_pktmbuf_trim_export(struct rte_mbuf *m, uint16_t len);
]]

return dpdk_export_lib
