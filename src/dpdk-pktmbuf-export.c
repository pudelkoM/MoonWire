#include <rte_mbuf.h>

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
