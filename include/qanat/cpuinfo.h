#ifndef QANAT_CPUINFO_H
#define QANAT_CPUINFO_H

#include "qanat/util.h"

#define QN_MAX_CPUS     32
#define QN_MAX_CLUSTERS 4

typedef struct {
    uint32_t id;
    uint32_t max_khz;
    uint8_t  cluster;
    uint8_t  online;
    uint8_t  _pad[2];
} qn_cpu;

/* Clusters are ordered fastest first. */
typedef struct {
    uint32_t khz;
    uint32_t count;
    uint32_t first;
    uint32_t mask;
} qn_cluster;

typedef struct {
    qn_cpu   cpu[QN_MAX_CPUS];
    uint32_t ncpu;
    uint32_t nonline;

    qn_cluster cluster[QN_MAX_CLUSTERS];
    uint32_t   nclusters;

    uint32_t perf_mask;
    uint32_t perf_count;
    bool     heterogeneous;

    bool has_neon;
    bool has_asimddp;
    bool has_crc32;

    char soc[64];
} qn_topology;

void qn_topology_detect(qn_topology *t);

/* Uses performance and mid cores for I/O-bound work. */
uint32_t qn_topology_workers(const qn_topology *t, bool io_bound);

/* Affinity is best-effort under Android cpusets. */
bool qn_pin_thread(uint32_t cpu);
bool qn_pin_thread_mask(uint32_t mask);

/* Highest thermal-zone reading in milli-Celsius. */
uint32_t qn_thermal_read(void);

uint32_t qn_raise_nofile(void);

#endif /* QANAT_CPUINFO_H */
