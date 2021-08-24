// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (C) 2017 - 2021 Intel Corporation. */

#include <memkind.h>
#include <memkind/internal/heap_manager.h>
#include <memkind/internal/memkind_arena.h>
#include <memkind/internal/memkind_default.h>
#include <memkind/internal/memkind_log.h>

#include <pthread.h>
#include <numa.h>
#include <numaif.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

// Assumption: Only one node in the mask can be set at one time.
static struct bitmask *numa_node_mask = NULL;
static unsigned num_numa_nodes = 1u;
static __thread unsigned node_id = 0u;

static void numa_nodes_init(void)
{
    unsigned nodes_num = (unsigned)numa_num_configured_nodes();
    num_numa_nodes = nodes_num;

    numa_node_mask = numa_allocate_nodemask();
    numa_bitmask_clearall(numa_node_mask);
    numa_bitmask_setbit(numa_node_mask, node_id);

}

static void set_single_numa_node(int nodeID) {
    static bool inited = false;
    if(!inited) {
        numa_nodes_init();
        inited = true;
    }
    numa_bitmask_clearall(numa_node_mask);
    numa_bitmask_setbit(numa_node_mask, (unsigned int) nodeID);
    node_id = (unsigned)nodeID;
}

unsigned get_numa_node() {
    return node_id;
}

static void memkind_numa_init_once(void)
{
    printf("ipex third party memkind init once\n");
    numa_nodes_init();
    memkind_init(MEMKIND_NUMA, true);
}

static int memkind_numa_check_available(struct memkind *kind)
{
    /* init_once method is called in memkind_malloc function
     * when memkind malloc is not called this function will fail.
     * Call pthread_once to be sure that situation mentioned
     * above will never happen */
    pthread_once(&kind->init_once, kind->ops->init_once);
    return numa_node_mask != NULL ? MEMKIND_SUCCESS
                                      : MEMKIND_ERROR_UNAVAILABLE;
}

MEMKIND_EXPORT int memkind_numa_get_mbind_nodemask(
    struct memkind *kind, unsigned long *nodemask, unsigned long maxnode)
{
    struct bitmask nodemask_bm = {maxnode, nodemask};

    if (!numa_node_mask) {
        return MEMKIND_ERROR_UNAVAILABLE;
    }

    copy_bitmask_to_bitmask(numa_node_mask, &nodemask_bm);
    return MEMKIND_SUCCESS;
}

static int memkind_numa_finalize(memkind_t kind)
{
    if (numa_node_mask)
        numa_bitmask_free(numa_node_mask);

    return memkind_arena_finalize(kind);
}

MEMKIND_EXPORT int memkind_numa_mbind(struct memkind *kind, void *ptr,
                                         size_t size)
{
    nodemask_t nodemask;
    int err = 0;
    int mode;

    if (MEMKIND_UNLIKELY(kind->ops->get_mbind_nodemask == NULL ||
                         kind->ops->get_mbind_mode == NULL)) {
        log_err(
            "memkind_ops->mbind_mode or memkind_ops->bind_nodemask is NULL.");
        return MEMKIND_ERROR_BADOPS;
    }
    err = kind->ops->get_mbind_nodemask(kind, nodemask.n, NUMA_NUM_NODES);
    if (MEMKIND_UNLIKELY(err)) {
        return err;
    }
    err = kind->ops->get_mbind_mode(kind, &mode);
    if (MEMKIND_UNLIKELY(err)) {
        return err;
    }
    err = mbind(ptr, size, mode, nodemask.n, NUMA_NUM_NODES, 0);
    if (MEMKIND_UNLIKELY(err)) {
        log_err("syscall mbind() returned: %d", err);
        return MEMKIND_ERROR_MBIND;
    }
    return err;
}

MEMKIND_EXPORT void *memkind_signle_numa_node_mmap(struct memkind *kind, void *addr,
                                          size_t size)
{
    void *result = MAP_FAILED;
    int err = 0;
    int flags;

    if (kind->ops->get_mmap_flags) {
        err = kind->ops->get_mmap_flags(kind, &flags);
    } else {
        err = memkind_default_get_mmap_flags(kind, &flags);
    }
    if (MEMKIND_LIKELY(!err)) {
        result = mmap(addr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (result == MAP_FAILED) {
            log_err("syscall mmap() returned: %p", result);
            return result;
        }
    }
    if (kind->ops->mbind) {
        err = kind->ops->mbind(kind, result, size);
        if (err) {
            munmap(result, size);
            result = MAP_FAILED;
        }
    }
    if (kind->ops->madvise) {
        err = kind->ops->madvise(kind, result, size);
        if (err) {
            munmap(result, size);
            result = MAP_FAILED;
        }
    }
    return result;
}

/*
 *
 * We use thread control block as unique thread identifier
 * For more read: https://www.akkadia.org/drepper/tls.pdf
 * We could consider using rdfsbase when it will arrive to linux kernel
 *
 * This approach works only on glibc (and possibly similar implementations)
 * but that covers our current needs.
 *
 */

// SplitMix64 hash
static uint64_t hash64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
    return x ^ (x >> 31);
}

static uintptr_t get_fs_base()
{
    uintptr_t tmp = (uintptr_t)pthread_self();
    return tmp;
}

// We set the logical mapping of numa node id to the arena id, hence make the arena numa aware. 
MEMKIND_EXPORT int memkind_thread_get_numa_specific_arena(struct memkind *kind,
                                            unsigned int *arena, size_t size)
{
    unsigned current_node_id = get_numa_node();
    unsigned int arena_idx;
    arena_idx = hash64(get_fs_base()) & kind->arena_map_mask;
    unsigned int origin_idx = (kind->arena_zero + arena_idx);
    if (num_numa_nodes > 0) {
        unsigned int numa_map_arena_id = origin_idx - origin_idx % num_numa_nodes + current_node_id;
        *arena = numa_map_arena_id;
    } else {
        /// TODO:
    }
    return 0;
}

static void memkind_numa_set_mbind_node(memkind_t kind, int nodeID) {
    set_single_numa_node(nodeID);

}

static int memkind_numa_get_mbind_node(memkind_t kind) {
    return (int)node_id;
}

MEMKIND_EXPORT struct memkind_ops MEMKIND_NUMA_OPS = {
    .create = memkind_arena_create,
    .destroy = memkind_default_destroy,
    .malloc = memkind_arena_malloc,
    .calloc = memkind_arena_calloc,
    .posix_memalign = memkind_arena_posix_memalign,
    .realloc = memkind_arena_realloc,
    .free = memkind_arena_free,
    .mmap = memkind_signle_numa_node_mmap,
    .check_available = memkind_numa_check_available,
    .mbind = memkind_numa_mbind,
    .get_mmap_flags = memkind_default_get_mmap_flags,
    .get_mbind_mode = memkind_default_get_mbind_mode,
    .get_mbind_nodemask = memkind_numa_get_mbind_nodemask,
    .get_arena = memkind_thread_get_numa_specific_arena,
    .init_once = memkind_numa_init_once,
    .malloc_usable_size = memkind_default_malloc_usable_size,
    .finalize = memkind_numa_finalize,
    .get_stat = memkind_arena_get_kind_stat,
    .defrag_reallocate = memkind_arena_defrag_reallocate,
    .set_mbind_node = memkind_numa_set_mbind_node,
    .get_mbind_node = memkind_numa_get_mbind_node,
};
