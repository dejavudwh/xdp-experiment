/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 19:31:17
 */
// SPDX-License-Identifier: GPL-2.0

#ifndef _UTILS_H
#define _UTILS_H

#include <linux/bpf.h>

#include "kernel/bpf_endian.h"
#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

#include "common.h"

/*
    对xdp_md进行一个封装
*/
static __always_inline struct context to_ctx(struct xdp_md *xdp_ctx)
{
    struct context ctx = {
        .data_start = (void *)(long)xdp_ctx->data,
        .data_end = (void *)(long)xdp_ctx->data_end,
        .nh_proto = 0,
        .nh_offset = 0,
    };
    ctx.length = ctx.data_end - ctx.data_start;

    return ctx;
}

/*
    和上一节的相同
*/
struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

/*
    用来更新counters，在上一节中出现过
*/
static __always_inline __u32 update_action_stats(struct context *ctx, __u32 action)
{
    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += ctx->length;

    return action;
}

#endif /* _UTILS_H */
