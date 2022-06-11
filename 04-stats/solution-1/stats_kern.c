/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 14:33:43
 */
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "common.h"

struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 1,
};

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 length = data_end - data;

    __u32 counter_idx = 0;
    struct counters *cnt = bpf_map_lookup_elem(&counters, &counter_idx);

    /*
        ---------- SOLUTION ----------

        不管查询的是什么BPF MAP类型，都必须检查它的值指针的有效性
        否则验证器会拒绝xdp程序，出现的错误是：invalid mem access 'map_value_or_null'
        这是为了防止空指针异常在XDP程序中发生，也就是防止在内核当中发生
    */
    if (!cnt)
    {
        return XDP_ABORTED;
    }
    /*
        -------- END SOLUTION --------
    */

    __sync_fetch_and_add(&cnt->packets, 1);
    __sync_fetch_and_add(&cnt->bytes, length);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
