/*
 * @Author: dejavudwh
 * @Date: 2022-06-09 14:40:00
 * @LastEditTime: 2022-06-09 14:42:57
 */
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "common.h"

struct bpf_map_def SEC("maps") counters = {
    /*
        ---------- SOLUTION ----------

        我们在这里改变的关键部分是使用一个BPF_MAP_TYPE_PERCPU_ARRAY，它为每个CPU分配一个条目
        尽管我们把max_entries限制为 "1"，但实际上最终会把这个值乘以运行该程序的系统的CPU数量
        这是线程安全的BPF MAP类型
    */
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    /*
        -------- END SOLUTION --------
    */
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

    if (!cnt)
    {
        return XDP_ABORTED;
    }

    /*
        ---------- SOLUTION ----------

        因为我们将BPF MAP类型定义更新为PERCPU数组，我们不再需要调用，'__sync_fetch_and_add'
        因为这个XDP程序的每个实例都有自己的条目来处理，不需要担心线程安全问题
    */
    cnt->packets += 1;
    cnt->bytes += length;
    /*
        -------- END SOLUTION --------
    */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
