/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 17:34:55
 */
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

/*
    这个定义与上一节中的counters定义相似。

    这里的关键区别是我们在本节中使从用户空间更新这个BPF MAP。
*/
struct bpf_map_def SEC("maps") action = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(long),
    .max_entries = 1,
};

/*
    这个定义与上一节中更新为PERCPU数组的'counters'定义同样相似。
    这里的关键区别是我们现在有 5 个元素，代表 XDP 程序的各种返回代码
*/
struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 5,
};

/*
    这里是被xdp section调用的独立函数，必须声明为内联的    
*/

/*
    函数'update_action_stats'处理接收数据包上下文和所需的动作
    并以处理的数据包和字节数更新上面定义的'action_counters' BPF MAP。
    如果提供的动作没有定义，即它不存在于BPF MAP中，该函数会返回XDP_ABORTED。
*/
static __always_inline __u32 update_action_stats(struct xdp_md *ctx, __u32 action)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 length = data_end - data;

    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);

    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += length;

    return action;
}

/*
    函数'get_action'处理检索xdp程序'stats'的定义返回代码。如果它还没有被用户空间的 控制程序，则返回XDP_ABORTED。
*/
static __always_inline __u32 get_action()
{
    __u32 action_idx = 0;
    __u32 *elem = bpf_map_lookup_elem(&action, &action_idx);
    if (!elem)
    {
        return XDP_ABORTED;
    }

    return *elem;
}

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    /*
        找到用户态程序设置的action
    */
    __u32 action = get_action();

    /*
        更新用户定义的动作的统计信息，并将该动作返回给内核
    */
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
