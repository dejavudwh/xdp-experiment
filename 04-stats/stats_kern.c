/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-10 16:07:59
 */
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "common.h"

/*
    BPF内核态程序
*/

/*
    该定义表示一个名为'counters'的BPF映射对象，其类型为bpf_map_type_array
    bpf_map_type_array是数组类型，初始化后会预分配内存，key值为4byte的索引值，并且这个类型不是线程安全的
    关于BPF MAP的类型具体可以参考实验指导书

    这里使用bpf_map_def SEC("maps")定义了BPF MAP，描述了如何与MAP进行交互。
        - type: BPF MAP的类型。
        - key_size 设置了用于查询、插入、更新或删除元素的键的大小。
        - value_size 设置了存储在一个给定键上的值的大小。
        - max_entries 决定了在这个MAP中可以存储的KV的数量。
*/
struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),  // counters在common.h中定义
    .max_entries = 1,
};

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    /*
        xdp_md可以认为是现在内核传递给我们的数据包，我们现在只关系其中的两个字段：data和data_end，

        struct xdp_md {
            __u32 data;
            __u32 data_end;
            <-- snip -->
        };

        其中data代表数据包的开始，而data_end代表数据包的结束。
        为了正确地看到有关数据包的大小，我们需要将data和data_end字段进行运算
    */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /*
        计算数据包的长度，取结尾指针位置和开始指针位置之间的差值。得到数据包的长度，单位是字节。
    */
    __u64 length = data_end - data;

    /*
        依旧通过内核提供的bpf_map_lookup_elem检索一个指向希望用新数据更新的BPF MAP的指针。       
        注意'bpf_map_lookup_elem'函数是如何获取一个指向被查询的索引值的指针，而不是索引值本身。
    */
    __u32 counter_idx = 0;
    struct counters *cnt = bpf_map_lookup_elem(&counters, &counter_idx);

    /*
        因为使用了BPF_MAP_TYPE_ARRAY，它不是线程安全的
        所以需要确保操作是原子的，所以使用__sync_fetch_and_add来进行更新数据
    */
    __sync_fetch_and_add(&cnt->packets, 1);
    __sync_fetch_and_add(&cnt->bytes, length);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
