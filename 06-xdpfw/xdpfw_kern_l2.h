#ifndef _XDPFW_KERN_L2_H
#define _XDPFW_KERN_L2_H

#include <linux/if_ether.h>

/*
    如果数据包中存在vlan头的话，这将用于解包
    代码来自$(LINUX)/include/linux/if_vlan.h#L38
*/
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/*
    这个定义代表了允许列入黑名单的MAC地址的总数 
*/
#ifndef MAC_BLACKLIST_MAX_ENTRIES
#define MAC_BLACKLIST_MAX_ENTRIES 4096
#endif

/*
    这里的'mac_blacklist'代表我们希望直接丢弃的各种MAC地址，也就是如果数据包中的mac地址被包含其中，则进行丢弃其类型为'BPF_MAP_TYPE_HASH'
    首先注意到我们有一个新的字段'map_flags'
    和BPF_MAP_TYPE_ARRAY和BPF_MAP_TYPE_PERCPU_ARRAY时不同，这个字段控制内核如何初始化BPF MAP本身。
    在本例中，我们传入标志'BPF_F_NO_PREALLOC'，这意味着内核将不会对BPF MAP进行每个entires的预填充
    如果我们不指定这个标志，当我们加载程序时，整个BPF MAP就会被填满数据。
    在这里没有使用线程安全的MAP，因为我们并没有从内核中实际更新BPF MAP中的条目，我们只是判断BPF MAP中是否存在一个给定的MAC地址
    所以在这种情况下不需要担心锁的问题
    最后，我们在这里指定value_size为1,我们只是使用它来测试对应key是否存在
*/
struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    parse_eth'处理解析传入的数据包的以太网和vlan头（如果有的话）
    它将解析出这个数据包的源MAC地址 并检查它是否存在于上面定义的'mac_blacklist' BPF MAP中
    这里context是对xdp_md的一个封装，定义在xdpfw_kern_utils.h中
*/
static __always_inline __u32 parse_eth(struct context *ctx)
{
    /*
        我们需要访问以太网头数据，以便找出这个数据包的源MAC地址是否被列入黑名单。 
        强转成ethhdr
        还要加上偏移以访问下一个以太网帧
    */
    struct ethhdr *eth = ctx->data_start + ctx->nh_offset;

    /*
        如果这个以太网帧不是完整的则直接丢弃
    */
    if (eth + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        一旦我们知道我们至少有一个完整的以太网头
        让我们看看在我们上面定义的mac_blacklist map中是否有一个匹配的源MAC地址
        如果有，立即返回XDP_DROP并丢弃这个数据包
    */
    if (bpf_map_lookup_elem(&mac_blacklist, &eth->h_source))
    {
        return XDP_DROP;
    }

    /*
        如果当前数据包的源MAC地址不在黑名单中
        则将偏移量更新为下一个头，并将下一个头的协议更新为以太网头中的协议
    */
    ctx->nh_offset += sizeof(*eth);
    ctx->nh_proto = bpf_ntohs(eth->h_proto);

    /*
        在BPF程序中，一般循环是被禁止的，所以我们需要使用unroll来展开循环
        这个循环将试图展开vlan头，因为一个数据包中可能包含多层vlan头。
    */
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        /*
            检查这个数据包的下一个是否是vlan头，即8021Q或8021AD协议头。
        */
        if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD)
        {
            /*
                执行与上述原始以太网头相同的过程，以确保进入下一个头
            */
            struct vlan_hdr *vlan = ctx->data_start + ctx->nh_offset;

            if (vlan + 1 > ctx->data_end)
            {
                return XDP_DROP;
            }

            ctx->nh_offset += sizeof(*vlan);
            ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

    /*
        继续解析，所以返回XDP_PASS。
    */
    return XDP_PASS;
}

#endif // _XDPFW_KERN_L2_H