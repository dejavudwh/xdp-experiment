#ifndef _XDPFW_KERN_L3_H
#define _XDPFW_KERN_L3_H

#include <linux/ip.h>
#include <linux/ipv6.h>

/*
    和xdpfw_kern_l2.h中的定义类似，只是前者定义对mac地址的黑名单数量
    这里限制ip地址的
*/
#ifndef V4_BLACKLIST_MAX_ENTRIES
#define V4_BLACKLIST_MAX_ENTRIES 10000
#endif

/*
    同上
*/
#ifndef V6_BLACKLIST_MAX_ENTRIES
#define V6_BLACKLIST_MAX_ENTRIES 10000
#endif

/*
    v4_blacklist在这里代表了我们想要ban的各种IPv4地址，其类型为BPF_MAP_TYPE_LPM_TRIE
    是专门用于键上最长前缀匹配的BPF映射类型，是一个专门的BPF MAP类型，用于键上最长的前缀匹配
    这个BPF MAP类型的键的匹配和之前提过的类型事不同的，因为它能够对传入的值进行"范围"匹配
    比如192.168.0.1会和192.168.0.0/24相匹配

    这里的键使用的是lpm_v4_key，它定义在common.h中
*/
struct bpf_map_def SEC("maps") v4_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_v4_key),
    .value_size = 1,
    .max_entries = V4_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    原理和v4_blacklist相同
*/
struct bpf_map_def SEC("maps") v6_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_v6_key),
    .value_size = 1,
    .max_entries = V6_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    parse_ipv4处理解析传入的数据包的IPv4头
    它将解析出数据包的源地址，并检查它是否存在于上面定义的'v4_blacklist'BPF MAP中。
*/
static __always_inline __u32 parse_ipv4(struct context *ctx)
{
    /*
        我们需要访问IPv4头数据，以便找出这个数据包的源IP地址是否被列入黑名单
        如果不是，那么头中的下一个协议是什么，以便继续解析
        我们需要添加一个头的偏移，这是在先前调用的parse_eth函数中确定的
    */
    struct iphdr *ip = ctx->data_start + ctx->nh_offset;

    /*
        和xdpfw_kern_l2.h相同 要确保不会越界
    */
    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    struct lpm_v4_key key;

    /*
        为了与上面定义的'v4_blacklist' BPF MAP中存储的IPv4范围正确匹配
        我们需要将数据包中的源地址复制到我们key的'地址'字段
        同时，因为我们在这里使用一个完整的IPv4地址作为密钥
        我们需要将'prefixlen'设置为32，这是一个IPv4地址的最大尺寸
    */
    __builtin_memcpy(key.address, &ip->saddr, sizeof(key.address));
    key.prefixlen = 32;

    /*
        使用LPM_TRIE的方法与其他BPF MAP相同
        依旧是bpf_map_lookup_elem来处理对TRIE中存在的最长前缀的匹配
        如果在我们的黑名单中确实存在匹配，则立即退出并丢弃数据包。
    */
    if (bpf_map_lookup_elem(&v4_blacklist, &key))
    {
        return XDP_DROP;
    }

    /*
        就像以太网帧的情况一样，如果这个数据包的源IP地址在黑名单中不匹配
        我们需要更新数据包中下一个头的偏移量，并更新数据包中下一个头的协议
        ihl = Internet Header Length 头部长度 要乘以单位4字节
    */
    ctx->nh_offset += ip->ihl * 4;
    ctx->nh_proto = ip->protocol;

    /*
        继续
    */
    return XDP_PASS;
}

/*
    功能和parse_ipv4相同，代码也几乎相同
*/
static __always_inline __u32 parse_ipv6(struct context *ctx)
{
    /*
       同parse_ipv4
    */
    struct ipv6hdr *ip = ctx->data_start + ctx->nh_offset;

    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    struct lpm_v6_key key;

    __builtin_memcpy(key.address, &ip->saddr, sizeof(key.address));
    key.prefixlen = 128;

    if (bpf_map_lookup_elem(&v6_blacklist, &key))
    {
        return XDP_DROP;
    }

    /*
        这里和parse_ipv4不同的是
        ipv6包中没有Header Length，因为对于固定长度的报头，它是没有作用的
        直接计算即可
    */
    ctx->nh_offset += sizeof(*ip);
    ctx->nh_proto = ip->nexthdr;

    return XDP_PASS;
}

#endif // _XDPFW_KERN_L3_H