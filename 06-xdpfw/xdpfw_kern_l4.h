#ifndef _XDPFW_KERN_L4_H
#define _XDPFW_KERN_L4_H

#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef PORT_BLACKLIST_MAX_ENTRIES
#define PORT_BLACKLIST_MAX_ENTRIES (65535 * 4) /* src + dest * tcp + udp */
#endif

/*
    这里的port_blacklist代表我们想列入黑名单的tcp和udp源/目的端口的组合。
    这里与mac_blacklist的唯一真正区别是，我们的键是一个任意的自定义类型
    struct port_key定义在common.h中
*/
struct bpf_map_def SEC("maps") port_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = 1,
    .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    parse_udp'处理解析传入的数据包的UDP头
    它将解析出数据包的源端口和目的端口，并检查是否存在于上面定义的'port_blacklist'中
*/
static __always_inline __u32 parse_udp(struct context *ctx)
{
    /*
        我们需要访问UDP头数据，以便找出这个数据包的源端口或输出端口是否被列入黑名单，并最终将数据包返回给内核
        偏移依旧是上次解析时确定的
    */
    struct udphdr *udp = ctx->data_start + ctx->nh_offset;

    /*
        这里见过太多次啦！
    */
    if (udp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        我们需要创建两个'port_key'值，以便我们可以在上面定义的'port_blacklist'中搜索源端口和目的端口
        一个是源端口，另一个是目的端口
    */
    struct port_key src_key = {
        .type = source_port,
        .proto = udp_port,
    };
    struct port_key dst_key = {
        .type = destination_port,
        .proto = udp_port,
    };

    /*
        转换字节序
    */
    src_key.port = bpf_ntohs(udp->source);
    dst_key.port = bpf_ntohs(udp->dest);

    /*
        依旧是bpf_map_lookup_elem
    */
    if (bpf_map_lookup_elem(&port_blacklist, &src_key) ||
        bpf_map_lookup_elem(&port_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

/*
    功能和parse_udp类似，代码几乎一样，这里不做多解释
*/
static __always_inline __u32 parse_tcp(struct context *ctx)
{
    struct tcphdr *tcp = ctx->data_start + ctx->nh_offset;

    if (tcp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    struct port_key src_key = {
        .type = source_port,
        .proto = tcp_port,
    };
    struct port_key dst_key = {
        .type = destination_port,
        .proto = tcp_port,
    };

    src_key.port = bpf_ntohs(tcp->source);
    dst_key.port = bpf_ntohs(tcp->dest);

    if (bpf_map_lookup_elem(&port_blacklist, &src_key) ||
        bpf_map_lookup_elem(&port_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

#endif // _XDPFW_KERN_L4_H