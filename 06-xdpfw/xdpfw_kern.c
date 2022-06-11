/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 19:49:12
 */
// SPDX-License-Identifier: GPL-2.0

#include <linux/if_ether.h>
#include <linux/in.h>

#include "xdpfw_kern_utils.h"

#include "xdpfw_kern_l2.h"
#include "xdpfw_kern_l3.h"
#include "xdpfw_kern_l4.h"

SEC("xdpfw")
int xdpfw_fn(struct xdp_md *xdp_ctx)
{
    /*
        对数据包的默认action
    */
    __u32 action = XDP_PASS;

    /*
        将提供的'xdp_md'结构转换为我们自定义的'context'结构，以便于后续处理。
    */
    struct context ctx = to_ctx(xdp_ctx);

    /*
        解析我们的以太网头，并从这个数据包中解开任何潜在的vlan头。同时还要确保这个数据包的源MAC地址不在我们的黑名单中
    */
    action = parse_eth(&ctx);
    if (action != XDP_PASS)
    {
        goto ret;
    }

    /*
        检查这个数据包中包含的第三层协议，在这种情况下，我们只关心IPv4和IPv6，所以如果它不是其中之一
        就返回最后设置的action。
    */
    switch (ctx.nh_proto)
    {
    case ETH_P_IP:
        /*
            我们有一个IPv4数据包，所以让我们解析出它的源地址，并根据我们的黑名单检查它，看看我们是否应该放弃它
        */
        action = parse_ipv4(&ctx);
        break;
    case ETH_P_IPV6:
        /*
            我们有一个IPv6数据包，所以让我们解析出它的源地址，并对照我们的黑名单
            看看我们是否应该丢弃它。如果不是，就抓取下一个头，继续处理下一层协议。
        */
        action = parse_ipv6(&ctx);
        break;
    default:
        /*
            不是ipv4或者ipv6的数据包
        */
        goto ret;
    }

    if (action != XDP_PASS)
    {
        /*
            之前的一个解析函数返回了XDP_PASS以外的动作，所以让我们立即返回这个动作。
        */
        goto ret;
    }

    /*
        检查TCP和UDP
    */
    switch (ctx.nh_proto)
    {
    case IPPROTO_UDP:
        /*
            检查udp
        */
        action = parse_udp(&ctx);
        break;
    case IPPROTO_TCP:
        /*
            检查tcp
        */
        action = parse_tcp(&ctx);
        break;
    }

ret:
    /*
        更新counter
    */
    return update_action_stats(&ctx, action);
}

char _license[] SEC("license") = "GPL";
