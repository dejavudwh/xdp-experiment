/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 19:35:46
 */
// SPDX-License-Identifier: GPL-2.0

#ifndef _COMMON_H
#define _COMMON_H

#include <linux/types.h>

/*
    这里的'context'是我们将在这个XDP程序中的解析函数之间传递的结构
    它负责通过'nh_offset'跟踪我们在数据包中的位置，以及通过'nh_proto'跟踪下一个头协议是什么
    这个结构还持有当前数据包的开始和结束以及总长度的指针
    以减少我们在'xdp_md'结构的data/data_end ints和void指针之间的转换次数
*/
struct context
{
    void *data_start;
    void *data_end;
    __u32 length;

    __u32 nh_proto;
    __u32 nh_offset;
};

/*
    lpm_v4_key 代表一个IPv4地址范围，除了地址长度之外，它与IPv6的对应部分是相同的。
*/
struct lpm_v4_key
{
    __u32 prefixlen;
    __u8 address[4];
};

/*
    lpm_v6_key "代表一个IPv6地址范围，除了地址长度外，与IPv4的对应部分相同
*/
struct lpm_v6_key
{
    __u32 prefixlen;
    __u8 address[16];
};

/*
    这里的'port_type'代表我们希望ban的端口的类型，在这种情况下是源端口或目的端口。
*/
enum port_type
{
    source_port,
    destination_port,
};

/*
    'port_protocol'在这里代表我们希望ban的端口的协议，在这种情况下是tcp或udp端口。
*/
enum port_protocol
{
    tcp_port,
    udp_port,
};

/*
    port_key'是我们将使用的结构，用于在我们的防火墙中匹配udp或tcp端口
    BPF MAP是对键的值进行原始的字节散列，而不考虑数据的实际C类型
    因此，如果一个键的字节结构是相同的，那么即使这些值的类型不同，也会匹配
    然而，你需要注意字节的界限，
    在这种情况下，我们必须使用'__u32'，尽管一个端口永远不会大于'__u16'，但是需要确保额外的填充来满足这里的'12'的字节界限被正确处理
    但简单的解释是，你用作键的结构需要有一个可被4整除的字节大小
    否则编译器将添加填充字节来满足这一要求，它可能（也可能不）在MAP中丢掉匹配。
*/
struct port_key
{
    enum port_type type;
    enum port_protocol proto;
    __u32 port;
};

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#endif /* _COMMON_H */
