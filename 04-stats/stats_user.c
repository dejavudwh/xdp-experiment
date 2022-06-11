/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 14:20:29
 */
// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kernel/bpf_util.h"

#include "common.h"

/*
    @brief: 用来打开一个BPF MAP文件
    @param: 文件路径
    @return： 如果出错则返回一个错误号，成功则返回一个文件描述符
*/
int open_bpf_map(const char *file)
{
    int fd;

    /*
        bpf_obj_get是由libbpf提供的api，通过文件路径获取BPF MAP
    */
    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file '%s' err(%d): %s\n",
               file, errno, strerror(errno));
        return -errno;
    }
    return fd;
}

/*
    函数'get_array_stats'主要用来在类型为'BPF_MAP_TYPE_ARRAY'的BPF MAP上进行操作，
    通过bpf_map_lookup_elem从提供的文件描述符中找到counters
    如果出错，它将返回'bpf_map_lookup_elem'的错误号。
    否则，它将返回'0'，并在提供的'struct counters'指针中填充存储在BPF MAP中的数据。
*/
static __u32 get_array_stats(int fd, struct counters *overall)
{
    /*
        这里虽然使用的是数组类型，但是一直只用了第一个元素，所以索引一直为1
    */
    __u32 counter_idx = 0;

    /*
        调用'bpf_map_lookup_elem'，需要传入文件描述符以及key和需要拿到的value的指针，
        如果值不存在，或者文件描述符不是正确的BPF MAP，那么这个运行程序将返回一个非'0'的错误代码并设置errno。
    */
    if ((bpf_map_lookup_elem(fd, &counter_idx, overall)) != 0)
    {
        printf("ERR: Failed to open bpf map object fd '%d' err(%d): %s\n",
               fd, errno, strerror(errno));
        return -errno;
    }
    return 0;
}

int main(int argc, char **argv)
{
    /*
        首先，要在我们用'bpftool'设置的路径上打开我们刚设置好的BPF MAP
    */
    int fd = open_bpf_map("/sys/fs/bpf/counters");
    if (fd < 0)
    {
        return 1;
    }

    /*
        从BPF MAP中拿到统计信息，然后将它们打印到标准输出上
    */
    struct counters overall = {
        .packets = 0,
        .bytes = 0,
    };
    if (get_array_stats(fd, &overall) < 0)
    {
        return 1;
    }

    printf("Overall:\n");
    printf("\tPackets: %llu\n", overall.packets);
    printf("\tBytes:   %llu Bytes\n", overall.bytes);
    return 0;
}
