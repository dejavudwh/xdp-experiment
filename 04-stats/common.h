/*
 * @Author: dejavudwh
 * @Date: 2022-06-08 00:29:17
 * @LastEditTime: 2022-06-09 14:01:47
 */
// SPDX-License-Identifier: GPL-2.0

#ifndef _STATS_COMMON_H
#define _STATS_COMMON_H

#include <linux/types.h>

/*
    counters：用来表示一个特定的XDP程序所处理的数据包和字节数。
*/
struct counters
{
    __u64 packets;
    __u64 bytes;
};

#endif // _STATS_COMMON_H
