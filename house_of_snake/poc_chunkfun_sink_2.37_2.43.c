#define _GNU_SOURCE
/*
 * 手法：通过 House of Snake 到达分配回调，适用于 glibc 2.37～2.43。
 *
 * glibc 2.37 删除了旧 `_IO_obstack_jumps` printf 后端，但保留 obstack 的
 * 可配置分配函数，并改为下面的新调用链：
 *
 *   从格式化入口 obstack_printf 开始，
 *     -> 构造 obstack 输出缓冲区 __printf_buffer_obstack，
 *     -> 经刷新函数 __printf_buffer_flush_obstack，
 *     -> 再进入扩容函数 _obstack_newchunk，
 *     -> 最终调用 obstack.chunkfun(obstack.extra_arg, new_size)。
 *
 * 这份程序用公开 API 建立一个真实的 obstack，再把当前 chunk 耗尽，严格
 * 确认最终调用到的 callback 和它的两个参数。API 本身不是漏洞；House of
 * Snake 真正的题目侧前置条件，是能覆盖或伪造被 printf_buffer 持有的那个
 * obstack 对象。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        &obs, 0x100, 0, controlled_chunkfun, controlled_freefun,
        &controlled_marker);
    assert(initialized != 0);

    /* 把计数器清零，避免把 obstack 初始化时的那次分配误算成后面的 printf_buffer flush。 */
    callback_count = 0;
    last_extra_arg = NULL;
    last_requested_size = 0;

    size_t room = obstack_room(&obs);
    size_t text_length = room + 0x1000;
    char *text = malloc(text_length + 1);
    assert(text != NULL);
    memset(text, 'S', text_length);
    text[text_length] = '\0';

    int written = obstack_printf(&obs, "%s", text);
    assert(written == (int)text_length);
    assert(callback_count >= 1);
    assert(last_extra_arg == &controlled_marker);
    assert(last_requested_size > 0);

    free(text);
    obstack_free(&obs, NULL);
    assert(free_count >= 1);
    puts("[+] Snake：chunkfun 命中");
    return 0;
}

/*
 * ======================== printf_buffer 布局伪代码 ========================
 *
 * 如果 2.37～2.43 的题目能覆盖 `struct __printf_buffer_obstack`，那就先按
 * 附件源码或调试符号，确认其中 obstack 指针的真实偏移，再据此构造：
 *
 *     fake_printf_buffer.obstack = &fake_obstack；
 *     fake_obstack.next_free = 可控缓冲区末尾；
 *     fake_obstack.chunk_limit = fake_obstack.next_free；
 *     fake_obstack.chunkfun = 受控函数；
 *     fake_obstack.extra_arg = 第一个参数；
 *     fake_obstack.use_extra_arg = 1；
 *
 *     触发一次仍有数据待写的 printf obstack flush；
 *     因当前 chunk 没有空间，进入 `_obstack_newchunk`；
 *     验证调用形态是 chunkfun(extra_arg, new_size)；
 *
 * `__printf_buffer_obstack` 属于内部结构，其中的指针偏移必须按目标的
 * Build ID 重新核实。存在合法的回调设置 API，只能说明这条调用链确实能被
 * 触发，并不代表题目自动就拥有覆盖它所需的写入原语。
 */
