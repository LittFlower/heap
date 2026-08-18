/*
 * House of Rust 第五阶段的 __free_hook 终点，适用于 glibc 2.32～2.33。
 *
 * 输入原语：已经知道 libc 地址，并能让一次写覆盖 __free_hook。
 * 成功判据：free(chunk) 进入我们写入的回调函数。
 *
 * glibc 2.34 起 free 主路径不再消费这个 hook，因此本文件不做兼容处理。
 */

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

static int called = 0;

/* hook 回调是这个利用终点本身，不是为了封装代码。 */
static void win(void *pointer, const void *caller)
{
    (void)pointer;
    (void)caller;
    called = 1;
}

int main(void)
{
    void *chunk = malloc(0x30);

    /* 漏洞模拟：把 __free_hook 改成受控函数地址。 */
    __free_hook = win;

    /* glibc 2.32～2.33 的 free 主路径会调用 __free_hook。 */
    free(chunk);

    assert(called == 1);
    printf("[+] free_hook 回调命中\n");
    return 0;
}
