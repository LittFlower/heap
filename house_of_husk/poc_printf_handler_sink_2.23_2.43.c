#define _GNU_SOURCE
/*
 * House of Husk 的 printf handler 最终触发点：glibc 2.23～2.43，x86-64。
 *
 * House of Husk 的完整利用通常先用 arbitrary write/largebin attack 改写
 * `__printf_function_table` 与 `__printf_arginfo_table`，再让 printf 解析某个
 * 格式符，间接调用攻击者布置的 handler。本 PoC 使用 glibc 官方
 * `register_printf_specifier` API 合法地填入同一组内部表，从而隔离验证：
 *
 *   调用链为 printf("%Q") → 参数信息回调 arginfo → 自定义格式化回调 printf callback。
 *
 * 它不声称“注册 API 本身是漏洞”，也不替代题目中的任意写；价值在于给
 * 2.42/2.43 一个不依赖 hidden-symbol 固定偏移的可执行最终触发点证明。旧版
 * largebin 投递在 2.42 已失效，但 handler 消费路径并没有随之删除。
 */

#include <assert.h>
#include <printf.h>
#include <stdio.h>
#include <string.h>

static int arginfo_count;
static int handler_count;

/* reg-printf.c 将 __printf_arginfo_table 建立为这个弱别名，但发行版
   的 version script 可能不导出它。用 weak 声明只作调试提示：
   符号不可见时仍然依靠下面的真实 callback 判据，不会失败。 */
extern void *__libc_reg_printf_freemem_ptr __attribute__((weak));

static int husk_arginfo(const struct printf_info *info, size_t n,
                        int *argtypes, int *sizes)
{
    (void)info;
    (void)n;
    (void)argtypes;
    (void)sizes;

    /* `%Q` 不消费可变参数，因此返回 0。完整攻击中，arginfo 表的槽位本身
       常被用作第一次可控间接调用。 */
    arginfo_count++;
    return 0;
}

static int husk_handler(FILE *stream, const struct printf_info *info,
                        const void *const *args)
{
    static const char marker[] = "HUSK_CALLBACK";
    (void)info;
    (void)args;

    handler_count++;
    if (fwrite(marker, 1, sizeof(marker) - 1, stream) != sizeof(marker) - 1)
        return -1;
    return (int)(sizeof(marker) - 1);
}

int main(void)
{
    setbuf(stdout, NULL);

    /* Q 是 glibc 默认 printf 不使用的自定义 specifier。注册函数会初始化并
       更新 House of Husk 所攻击的内部 handler 表。 */
    int rc = register_printf_specifier('Q', husk_handler, husk_arginfo);
    assert(rc == 0);

	if (&__libc_reg_printf_freemem_ptr != NULL)
		printf("[i] arginfo 槽=%p，表=%p\n",
		       &__libc_reg_printf_freemem_ptr,
		       __libc_reg_printf_freemem_ptr);

    int written = printf("before=<%Q>, after\n");
    assert(written > 0);
    assert(arginfo_count >= 1);
    assert(handler_count == 1);

    printf("[+] Husk：参数回调=%d，处理回调=%d\n",
           arginfo_count, handler_count);
    return 0;
}
