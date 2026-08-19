/*
 * 本文件是“small bin attack”手法在 direct smallbin / House of Lore 分支
 * （2.26～2.42）下的检索入口。权威实现统一放在 house_of_lore 目录，避免
 * 维护两份几乎相同的长 PoC 导致版本结论出现分歧。被包含的 C 文件里有
 * 完整的中文堆排布说明、漏洞模拟过程，以及严格校验“malloc 返回栈地址”
 * 的断言。
 */
#include "../house_of_lore/poc_2.26_2.42.c"
