/*
 * “small bin attack”检索入口：direct smallbin / House of Lore，2.26～2.42。
 * 权威实现放在 house_of_lore，避免两份长 PoC 再次产生版本漂移。被包含的
 * C 文件含完整中文堆排布、漏洞模拟和严格的“malloc 返回栈地址”断言。
 */
#include "../house_of_lore/poc_2.26_2.42.c"
