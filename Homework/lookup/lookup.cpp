#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <netinet/in.h>

#include <iostream>

using namespace std;

vector<RoutingTableEntry> routingTable;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  // 不管插入相同的和删除都是要先删掉的
  for (vector<RoutingTableEntry>::iterator routing = routingTable.begin(); routing < routingTable.end(); routing++)
	{
		if (routing->addr == entry.addr && routing->len == entry.len)
		{
			// cerr<<"++++++++++++++++found+++++++++++++++++!"<<endl;
			routingTable.erase(routing);
			break;
		}
	}
	if(insert){
	// cerr<<"=============ADD==========!"<<endl;
    routingTable.push_back(entry);
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，网络字节序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;

  uint32_t _nexthop = 0;
  uint32_t _if_index = 0;

  // 因为是最长前缀匹配原则
  int32_t max_match_len = -1;
	uint32_t rev_addr = ntohl(addr);

	for (vector<RoutingTableEntry>::iterator routing = routingTable.begin(); routing < routingTable.end(); routing++)
	{
		uint32_t rev_routing_addr = ntohl(routing->addr);
		// 前缀符合要求即可
		if (((rev_addr >> (32 - routing->len)) == (rev_routing_addr >> (32 - routing->len))) || routing->len == 0)
			if (int32_t(routing->len) > max_match_len)
			{
				max_match_len = routing->len;
				_nexthop = routing->nexthop;
				_if_index = routing->if_index;
			}
	}
	if(max_match_len>-1){
		*nexthop = _nexthop;
		*if_index = _if_index;
    	return true;
  	}
  return false;
}
