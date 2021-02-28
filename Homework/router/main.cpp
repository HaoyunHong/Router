#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <vector>
#include <iostream>
#include <algorithm>

using namespace std;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern vector<RoutingTableEntry> routingTable;

uint8_t packet[2048];
uint8_t output[2048];

// for online experiment, don't change
#ifdef ROUTER_R1
// 0: 192.168.1.1
// 1: 192.168.3.1
// 2: 192.168.6.1
// 3: 192.168.7.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0101a8c0, 0x0103a8c0, 0x0106a8c0,
										   0x0107a8c0 };
#elif defined(ROUTER_R2)
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 192.168.8.1
// 3: 192.168.9.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0203a8c0, 0x0104a8c0, 0x0108a8c0,
										   0x0109a8c0 };
#elif defined(ROUTER_R3)
// 0: 192.168.4.2
// 1: 192.168.5.2
// 2: 192.168.10.1
// 3: 192.168.11.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0204a8c0, 0x0205a8c0, 0x010aa8c0,
										   0x010ba8c0 };
#else

// 自己调试用，你可以按需进行修改，注意字节序
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0100000a, 0x0101000a, 0x0102000a,
									 0x0103000a };
#endif

in_addr_t multicast_dst_ip = 0x090000e0;

void setIPChecksum(ip *ip_header) {
	// 校验和变 0
	ip_header->ip_sum = 0;
	uint32_t sum = 0;
	// 然后得到包头的字节数
	size_t head_length = ip_header->ip_hl * 32 / 8;
	uint8_t* buf = (uint8_t*)ip_header;
	for (size_t i = 0; i < head_length; i += 2) {
		// 因为是大端序，计算反码和
		sum += buf[i + 1] + (buf[i] << 8);
		// 如果有溢出持续加到后面，不过溢出应该不会超过连续两次
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	ip_header->ip_sum = htons(~sum);
}

void setICMPChecksum(icmphdr *icmpHeader, size_t head_length) {
	icmpHeader->checksum = 0;
	uint32_t sum = 0;
	uint8_t* buf = (uint8_t*)icmpHeader;
	// ICMP校验和是针对整个ICMP包的
	for (size_t i = 0; i < head_length; i += 2) {
		// 因为是大端序，计算反码和
		sum += buf[i + 1] + (buf[i] << 8);
		// 如果有溢出持续加到后面，不过溢出应该不会超过连续两次
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	icmpHeader->checksum = htons(~sum);
}

const uint32_t len2Mask[33] = { 0, 0x00000080, 0x000000c0, 0x000000e0, 0x000000f0, 0x000000f8, 0x000000fc, 0x000000fe, 0x000000ff,
								0x000080ff, 0x0000c0ff, 0x0000e0ff, 0x0000f0ff, 0x0000f8ff, 0x0000fcff, 0x0000feff, 0x0000ffff,
								0x0080ffff, 0x00c0ffff, 0x00e0ffff, 0x00f0ffff, 0x00f8ffff, 0x00fcffff, 0x00feffff, 0x00ffffff,
								0x80ffffff, 0xc0ffffff, 0xe0ffffff, 0xf0ffffff, 0xf8ffffff, 0xfcffffff, 0xfeffffff, 0xffffffff };

uint32_t mask2Len(uint32_t mask) {
	uint32_t len = 0;
	switch (mask)
	{
	case 0:
		len = 0;
		break;
	case 0x00000080:
		len = 1;
		break;
	case 0x000000c0:
        len = 2;
        break;
    case 0x000000e0:
        len = 3;
        break;
    case 0x000000f0:
        len = 4;
        break;
    case 0x000000f8:
        len = 5;
        break;
    case 0x000000fc:
        len = 6;
        break;
    case 0x000000fe:
        len = 7;
        break;
    case 0x000000ff:
        len = 8;
        break;
    case 0x000080ff:
        len = 9;
        break;
    case 0x0000c0ff:
        len = 10;
        break;
    case 0x0000e0ff:
        len = 11;
        break;
    case 0x0000f0ff:
        len = 12;
        break;
    case 0x0000f8ff:
        len = 13;
        break;
    case 0x0000fcff:
        len = 14;
        break;
    case 0x0000feff:
        len = 15;
        break;
    case 0x0000ffff:
        len = 16;
        break;
    case 0x0080ffff:
        len = 17;
        break;
    case 0x00c0ffff:
        len = 18;
        break;
    case 0x00e0ffff:
        len = 19;
        break;
    case 0x00f0ffff:
        len = 20;
        break;
    case 0x00f8ffff:
        len = 21;
        break;
    case 0x00fcffff:
        len = 22;
        break;
    case 0x00feffff:
        len = 23;
        break;
    case 0x00ffffff:
        len = 24;
        break;
    case 0x80ffffff:
        len = 25;
        break;
    case 0xc0ffffff:
        len = 26;
        break;
    case 0xe0ffffff:
        len = 27;
        break;
    case 0xf0ffffff:
        len = 28;
        break;
    case 0xf8ffffff:
        len = 29;
        break;
    case 0xfcffffff:
        len = 30;
        break;
    case 0xfeffffff:
        len = 31;
        break;
    case 0xffffffff:
        len = 32;
        break;

    default:
        break;
	}
	return len;
}

void sendRIPPacket(int if_index, uint8_t *output, macaddr_t dst_mac, in_addr_t dst_ip) {
	RipPacket resp;
	// 25个一组把entry写进resp里
	// TODO: fill resp
	// implement split horizon with poisoned reverse
	// ref. RFC 2453 Section 3.4.3
	resp.command = 2;
	uint32_t count = 0;

	// fill IP headers
	struct ip *ip_header = (struct ip *)output;
	ip_header->ip_hl = 5;
	ip_header->ip_v = 4;
	// TODO: set tos = 0, id = 0, off = 0, ttl = 1, p = 17(udp), dst and src
	ip_header->ip_tos = 0;
	ip_header->ip_id = 0;
	ip_header->ip_off = 0;
	// 这两个就1个字节，不用字节序转换
	ip_header->ip_ttl = 1;
	ip_header->ip_p = 17;
	ip_header->ip_dst.s_addr = dst_ip;

	// fill UDP headers
	struct udphdr *udpHeader = (struct udphdr *)&output[20];
	// src port = 520
	udpHeader->uh_sport = htons(520);
	// dst port = 520
	udpHeader->uh_dport = htons(520);


	for (uint32_t i = 0; i < N_IFACE_ON_BOARD; ++i) {
		if (if_index == i || if_index == -1) {
			ip_header->ip_src.s_addr = addrs[i];
			uint32_t count = 0;
			for (vector<RoutingTableEntry>::iterator routing = routingTable.begin(); routing < routingTable.end(); routing++) {
				// 带毒性反转的水平分割
				resp.entries[count].metric = routing->metric;
				// 这里要小心字节序啊
				if (routing->if_index == i) {
					resp.entries[count].metric = htonl(16);
				}
				resp.entries[count].addr = routing->addr;
				resp.entries[count].mask = len2Mask[routing->len];
				resp.entries[count].nexthop = routing->nexthop;

				count++;

				if (count == 25) {
					resp.numEntries = count;
					// assemble RIP
					uint32_t rip_len = assemble(&resp, &output[20 + 8]);
					// TODO: udp length
					udpHeader->len = htons(8 + rip_len);
					ip_header->ip_len = htons(rip_len + 20 + 8);
					setIPChecksum(ip_header);
					udpHeader->uh_sum = 0;
					// send it back
					HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
					count = 0;
				}
			}
			if (count > 0) {
				resp.numEntries = count;

				// assemble RIP
				uint32_t rip_len = assemble(&resp, &output[20 + 8]);
				// TODO: udp length
				udpHeader->len = htons(8 + rip_len);
				ip_header->ip_len = htons(rip_len + 20 + 8);
				// TODO: checksum calculation for ip and udp
				// if you don't want to calculate udp checksum, set it to zero
				setIPChecksum(ip_header);
				udpHeader->uh_sum = 0;
				// send it back
				HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
			}
		}
	}
}

void printRoutingTable() {
	cerr<<"===================================="<<endl;
	cerr << "routingTable.size(): " << routingTable.size() << endl;
	for (vector<RoutingTableEntry>::iterator routing = routingTable.begin(); routing < routingTable.end(); routing++) {
		printf("addr %08x    if_index %08x    len %08x    metric %08x    nexthop %08x\n", routing->addr, routing->if_index, routing->len, routing->metric, routing->nexthop);
	}
	cerr<<"===================================="<<endl;
}

void updateRoutingTable(RipPacket rip, int if_index, in_addr_t src_addr) {
	// cerr<<"===================================="<<endl;
	// cerr<<"before update"<<endl;
	// printRoutingTable();
	for (int i = 0; i < rip.numEntries; i++) {
		uint32_t mask = rip.entries[i].mask;
		uint32_t len = mask2Len(mask);
		uint32_t addr = rip.entries[i].addr & mask;
		uint32_t nexthop = rip.entries[i].nexthop;
		// 要做加法的，要特别注意字节序
		uint32_t metric = htonl(min(uint32_t(16), uint32_t(ntohl(rip.entries[i].metric) + 1)));
		bool found = false;
		for (vector<RoutingTableEntry>::iterator rte = routingTable.begin(); rte < routingTable.end(); rte++)
		{
			// 事实上就是下面的情况才需要更新的，这里就不要轻易扔掉了
			if ((addr == rte->addr) && (len == rte->len)) {
				if (ntohl(rte->metric) > ntohl(metric)) {
					rte->metric = metric;
					// 记录从哪里学到的路由表项
					rte->if_index = if_index;
					rte->nexthop = src_addr;
				}
				found = true;
				break;
			}
		}
		if (!found && ntohl(metric) < 16) {
			routingTable.push_back(RoutingTableEntry{ addr, len, if_index, src_addr, metric });
		}
	}
	// cerr<<"after update"<<endl;
	// printRoutingTable();
	// cerr<<"===================================="<<endl;
}



int main(int argc, char *argv[]) {
	// 0a.
	int res = HAL_Init(1, addrs);
	if (res < 0) {
		return res;
	}

	// 0b. Add direct routes
	// For example:
	// 10.0.0.0/24 if 0
	// 10.0.1.0/24 if 1
	// 10.0.2.0/24 if 2
	// 10.0.3.0/24 if 3
	for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
		RoutingTableEntry entry = {
			.addr = addrs[i] & 0x00FFFFFF, // network byte order
			.len = 24,                     // host byte order
			.if_index = i,                 // host byte order
			.nexthop = 0,                   // network byte order, means direct
			.metric = htonl(1)              // also network byte order
		};
		update(true, entry);
	}

	uint64_t last_time = 0;
	while (1) {
		uint64_t time = HAL_GetTicks();
		// the RFC says 30s interval,
		// but for faster convergence, use 5s here
		if (time > last_time + 5 * 1000) {
			// ref. RFC 2453 Section 3.8
			printf("5s Timer\n");

            //printRoutingTable();

			// HINT: print complete routing table to stdout/stderr for debugging
			// TODO: send complete routing table to every interface
			macaddr_t multicast_mac = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x09 };
			sendRIPPacket(-1, output, multicast_mac, multicast_dst_ip);
			last_time = time;
		}

		int mask = (1 << N_IFACE_ON_BOARD) - 1;
		macaddr_t src_mac;
		macaddr_t dst_mac;
		int if_index;
		res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
			1000, &if_index);
		if (res == HAL_ERR_EOF) {
			break;
		}
		else if (res < 0) {
			return res;
		}
		else if (res == 0) {
			// Timeout
			continue;
		}
		else if (res > sizeof(packet)) {
			// packet is truncated, ignore it
			continue;
		}

		// 1. validate
		if (!validateIPChecksum(packet, res)) {
			printf("Invalid IP Checksum\n");
			// drop if ip checksum invalid
			continue;
		}
		in_addr_t src_addr, dst_addr;
		// TODO: extract src_addr and dst_addr from packet (big endian)
		// 保持大端序
		struct ip *ip_header = (struct ip *)packet;
		src_addr = ip_header->ip_src.s_addr;
		dst_addr = ip_header->ip_dst.s_addr;

		// 2. check whether dst is me
		bool dst_is_me = false;
		for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
			if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
				dst_is_me = true;
				break;
			}
		}
		// TODO: handle rip multicast address(224.0.0.9)
		if (memcmp(&dst_addr, &multicast_dst_ip, sizeof(in_addr_t)) == 0) {
			dst_is_me = true;
		}

		if (dst_is_me) {
			// 3a.1
			RipPacket rip;
			// check and validate
			if (disassemble(packet, res, &rip)) {
				// rip.command == 1: 本地收到src的request，就把自己的路由表发给它
				// rip.command == 2: 本地收到src的response，就更新自己的路由表
				if (rip.command == 1) {
					// 3a.3 request, ref. RFC 2453 Section 3.9.1
					// only need to respond to whole table requests in the lab
					// 要发回去，所以反一下
					sendRIPPacket(if_index, output, src_mac, src_addr);
				}
				else {
					// 3a.2 response, ref. RFC 2453 Section 3.9.2
					// TODO: update routing table
					// new metric = ?
					// update metric, if_index, nexthop
					// HINT: handle nexthop = 0 case 说明是src的地址，就把nexthop设成src_addr
					// HINT: what is missing from RoutingTableEntry?
					// you might want to use `prefix_query` and `update`, but beware of
					// the difference between exact match and longest prefix match.
					// optional: triggered updates ref. RFC 2453 Section 3.10.1
					updateRoutingTable(rip, if_index, src_addr);
				}
			}
			else {
				// not a rip packet
				// handle icmp echo request packet
				// TODO: how to determine?
				// 要在这里先判断是不是 icmp 协议，是不是 echo request packet
				struct ip *old_ip_header = (struct ip *)packet;
				if (old_ip_header->ip_p == 1) {
					// construct icmp echo reply
					// reply is mostly the same as request,
					// you need to:
					// 1. swap src ip addr and dst ip addr
					// 2. change icmp `type` in header
					// 3. set ttl to 64
					// 4. re-calculate icmp checksum and ip checksum
					// 5. send icmp packet
					struct icmphdr *old_icmpHeader = (struct icmphdr *)&packet[20];
					if (old_icmpHeader->type == ICMP_ECHO) {
						// 包的总长度
						uint32_t allLen = ntohs(old_ip_header->ip_len);

						memcpy(output, packet, allLen * sizeof(uint8_t));
						struct ip *ip_header = (struct ip *)output;
						struct icmphdr *icmpHeader = (struct icmphdr *)&output[20];
						ip_header->ip_dst.s_addr = src_addr;
						ip_header->ip_src.s_addr = addrs[if_index];
						ip_header->ip_ttl = 64;

						// 获得原本的长度
						uint32_t icmpLen = allLen - 20;
						icmpHeader->type = ICMP_ECHOREPLY;// 发来的时候邮戳是 ICMP_ECHO，发回去的时候是 ICMP_ECHOREPLY
						// 和发过来的echo包的数据段一致
						setICMPChecksum(icmpHeader, icmpLen);
						setIPChecksum(ip_header);
						HAL_SendIPPacket(if_index, output, allLen, src_mac);
					}
				}
			}
		}
		else {
			// 3b.1 dst is not me
			// check ttl
			uint8_t ttl = packet[8];
			if (ttl <= 1) {
				// send icmp time to live exceeded to src addr
				// fill IP header
				struct ip *ip_header = (struct ip *)output;
				ip_header->ip_hl = 5;
				ip_header->ip_v = 4;
				// TODO: set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
				ip_header->ip_tos = 0;
				ip_header->ip_id = 0;
				ip_header->ip_off = 0;
				ip_header->ip_ttl = 64;
				ip_header->ip_p = 1;
				ip_header->ip_dst.s_addr = src_addr;
				// 这个包都要我回回去
				ip_header->ip_src.s_addr = addrs[if_index];
				// fill icmp header
				struct icmphdr *icmpHeader = (struct icmphdr *)&output[20];
				// icmp type = Time Exceeded
				icmpHeader->type = ICMP_TIME_EXCEEDED;
				// TODO: icmp code = 0
				// TODO: fill unused fields with zero
				// TODO: append "ip header and first 8 bytes of the original payload"
				// TODO: calculate icmp checksum and ip checksum
				// TODO: send icmp packet
				icmpHeader->code = 0;
				icmpHeader->un.echo.id = 0;
				icmpHeader->un.echo.sequence = 0;
				memcpy(output + 28, packet, 28);

				ip_header->ip_len = htons(56);
				uint32_t icmpLen = 8 + 20 + 8;
				setIPChecksum(ip_header);
				setICMPChecksum(icmpHeader, icmpLen);
				HAL_SendIPPacket(if_index, output, 20 + icmpLen, src_mac);
			}
			else {
				// forward
				// beware of endianness
				uint32_t nexthop, dest_if;
				if (prefix_query(dst_addr, &nexthop, &dest_if)) {
					// found
					macaddr_t dest_mac;
					// direct routing
					// 这里是要从我这里发出去
					if (nexthop == 0) {
						nexthop = dst_addr;
					}
					if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
						// found
						memcpy(output, packet, res);
						// update ttl and checksum
						forward(output, res);
						HAL_SendIPPacket(dest_if, output, res, dest_mac);
					}
					else {
						// not found
						// you can drop it
						printf("ARP not found for nexthop %x\n", nexthop);
					}
				}
				else {
					// not found
					// send ICMP Destination Network Unreachable
					printf("IP not found in routing table for src %x dst %x\n", src_addr, dst_addr);
					// send icmp destination net unreachable to src addr
					// fill IP header
					struct ip *ip_header = (struct ip *)output;
					ip_header->ip_hl = 5;
					ip_header->ip_v = 4;
					// TODO: set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
					ip_header->ip_tos = 0;
					ip_header->ip_id = 0;
					ip_header->ip_off = 0;
					ip_header->ip_ttl = 64;
					ip_header->ip_p = 1;
					ip_header->ip_dst.s_addr = src_addr;
					// 这个包都要我回回去
					ip_header->ip_src.s_addr = addrs[if_index];

					// fill icmp header
					struct icmphdr *icmp_header = (struct icmphdr *)&output[20];
					// icmp type = Destination Unreachable
					icmp_header->type = ICMP_DEST_UNREACH;
					// TODO: icmp code = Destination Network Unreachable
					// TODO: fill unused fields with zero
					// TODO: append "ip header and first 8 bytes of the original payload"
					// TODO: calculate icmp checksum and ip checksum
					// TODO: send icmp packet
					icmp_header->code = 0;
					icmp_header->un.echo.id = 0;
					icmp_header->un.echo.sequence = 0;
					memcpy(output + 28, packet, 28);

					ip_header->ip_len = htons(56);
					uint32_t icmpLen = 8 + 20 + 8;
					setIPChecksum(ip_header);
					setICMPChecksum(icmp_header, icmpLen);
					HAL_SendIPPacket(if_index, output, 20 + icmpLen, src_mac);
				}
			}
		}
	}
	return 0;
}
