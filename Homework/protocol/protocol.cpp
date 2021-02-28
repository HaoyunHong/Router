#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

const uint32_t valid_mask[33] = { 0, 0x00000080, 0x000000c0, 0x000000e0, 0x000000f0, 0x000000f8, 0x000000fc, 0x000000fe, 0x000000ff,
								0x000080ff, 0x0000c0ff, 0x0000e0ff, 0x0000f0ff, 0x0000f8ff, 0x0000fcff, 0x0000feff, 0x0000ffff,
								0x0080ffff, 0x00c0ffff, 0x00e0ffff, 0x00f0ffff, 0x00f8ffff, 0x00fcffff, 0x00feffff, 0x00ffffff,
								0x80ffffff, 0xc0ffffff, 0xe0ffffff, 0xf0ffffff, 0xf8ffffff, 0xfcffffff, 0xfeffffff, 0xffffffff };

/*
  在头文件 rip.h 中定义了结构体 `RipEntry` 和 `RipPacket` 。
  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的
  IP 包。 由于 RIP 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在
  RipPacket 中额外记录了个数。 需要注意这里的地址都是用 **网络字节序（大端序）**
  存储的，1.2.3.4 在小端序的机器上被解释为整数 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 RIP 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
	uint32_t Total_Length = (packet[2] << 8) + packet[3];
	if (Total_Length > len){
    return false;
  }
	// 因为是大端序，所以获取低四位得到IHL，IHL代表IPv4协议包头长度的字节数有几个 32 bit
  uint8_t IHL = packet[0] & 0x0f;
  // 然后得到包头的字节数
  size_t header_length = IHL * 32 / 8;
	uint32_t UDP_length = 8;
  // 获得Command的位置
	uint32_t Command = packet[header_length + UDP_length];
  // 检查Command
	if (Command != 0x01 && Command != 0x02){
    return false;
  }
  // 获得version的位置
	uint32_t version = packet[header_length + UDP_length + 1];
  // 检查version
	if (version != 2){
    return false;
  }
	// 获得zero的位置
	uint32_t zero = packet[header_length + UDP_length + 3] + (packet[header_length + UDP_length + 2] << 8);
	// 检查zero
  if (zero != 0x00){
    return false;
  }

  output->command = Command;
  uint32_t RIP_start = header_length + UDP_length + 4;
  output->numEntries = (Total_Length - RIP_start) / 20;

	for (uint32_t i = 0; i < output->numEntries; i++)
	{
    // 获得 Family
    uint32_t Family = packet[RIP_start + 1] + (packet[RIP_start]<<8);
    // 检测 Family 和 Command 的关系
    if (Family != 2*Command - 2){
      return false;
    }
    // 获得 Tag
    uint32_t Tag = packet[RIP_start + 3] + (packet[RIP_start + 2] << 8);
    // 检测 Tag
    if (Tag != 0){
      return false;
    }
    // 获得 IP_Address
    uint32_t  addr_start = RIP_start + 4;
    uint32_t IP_Address = packet[addr_start + 3] + (packet[addr_start + 2] << 8) + (packet[addr_start + 1] << 16) + (packet[addr_start] << 24);
    // 获得 Next_Hop
    uint32_t  Next_Hop_start = RIP_start + 12;
    uint32_t Next_Hop = packet[Next_Hop_start + 3] + (packet[Next_Hop_start + 2] << 8) + (packet[Next_Hop_start + 1] << 16) + (packet[Next_Hop_start] << 24);
    // 获得 Mask
    uint32_t  Mask_start = RIP_start + 8;
    uint32_t Mask = packet[Mask_start + 3] + (packet[Mask_start + 2] << 8) + (packet[Mask_start + 1] << 16) + (packet[Mask_start] << 24);
    // 检测 Mask 的二进制是不是连续的 1 与连续的 0 组成
    bool mask_is_valid = false;
    for(uint32_t m : valid_mask){
      if(Mask == ntohl(m)){
        mask_is_valid = true;
        break;
      }
    }
    if (!mask_is_valid){
      return false;
    }
    // 获得 Metrics
    uint32_t Metrics_start = RIP_start + 16;
    uint32_t Metrics = packet[Metrics_start + 3] + (packet[Metrics_start + 2] << 8) + (packet[Metrics_start + 1] << 16) + (packet[Metrics_start] << 24);
    // 检测 Metrics
    if (Metrics < 1 || Metrics > 16){
      return false;
    }
		output->entries[i].addr = ntohl(IP_Address);
		output->entries[i].mask = ntohl(Mask);
    output->entries[i].nexthop = ntohl(Next_Hop);
		output->entries[i].metric = ntohl(Metrics);

    // 每个RIP头都要写
    RIP_start+=20;
	}
	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括
 * Version、Zero、Address Family 和 Route Tag 这四个字段 你写入 buffer
 * 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  uint32_t index = 0;
  // Command
	buffer[index++] = rip->command;
  // version
	buffer[index++] = 0x02;
  // zero
	buffer[index++] = 0x00;
	buffer[index++] = 0x00;

  // 就这么循环写进去就行
	for (uint32_t i = 0; i < rip->numEntries; i++)
	{
    // Family
    buffer[index++] = 0x00;
    buffer[index++] = 2 * rip->command - 2;
    // Tag
    buffer[index++] = 0x00;
    buffer[index++] = 0x00;
    // IP address
		buffer[index++] = ntohl(rip->entries[i].addr) >> 24;
		buffer[index++] = ntohl(rip->entries[i].addr) >> 16;
		buffer[index++] = ntohl(rip->entries[i].addr) >> 8;
		buffer[index++] = ntohl(rip->entries[i].addr);
    // Mask
		buffer[index++] = ntohl(rip->entries[i].mask) >> 24;
		buffer[index++] = ntohl(rip->entries[i].mask) >> 16;
		buffer[index++] = ntohl(rip->entries[i].mask) >> 8;
		buffer[index++] = ntohl(rip->entries[i].mask);
    // Next Hop
		buffer[index++] = ntohl(rip->entries[i].nexthop) >> 24;
		buffer[index++] = ntohl(rip->entries[i].nexthop) >> 16;
		buffer[index++] = ntohl(rip->entries[i].nexthop) >> 8;
		buffer[index++] = ntohl(rip->entries[i].nexthop);
    // Metrics
		buffer[index++] = ntohl(rip->entries[i].metric) >> 24;
		buffer[index++] = ntohl(rip->entries[i].metric) >> 16;
		buffer[index++] = ntohl(rip->entries[i].metric) >> 8;
		buffer[index++] = ntohl(rip->entries[i].metric);
	}
	return index;
}
