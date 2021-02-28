#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include<iostream>

using namespace std;


// 在 checksum.cpp 中定义
extern bool validateIPChecksum(uint8_t *packet, size_t len);

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以调用 checksum 题中的 validateIPChecksum 函数，
 *        编译的时候会链接进来。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  // 如果校验和有误，直接返回false，不做下一步处理
  if (!validateIPChecksum(packet, len)){
    return false;
  }	
	else
	{
    // //TTL-1
		// packet[8] -= 1;
    // // 校验和变 0
		// packet[10] = 0x00;
    // packet[11] = 0x00;

    // // 因为是大端序，所以获取低四位得到IHL，IHL代表IPv4协议包头长度的字节数有几个 32 bit
    // uint8_t IHL = packet[0] & 0x0f;
    // // 然后得到包头的字节数
    // size_t head_length = IHL * 32 / 8;
    // uint32_t sum = 0;
    // for (size_t i = 0; i < head_length; i += 2)
    //   // 因为是大端序，计算反码和
    //   sum += packet[i + 1] + (packet[i] << 8);
    // // 如果有溢出持续加到后面，不过溢出应该不会超过连续两次
    // while(sum >> 16){
    //   sum = (sum & 0xffff) + (sum >> 16);
    // }
    // uint32_t rev_sum = ~sum;
    // // 再填回去
		// packet[10] = rev_sum >> 8;
		// packet[11] = rev_sum & 0xff;

  // 发现这么写更简单些
  ip *ip_header = (ip *) packet;
  // TTL -1
  ip_header->ip_ttl -= 1;
  // 校验和变 0
  ip_header->ip_sum = 0;
  uint32_t sum = 0;
  // 然后得到包头的字节数
  size_t head_length = ip_header->ip_hl * 32 / 8;
  for (size_t i = 0; i < head_length; i += 2){
    // 因为是大端序，计算反码和
    sum += packet[i + 1] + (packet[i] << 8);
    // 如果有溢出持续加到后面，不过溢出应该不会超过连续两次
  }  
  while(sum >> 16){
    sum = (sum & 0xffff) + (sum >> 16);
  }
  ip_header->ip_sum = htons(~sum);
	return true;
	}
}
