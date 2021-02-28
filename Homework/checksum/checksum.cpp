#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  // 因为是大端序，所以获取低四位得到IHL，IHL代表IPv4协议包头长度的字节数有几个 32 bit
  uint8_t IHL = packet[0] & 0x0f;
  // 然后得到包头的字节数
  size_t head_length = IHL * 32 / 8;
  uint32_t sum = 0;
  for (size_t i = 0; i < head_length; i += 2)
    // 因为是大端序，计算反码和
    sum += packet[i + 1] + (packet[i] << 8);
  // 如果有溢出持续加到后面，不过溢出应该不会超过连续两次
  while(sum >> 16){
    sum = (sum & 0xffff) + (sum >> 16);
  }
  if(sum == 0xffff){
    return true;
  } 
  else{
    return false;
  }
}
