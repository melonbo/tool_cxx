#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap/pcap.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
//#include <pthread.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <thread>
#include <unistd.h>

using namespace std;
#define MAX_STREAM 10240

#include <map>
std::map<string,int>map_icmp_unreach;
void packetHandler2(unsigned char *user, const struct pcap_pkthdr *pkthdr, unsigned char *packet) {
    // 解析数据包，获取ICMP头
    const struct iphdr *ipHeader = reinterpret_cast<const struct iphdr*>(packet + 14);  // 14是以太网帧头的长度
    const struct icmphdr *icmpHeader = reinterpret_cast<const struct icmphdr*>(packet + 14 + ipHeader->ihl * 4);  // 偏移到ICMP头
    const struct iphdr *ipHeader_data = reinterpret_cast<const struct iphdr*>(packet + 14 + ipHeader->ihl * 4 + sizeof(struct icmphdr));
    const struct udphdr *udpHeader_data = reinterpret_cast<const struct udphdr*>(packet + 14 + ipHeader->ihl * 4 + sizeof(struct icmphdr) + 20);

    const char ip_from[20];
    const char ip_to[20];
    strcpy(ip_from, inet_ntoa(*(in_addr*)&ipHeader_data->saddr));
    strcpy(ip_to, inet_ntoa(*(in_addr*)&ipHeader_data->daddr));
    u_int16_t  port_from = ntohs(udpHeader_data->source);
    u_int16_t  port_to   = ntohs(udpHeader_data->dest);

    // 检查是否是ICMP回显请求（ping）数据包
    if (icmpHeader->type == ICMP_DEST_UNREACH) {
        printf("receive icmp dest unreach, from %s:%d to %s:%d\n", ip_from, port_from, ip_to, port_to);
        time_t current;
        time(&current);
        std::string ip_port = string(ip_to) + ":" + std::to_string(port_to);
        map_icmp_unreach[ip_port] = current;
    }
}

std::map<string,int>map_rtp_stream;

struct st_rtp_header {
    unsigned char v_p_x_cc;
    unsigned char m_pt;
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[];
}__attribute__((packed));

struct st_rtp_stream_info{
    uint16_t seq_start;
    uint16_t seq_end;
    uint16_t num;
    uint16_t num_last;
}rtp_stream_info[MAX_STREAM];

void printData(unsigned char* data, int len)
{
    for(int i=0; i<len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

bool isRtpPacket(int port, const st_rtp_header* header)
{
    if(port < 10000 && (port<5070 || port >5074))
    {
        return false;
    }
    if(header->v_p_x_cc != 0x80)
    {
        return false;
    }
    return true;
}

void clearScreen() {
    // 使用 ANSI 转义码清屏
    std::cout << "\033[2J\033[H";
}

int rtp_stream_num = 0;
void packetHandler(unsigned char *user, const struct pcap_pkthdr *pkthdr, unsigned char *packet) {
    // 解析数据包，获取ICMP头
    const struct iphdr *ipHeader = reinterpret_cast<const struct iphdr*>(packet + 14);  // 14是以太网帧头的长度
    const struct udphdr *udpHeader_data = reinterpret_cast<const struct udphdr*>(packet + 14 + ipHeader->ihl * 4);
    const struct st_rtp_header* rtpHeader = reinterpret_cast<const struct st_rtp_header*>(packet + 14 + ipHeader->ihl * 4 + sizeof(struct udphdr));

    const char ip_from[20];
    const char ip_to[20];
    strcpy(ip_from, inet_ntoa(*(in_addr*)&ipHeader->saddr));
    strcpy(ip_to, inet_ntoa(*(in_addr*)&ipHeader->daddr));
    u_int16_t  port_from = ntohs(udpHeader_data->source);
    u_int16_t  port_to   = ntohs(udpHeader_data->dest);

    std::string ip_port = string(ip_to) + ":" + std::to_string(port_to);

    if(isRtpPacket(port_to, rtpHeader))
    {
        if(map_rtp_stream.find(ip_port) == map_rtp_stream.end())
        {
            //printf("add a stream %s\n", ip_port.c_str());
            map_rtp_stream[ip_port] = rtp_stream_num;
            rtp_stream_info[rtp_stream_num].seq_start = ntohs(rtpHeader->seq_num);
            rtp_stream_info[rtp_stream_num].seq_end = ntohs(rtpHeader->seq_num);
            rtp_stream_info[rtp_stream_num].num = 1;
            rtp_stream_num += 1;

            if(rtp_stream_num == MAX_STREAM)
                rtp_stream_num = 0;
        }
        else
        {
            int stream_index = map_rtp_stream[ip_port];
            rtp_stream_info[stream_index].seq_end = ntohs(rtpHeader->seq_num);
            rtp_stream_info[stream_index].num += 1;
            //printf("========= %s, %d, %d\n", ip_port.c_str(), stream_index, rtp_stream_info[stream_index].seq_end);

            if(ntohs(rtpHeader->seq_num)==0)
            {
                rtp_stream_info[stream_index].seq_start = 0;
                rtp_stream_info[stream_index].seq_end = 0;
                rtp_stream_info[stream_index].num = 1;
                rtp_stream_info[stream_index].num_last = 1;
            }
        }
    }

    static time_t time_current;
    time(&time_current);
    static time_t time_last = time_current;
    static time_t time_start = time_current;

    if((time_current-time_last)>=1)
    {
        clearScreen();
        time_last = time_current;
        for(auto it=map_rtp_stream.begin(); it!=map_rtp_stream.end(); ++it)
        {
            string stream_ip_port = it->first;
            int stream_index = it->second;
            int num_should = rtp_stream_info[stream_index].seq_end-rtp_stream_info[stream_index].seq_start + 1;
            int num_lost = rtp_stream_info[stream_index].seq_end-rtp_stream_info[stream_index].seq_start + 1 - rtp_stream_info[stream_index].num;
            float lost_ratio = (float)num_lost/num_should*100;
            if(rtp_stream_info[stream_index].num_last != rtp_stream_info[stream_index].num)
                printf("rtp stream %s, start %-6d end %-6d num %-6d should %-6d lost %-6d %.2f\n",
                       stream_ip_port.c_str(),
                       rtp_stream_info[stream_index].seq_start,
                       rtp_stream_info[stream_index].seq_end,
                       rtp_stream_info[stream_index].num,
                       num_should, num_lost, lost_ratio);
            rtp_stream_info[stream_index].num_last = rtp_stream_info[stream_index].num;
        }
    }
}

void capRtpPacket()
{
    char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *handle;

#ifdef ARCH_ARM
      char eth_name[] = "eth0";
#else
      char eth_name[] = "ens33";
#endif
      // 打开网卡 eth0
      handle = pcap_open_live(eth_name, BUFSIZ, 1, 1000, errbuf);
      if (handle == nullptr) {
          std::cerr << "Error opening eth: " << errbuf << std::endl;
          return;
      }

      // 设置过滤规则，仅捕获 udp 数据包
      struct bpf_program fp;
      std::string filter = "udp";
      if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
          std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
          return;
      }
      if (pcap_setfilter(handle, &fp) == -1) {
          std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
          return;
      }
        printf("start receive ...\n");
      // 开始捕获数据包，使用 packetHandler 函数处理每个数据包
      pcap_loop(handle, 0, packetHandler, nullptr);

      // 关闭捕获会话
      pcap_close(handle);
}

int main()
{
//    std::thread([]{capRtpPacket();}).detach();
    capRtpPacket();
    while(1) sleep(1);
    return 0;
}
