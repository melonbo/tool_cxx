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

struct st_opt{
    bool flag = false;
    std::string str;
    int num;
};

std::string dst_ipaddr;
uint16_t dst_port = 0;
struct st_opt opt_dst_ip;
struct st_opt opt_src_ip;
struct st_opt opt_dst_port;
struct st_opt opt_src_port;
struct st_opt opt_offset;
struct st_opt opt_lenght;

void printData(unsigned char* data, int len)
{
    for(int i=0; i<len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void packetHandler(unsigned char *user, const struct pcap_pkthdr *pkthdr, unsigned char *packet) {
    // 解析数据包，获取ICMP头
    const struct iphdr *ipHeader = reinterpret_cast<const struct iphdr*>(packet + 14);  // 14是以太网帧头的长度
    const struct udphdr *udpHeader = reinterpret_cast<const struct udphdr*>(packet + 14 + ipHeader->ihl * 4);
    const char* udp_data = reinterpret_cast<const char*>(packet + 14 + ipHeader->ihl * 4 + sizeof(struct udphdr));

    const char ip_from[20];
    const char ip_to[20];
    strcpy(ip_from, inet_ntoa(*(in_addr*)&ipHeader->saddr));
    strcpy(ip_to, inet_ntoa(*(in_addr*)&ipHeader->daddr));
    u_int16_t  port_from = ntohs(udpHeader->source);
    u_int16_t  port_to   = ntohs(udpHeader->dest);

    std::string ip_port = string(ip_to) + ":" + std::to_string(port_to);

    if(opt_src_ip.flag)
    {
        if(opt_src_ip.str.compare(ip_from)!=0)
            return;
    }

    if(opt_dst_ip.flag)
    {
        if(opt_dst_ip.str.compare(ip_to)!=0)
            return;
    }

    if(opt_src_port.flag)
    {
        if(opt_src_port.num!=port_from)
            return;
    }

    if(opt_dst_port.flag)
    {
        if(opt_dst_port.num!=port_to)
            return;
    }

    printf("udp packet size %4d, from %s:%d\t to \t%s:%d\n", ntohs(udpHeader->uh_ulen)-8, ip_from, port_from, ip_to, port_to);

    if(opt_offset.flag)
    {
        if(opt_lenght.flag){
            printData(udp_data+opt_offset.num, opt_lenght.num);
        }
        else
        {
            printData(udp_data+opt_offset.num, ntohs(udpHeader->uh_ulen)-8);
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

int main(int argc, char* argv[])
{
    int result = 0;
    while( (result = getopt(argc, argv, "s:d:f:t:o:l:h")) != -1 )
    {
        switch(result)
        {
            case 's':
                opt_src_ip.flag = true;
                opt_src_ip.str = optarg;
                printf("src ip: %s\n", opt_src_ip.str.c_str());
                break;
            case 'd':
                opt_dst_ip.flag = true;
                opt_dst_ip.str = optarg;
                printf("dst ip: %s\n", optarg);
                break;
            case 'f':
                opt_src_port.flag = true;
                opt_src_port.num = atoi(optarg);
                printf("src port: %d\n", opt_src_port.num);
                break;
            case 't':
                opt_dst_port.flag = true;
                opt_dst_port.num = atoi(optarg);
                printf("dst port: %d\n", opt_dst_port.num);
                break;
            case 'o':
                opt_offset.flag = true;
                opt_offset.num = atoi(optarg);
                printf("start positon: %d\n", opt_offset.num);
                break;
            case 'l':
                opt_lenght.flag = true;
                opt_lenght.num = atoi(optarg);
                printf("length: %d\n", opt_lenght.num);
                break;
            case 'h':
                printf("s: src ip, d: dst ip, f: src port, t: dst port, o: offset, l: length, h: help\n");
                break;
            case '?':
                printf("result=?, optopt=%c, optarg=%s\n", optopt, optarg);
                break;
            default:
                printf("default, result=%c\n",result);
                break;
        }
    }

    capRtpPacket();
    while(1) sleep(1);
    return 0;
}
