#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include "radiotap.h"
#include "ieee80211.h"

void usage() {
   printf("syntax: airodump <interface>\n");
   printf("sample: airodump wlan0\n");
}

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};

struct data {
   std::string bssid;
   uint32_t beacons;
   uint32_t num_data;
   std::string enc;
   std::string essid;
   
   data(std::string _bssid) {
      bssid = _bssid;
      beacons = 0;
      num_data = 0;
      enc = "-";
   }
   data() : data(""){}
};

std::string addr_to_string (const mac_address &addr) {
   std::string addr_string;
   char temp[5];
   for (int i = 0; i < 6; i++) {
      if (i != 0) addr_string += ':';
      sprintf(temp, "%02x", addr.addr[i]);
      addr_string += temp;
   }
   return addr_string;
}

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }
   
   std::vector<data> packet_info;

   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
      
      printf("\x1B[2J");
      printf("\x1B[H");
      
      printf("\nBSSID\t\t\tBeacons\tnum_data\tENC\tESSID\n");
      for (auto [bssid, beacons, num_data, enc, essid] : packet_info) {
         printf("%s\t%u\t%u\t\t%s\t%s\n", bssid.c_str(), beacons,
         num_data, enc.c_str(), essid.c_str());
      }
      uint32_t remain = header->caplen;
      u_char* packet_ptr = const_cast<u_char*>(packet);
      radiotap_header* radiotapHeader = reinterpret_cast<radiotap_header*>(packet_ptr);
      uint16_t length = radiotapHeader->len;
      packet_ptr += length;
      remain -= length;
      if (remain <= 0) continue;
      if (packet_ptr[0] == 0x80) { // beacon
         packet_ptr += sizeof(IEEE80211_request_header);
         remain -= sizeof(IEEE80211_request_header);
         if(remain <= 0) continue;
         
         mac_address bssid = reinterpret_cast<IEEE80211_address*>(packet_ptr)->bss_id;
         
         std::string bssid_str = addr_to_string(bssid);
         
         int i;
         for (i = 0; i < (int)packet_info.size(); i++) {
            if(packet_info[i].bssid == bssid_str) break;
         }
         if (i == (int)packet_info.size()) {
            packet_info.emplace_back(data(bssid_str));
         }
         
         packet_info[i].beacons++;
         
         packet_ptr += sizeof(IEEE80211_address);
         remain -= sizeof(IEEE80211_address);
         
         packet_ptr += 12; // IEEE 802.11 Wireless Management Fixed parameters
         remain -= 12;
         
         while (remain > 0) {
            uint8_t tag_number = packet_ptr[0], tag_length = packet_ptr[1];
            if (tag_number == 0) { //SSID parameter set
               char essid[256];
               memcpy(essid, packet_ptr + 2, tag_length);
               essid[tag_length] = 0;
               packet_info[i].essid = essid;
            }
            packet_ptr += 2 + tag_length;
            remain -= 2 + tag_length;
         }
      }
   }

   pcap_close(pcap);
}