#include <pcap.h>
#include <stdlib.h>
#include "dot11.h"
#include "radiotap.h"
#include <set>
#include <string.h>
#include <vector>


void usage(){

    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

int main(int argc, char *argv[])
{

    using namespace std;
    if(argc!=2){
        usage();
        return -1;
    }

   /*interface open*/

    char* dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return -1;
    }

    /*get packet*/

    int cnt=0;

    set<vector<uint8_t>> ap_list ;
    printf("BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID  \n");
    while(true){
    if(cnt==50) break;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle,&header,&packet);
    if(res ==0) continue;
    if(res == -1 || res == -2) break;

    struct radiotap *rd = (struct radiotap *) packet;
    struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);
    if(dot11->fc.type != 0 || dot11->fc.subtype!=0x08) continue;

    uint8_t *target = dot11->bssid;


   vector<uint8_t> temp;
   for(int i=0;i<6;i++)
       temp.push_back(*(target+i));
   cnt++;
   if(!ap_list.insert(temp).second) continue;





    for(int i=0;i<5;i++)
        printf("%02x:",dot11->bssid[i]);
    printf("%02x\n",dot11->bssid[5]);




    }

    printf("total AP : %ld\n",ap_list.size());
/*
    for(auto i=ap_list.begin();i!=ap_list.end();i++)
            {

             for(int j=0;j<5;j++)
                 printf("%02x:",(*i)[j]);
             printf("%02x\n",(*i)[5]);

            }
*/
}
