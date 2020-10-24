#include <pcap.h>
#include <stdlib.h>
#include "dot11.h"
#include "radiotap.h"
#include <set>
#include <string.h>
#include <vector>
#include <map>


void usage(){

    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}


struct ap{

    //vector<uint8_t> bssid;
    vector<uint8_t> essid;
    uint8_t beacon;
    int8_t pwr;
};


int main(int argc, char *argv[])
{

    //using namespace std;
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
    map<vector<uint8_t>,struct ap> ap_ls;
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
       vector<uint8_t> name;
       for(int i=0;i<6;i++)
           temp.push_back(*(target+i));
       cnt++;
       if(!ap_list.insert(temp).second) {ap_ls.find(temp)->second.beacon++; continue;}


       struct ssid *size_ptr= (struct ssid *)(packet+rd->len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed));

       uint8_t size = size_ptr->ssid_len;

       for(int i=0;i<size;i++){

                name.push_back(*((uint8_t *)(packet+rd->len+sizeof(dot11_header)+sizeof(struct beacon_fixed)+2+i)));
       }
       struct ap temp_ap;
       temp_ap.beacon=1;
       temp_ap.essid=name;
       temp_ap.pwr=-((~(rd->signal)+1)&0x000000FF);
       //printf("%d\n",temp_ap.pwr);
       ap_ls.insert({temp,temp_ap});




/*
       for(int i=0;i<5;i++)
            printf("%02x:",dot11->bssid[i]);
       printf("%02x",dot11->bssid[5]);
       printf("                                                         ");
       for(auto i=name.begin();i<name.end();i++)
            printf("%c",(*i));
       printf("\n");*/
    }



/*
    for(auto i=ap_list.begin();i!=ap_list.end();i++)
            {

             for(int j=0;j<5;j++)
                 printf("%02x:",(*i)[j]);
             printf("%02x\n",(*i)[5]);

            }
*/


    for(auto i=ap_ls.begin();i!=ap_ls.end();i++)
           {

             for(int j=0;j<5;j++)
                 printf("%02x:",i->first[j]);
             printf("%02x",i->first[5]);
             printf("  %3d",i->second.pwr);
             printf("  %7d",i->second.beacon);
             printf("                                           ");
             for(auto k=i->second.essid.begin();k<i->second.essid.end();k++)
                  printf("%c",(*k));
             printf("\n");

           }
        printf("total AP : %ld\n",ap_list.size());
}
