#include "dot11.h"
#include "radiotap.h"
#include <map>
#include <string.h>
#include <arpa/inet.h>



uint8_t* make_beacon(vector<uint8_t> mac,struct ap select,uint8_t* pk_size,int num){

    uint8_t *packet;
    struct radiotap beacon_radio;
    beacon_radio.version=0;
    beacon_radio.pad=0;
    beacon_radio.len=8;
    beacon_radio.present=0;
    //memset((uint8_t*)&beacon_radio+4,0,beacon_radio.len-4);

    struct dot11_header beacon_header;


    for(int i=0;i<6;i++){
        beacon_header.bssid[i]=mac.at(i);
        beacon_header.sour[i]=mac.at(i);}
    //memset(beacon_header.sour,0x11,6);
    //memset(beacon_header.bssid,0x11,6);
    memset(beacon_header.dest,0xFF,6);
    beacon_header.duration=0x0000;
    beacon_header.seq=0x0000;

    beacon_header.fc.protver=0;
    beacon_header.fc.type=0;
    beacon_header.fc.subtype=8;
    beacon_header.fc.tods=0;
    beacon_header.fc.fromds=0;
    beacon_header.fc.moref=0;
    beacon_header.fc.retry=0;
    beacon_header.fc.power=0;
    beacon_header.fc.mored=0;
    beacon_header.fc.wep=0;
    beacon_header.fc.rsvd=0;

    struct beacon_fixed beacon_body;
    memset(beacon_body.timestamp,0x00,8);
    beacon_body.interval=0;
    beacon_body.capab=0;

    struct ssid beacon_ssid;
    beacon_ssid.ssid_num=0;
    beacon_ssid.ssid_len=select.essid_len+2;
    //beacon_ssid.ssid_len=select.essid_len;

    const int size = beacon_ssid.ssid_len;

    uint8_t ssid[size];
    int temp=0;
    for(auto i=select.essid.begin();i!=select.essid.end();i++)
           {
        ssid[temp++]=*i;
    }

    ssid[temp++]=0x2d;
    ssid[temp]=48+num;


    *(pk_size)=beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(beacon_ssid)+size;
    packet=(uint8_t*)malloc(sizeof(uint8_t)*(*pk_size));

    memcpy(packet,(uint8_t*)&beacon_radio,beacon_radio.len);
    memcpy(packet+beacon_radio.len,(uint8_t*)&beacon_header,sizeof(struct dot11_header));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header),(uint8_t*)&beacon_body,sizeof(struct beacon_fixed));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed),(uint8_t*)&beacon_ssid,sizeof(struct ssid));
    memcpy(packet+beacon_radio.len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+sizeof(struct ssid),(uint8_t*)ssid,size);

    /*
    for(int i=0;i<*pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");*/

    return packet;


}

uint8_t* make_deauth(vector<uint8_t> mac,uint8_t* size){



    uint8_t* packet;

    struct radiotap deauth_radio;

    deauth_radio.version=0x00;
    deauth_radio.pad=0;
    deauth_radio.len=8;
    deauth_radio.present=0;
    //packet=(uint8_t*)&deauth_radio;
    struct dot11_header deauth_header;

    for(int i=0;i<6;i++){
        deauth_header.bssid[i]=mac.at(i);
        deauth_header.sour[i]=mac.at(i);}

    memset(deauth_header.dest,0xFF,6);
    deauth_header.duration=0x0000;
    deauth_header.seq=0x0000;

    deauth_header.fc.protver=0;
    deauth_header.fc.type=0;
    deauth_header.fc.subtype=0xc;
    deauth_header.fc.tods=0;
    deauth_header.fc.fromds=0;
    deauth_header.fc.moref=0;
    deauth_header.fc.retry=0;
    deauth_header.fc.power=0;
    deauth_header.fc.mored=0;
    deauth_header.fc.wep=0;
    deauth_header.fc.rsvd=0;

    uint16_t reason_code =0x0007;
    int pk_size=deauth_radio.len+sizeof(struct dot11_header)+sizeof(uint16_t);
    packet=(uint8_t*)malloc(sizeof(uint8_t)*pk_size);
    memcpy(packet,(uint8_t*)&deauth_radio,deauth_radio.len);
    memcpy(packet+deauth_radio.len,(uint8_t*)&deauth_header,sizeof(struct dot11_header));
    memcpy(packet+deauth_radio.len+sizeof(struct dot11_header),(uint8_t*)&reason_code,sizeof(uint16_t));


/*
    for(int i=0;i<pk_size;i++)
        printf("%02x",*(packet+i));
    printf("\n");
*/

    *size= pk_size;

    return packet;

}
