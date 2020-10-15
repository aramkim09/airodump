#ifndef RADIOTAP_H
#define RADIOTAP_H
#include <stdint.h>

#pragma pack(push,1)

struct radiotap
{
  uint8_t version;
  uint8_t pad;
  uint16_t len;
  uint32_t present;

  /*
  uint8_t time[8];
  uint8_t c_flag;
  uint16_t freq;
  uint16_t chan;
  uint8_t signal;
  uint8_t ant;
  uint16_t rx_flag;
  */

};



#pragma pack(pop)



#endif // RADIOTAP_H
