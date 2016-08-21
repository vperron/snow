/**
 * =====================================================================================
 *
 *   @file analysis.c
 *
 *   
 *        Version:  1.0
 *        Created:  12/15/2012 04:57:14 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Frame analysis routines
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */


#include "main.h"
#include "utils.h"
#include "packet.h"
#include "local_ieee80211_radiotap.h"

#include <math.h>


#define GET_8BIT(p) (*(p))
#define GET_16BIT_LE(p) \
  ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int16_t)*((const u_int8_t *)(p) + 0)))
#define GET_32BIT_LE(p) \
  ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
    (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
    (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int32_t)*((const u_int8_t *)(p) + 0)))

#define GET_64BIT_LE(p) \
  ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
    (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
    (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
    (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
    (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
    (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
    (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int64_t)*((const u_int8_t *)(p) + 0)))


#define IS_SET(flags, bit)  (flags & (u_int32_t)pow(2,bit))

typedef struct ieee80211_radiotap_header tap_header_t;
typedef enum ieee80211_radiotap_type tap_type_t;

static int s_offset_table[32] = {
  sizeof(u_int64_t),     /* time synchro */ 
  2*sizeof(u_int8_t),      /* flags */
  0*sizeof(u_int8_t),      /* Tx/Rx data rate [SEENS DEPRECATED IN FAVOR OF FLAGS] */
  2*sizeof(u_int16_t),     /* Tx/Rx freq in MHz and flags */
  sizeof(u_int16_t),     /* hop setting and pattern */
  sizeof(int8_t),        /* RF signal power of antenna, difference to a milliwatt */
  sizeof(int8_t),        /* RF noise power at the antenna */
  sizeof(u_int16_t),     /* "signal quality" */
  sizeof(u_int16_t),     /* TX attenuation */
  sizeof(u_int16_t),     /* Attenuation bis */ 
  sizeof(int8_t),        /* txpower dBm */
  sizeof(u_int8_t),      /* antenna */
  sizeof(u_int8_t),      /* Signal in DB */
  sizeof(u_int8_t),      /* Noise in DB */ 
  sizeof(u_int32_t),     /* FCS */
};


static u_char* s_header_field_ptr(const u_char* data, u_int32_t flags, tap_type_t mask) 
{
  int i;
  u_char *ptr = (u_char*) data;

  for(i=0;i<(int)mask;i++) {
    if(IS_SET(flags,i)) {
      ptr += s_offset_table[i];
    }
  }

  return ptr;
}

u_int16_t pkt_tap_len(const u_char* p_tap)
{
  tap_header_t* tap_header = (tap_header_t*) p_tap;
  return GET_16BIT_LE(&tap_header->it_len);
}

bool pkt_tap_valid(const u_char* p_tap, u_int16_t len) 
{
  if(pkt_tap_len(p_tap) > len)
    return false;
  return true;
}

u_int64_t pkt_tap_tsft(const u_char* p_tap) 
{
  tap_header_t* tap_header = (tap_header_t*)p_tap;
  u_char* tap_payload = (u_char*)p_tap + sizeof(tap_header_t);
  u_int32_t present = GET_32BIT_LE(&tap_header->it_present);
  if(IS_SET(present,IEEE80211_RADIOTAP_TSFT))
    return GET_64BIT_LE(s_header_field_ptr(tap_payload,
          present,IEEE80211_RADIOTAP_TSFT));

  return -1;
}

int8_t pkt_tap_dbm_antsignal(const u_char* p_tap) 
{
  tap_header_t* tap_header = (tap_header_t*)p_tap;
  u_char* tap_payload = (u_char*)p_tap + sizeof(tap_header_t);
  u_int32_t present = GET_32BIT_LE(&tap_header->it_present);
  if(IS_SET(present,IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) 
    return GET_8BIT(s_header_field_ptr(tap_payload,present,IEEE80211_RADIOTAP_DBM_ANTSIGNAL));

  return -1;
}

u_int8_t pkt_80211_type(const u_char* p_wlan) 
{
  return (((u_int8_t)*p_wlan) & 0x0C) >> 2; /* bits 2 and 3 of FCF */
}

u_int8_t pkt_80211_subtype(const u_char* p_wlan) 
{
  return (((u_int8_t)*p_wlan) & 0xf0) >> 4; /* bits 4-7 of FCF */
}

u_int8_t pkt_80211_flags(const u_char* p_wlan) 
{
  return ((u_int8_t)*(p_wlan+1)); /*  second byte of frame */
}

void pkt_80211_mgt_hwaddr(const u_char* p_data, u_char* out_hwaddr)
{
  memcpy(out_hwaddr,p_data+10,6);
}

void pkt_80211_mgt_dstaddr(const u_char* p_data, u_char* out_dstaddr)
{
  memcpy(out_dstaddr,p_data+4,6);
}

void pkt_80211_mgt_bssid(const u_char* p_data, u_char* out_bssid)
{
  memcpy(out_bssid,p_data+16,6);
}

char* pkt_80211_mgt_ssid(const u_char* p_data)
{
  char* buf = NULL;
  int i;
  u_int8_t offset_in_pkt = 0;
  u_int8_t tag_type = 0;
  u_int8_t tag_len = 0, real_tag_len = 0;
  u_int8_t type = pkt_80211_type(p_data);
  u_int8_t subtype = pkt_80211_subtype(p_data);

  if(type != MGT_FRAME)
    return NULL;

  if( (subtype != MGT_PROBE_REQ) &&
      (subtype != MGT_ASSOC_REQ) &&
      (subtype != MGT_REASSOC_REQ))
    return NULL;


  switch(subtype) {
    case MGT_PROBE_REQ:
      offset_in_pkt = 24; /* MGT frame length*/
      break;
    case MGT_ASSOC_REQ:
      /*  Skip calpab. info and listen interval fields */
      offset_in_pkt = 24 + 2 + 2;
      break;
    case MGT_REASSOC_REQ:
      /*  Skip calpab. info, listen interval and previous AP fields */
      offset_in_pkt = 24 + 2 + 2 + 6;
      break;
  }

  tag_type = *(p_data + offset_in_pkt);
  tag_len = *(p_data + offset_in_pkt + 1);
  if(tag_type == TAG_TYPE_SSID && tag_len != 0) {
    const char *ptr = (const char *)&p_data[offset_in_pkt+2];
    buf = utils_escape_ssid(ptr, tag_len);
  }

  return buf;
}

bool pkt_80211_is_ap(const u_char* p_data) 
{
  if(pkt_80211_type(p_data) == MGT_FRAME && pkt_80211_subtype(p_data) == MGT_BEACON) {
    u_int16_t calpab = GET_16BIT_LE(p_data + 24 /* MGT frame */ + 10 /* TS+BeaconInterval */);
    return calpab & 0x01; /* ESS calpability, acces point */
  }
  return false;
}

void pkt_80211_data_hwaddr(const u_char* p_data, u_char* out_hwaddr)
{
  switch (FCF_ADDR_SELECTOR(pkt_80211_flags(p_data)))
  {
    case DATA_ADDR_T1:
      memcpy(out_hwaddr,p_data+10,6);
      break;
    case DATA_ADDR_T2:
      memcpy(out_hwaddr,p_data+16,6);
      break;
    case DATA_ADDR_T3:
      memcpy(out_hwaddr,p_data+10,6);
      break;
    case DATA_ADDR_T4:
      memcpy(out_hwaddr,p_data+24,6);
      break;
  }
}

void pkt_80211_data_dstaddr(const u_char* p_data, u_char* out_dstaddr)
{
  switch (FCF_ADDR_SELECTOR(pkt_80211_flags(p_data)))
  {
    case DATA_ADDR_T1:
      memcpy(out_dstaddr,p_data+4,6);
      break;
    case DATA_ADDR_T2:
      memcpy(out_dstaddr,p_data+4,6);
      break;
    case DATA_ADDR_T3:
      memcpy(out_dstaddr,p_data+16,6);
      break;
    case DATA_ADDR_T4:
      memcpy(out_dstaddr,p_data+16,6);
      break;
  }
}

void pkt_80211_data_bssid(const u_char* p_data, u_char* out_bssid)
{
  switch (FCF_ADDR_SELECTOR(pkt_80211_flags(p_data)))
  {
    case DATA_ADDR_T1:
      memcpy(out_bssid,p_data+16,6);
      break;
    case DATA_ADDR_T2:
      memcpy(out_bssid,p_data+10,6);
      break;
    case DATA_ADDR_T3:
      memcpy(out_bssid,p_data+4,6);
      break;
    case DATA_ADDR_T4:
      memcpy(out_bssid,p_data+16,6);
      break;
  }
}

snow_pkt_info* pkt_snow_new() 
{
  snow_pkt_info* info = malloc(sizeof(snow_pkt_info));
  memset(info,0,sizeof(snow_pkt_info));
  return info;
}

void pkt_snow_destroy(snow_pkt_info* pkt)
{
  if(pkt->ssid)
    free(pkt->ssid);
  free(pkt);
}
