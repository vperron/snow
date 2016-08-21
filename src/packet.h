/**
 * =====================================================================================
 *
 *   @file packet.h
 *
 *   
 *        Version:  1.0
 *        Created:  12/15/2012 06:11:14 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */


#ifndef _SNOW_PACKET_H_
#define _SNOW_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _snow_packet_info {
  long ts_sec; 
  long ts_msec;
  uint64_t hwhash;
  uint64_t ssidhash;
  uint8_t sig[3];
  uint8_t mac[6];
  uint8_t bssid[6];
  int8_t dbm;
  char* ssid;
} __attribute__((aligned(2),packed)) snow_pkt_info;


  //  ---------------------------------------------------------------------
  //  DEFINITIONS

#define MGT_FRAME            0x00  /* Frame type is management */
#define CONTROL_FRAME        0x01  /* Frame type is control */
#define DATA_FRAME           0x02  /* Frame type is Data */

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24  /* Length of Management frame-headers */

#define MGT_ASSOC_REQ          0x00  /* association request        */
#define MGT_ASSOC_RESP         0x01  /* association response       */
#define MGT_REASSOC_REQ        0x02  /* reassociation request      */
#define MGT_REASSOC_RESP       0x03  /* reassociation response     */
#define MGT_PROBE_REQ          0x04  /* Probe request              */
#define MGT_PROBE_RESP         0x05  /* Probe response             */
#define MGT_MEASUREMENT_PILOT  0x06  /* Measurement Pilot          */
#define MGT_BEACON             0x08  /* Beacon frame               */
#define MGT_ATIM               0x09  /* ATIM                       */
#define MGT_DISASS             0x0A  /* Disassociation             */
#define MGT_AUTHENTICATION     0x0B  /* Authentication             */
#define MGT_DEAUTHENTICATION   0x0C  /* Deauthentication           */
#define MGT_ACTION             0x0D  /* Action                     */
#define MGT_ACTION_NO_ACK      0x0E  /* Action No Ack              */
#define MGT_ARUBA_WLAN         0x0F  /* Aruba WLAN Specific        */

#define TAG_TYPE_SSID          0x00 /*  SSID type  */
#define TAG_TYPE_RATES         0x01 /*  Supported Rates type  */
#define TAG_TYPE_XT_RATES      0x32 /*  Extended Supported Rates type  */
#define TAG_TYPE_HT_CALP       0x2d /*  HT Calpabilities type  */

  /*
   * Extract an indication of the types of addresses in a data frame from
   * the frame control field.
   */

  /* Bits from the flags field. */
#define FLAG_TO_DS            0x01
#define FLAG_FROM_DS          0x02
#define FLAG_MORE_FRAGMENTS   0x04
#define FLAG_RETRY            0x08
#define FLAG_POWER_MGT        0x10
#define FLAG_MORE_DATA        0x20
#define FLAG_PROTECTED        0x40
#define FLAG_ORDER            0x80

#define FCF_ADDR_SELECTOR(x) ((x) & ((FLAG_TO_DS|FLAG_FROM_DS)))

#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         FLAG_FROM_DS
#define DATA_ADDR_T3         FLAG_TO_DS
#define DATA_ADDR_T4         (FLAG_TO_DS|FLAG_FROM_DS)


//  ---------------------------------------------------------------------
//  PROTOTYPES

/*  TAP layer */
u_int16_t pkt_tap_len(const u_char* p_tap);
bool pkt_tap_valid(const u_char* p_tap, u_int16_t len); 
u_int64_t pkt_tap_tsft(const u_char* p_tap); 
int8_t pkt_tap_dbm_antsignal(const u_char* p_tap); 

/*  802.11 layer  */
u_int8_t pkt_80211_type(const u_char* p_wlan); 
u_int8_t pkt_80211_subtype(const u_char* p_wlan); 
u_int8_t pkt_80211_flags(const u_char* p_wlan); 
bool pkt_80211_is_ap(const u_char* p_data);
void pkt_80211_mgt_hwaddr(const u_char* p_data, u_char* out_hwaddr);
void pkt_80211_mgt_dstaddr(const u_char* p_data, u_char* out_dstaddr);
void pkt_80211_mgt_bssid(const u_char* p_data, u_char* out_bssid);
void pkt_80211_data_hwaddr(const u_char* p_data, u_char* out_hwaddr);
void pkt_80211_data_dstaddr(const u_char* p_data, u_char* out_dstaddr);
void pkt_80211_data_bssid(const u_char* p_data, u_char* out_bssid);

/*  Return the SSID detected in a MGT packet, or NULL */
char* pkt_80211_mgt_ssid(const u_char* p_data);

/* Snow packet management */
snow_pkt_info* pkt_snow_new(); 
void pkt_snow_destroy(snow_pkt_info* pkt);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_PACKET_H_
