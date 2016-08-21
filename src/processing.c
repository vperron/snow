/**
 * =====================================================================================
 *
 *   @file processing.c
 *
 *
 *        Version:  1.0
 *        Created:  03/21/2013 10:00:26 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Functions related to high-level packet processing.
 *
 *   @section LICENSE
 *
 *
 *
 * =====================================================================================
 */

#include "processing.h"

#include "fnv.h"
#include "utils.h"
#include "packet.h"

#include <pcap.h>


#define UNKNOWN_SSID ""

static uint32_t s_inc_ap_count(zhash_t* aps, const  char* s_hwaddr)
{
  if (aps == NULL) {
    return -1;
  }
  uint32_t* counter = (uint32_t*)zhash_lookup(aps, s_hwaddr);
  if (counter != NULL)
    return ++(*counter);
  return 0;
}

static bool s_update_ap_list(zhash_t* aps, const char* s_hwaddr)
{
  if (aps == NULL) {
    return false;
  }
  void* obj = zhash_lookup(aps, s_hwaddr);
  if (obj == NULL) {
    uint32_t* c = malloc(sizeof(uint32_t)); *c = 0;
    zhash_insert(aps, s_hwaddr, c);
    zhash_freefn(aps, s_hwaddr, free);
    return true;
  }
  return false;
}

snow_pkt_info* processing_pcap_to_snow(
    bool ignoreap, bool ignoredata, bool ignoreoui, zhash_t* access_points,
    uint64_t* last_timestamp, uint8_t* _pkthdr, uint8_t* ptr,
    snow_perf_monitor* perf, uint8_t* oui, uint64_t seed)
{
  uint8_t hwaddr[6];
  uint8_t bssid[6];
  char* s_hwaddr = NULL;
  char* s_bssid = NULL;
  char* s_ssid = NULL;

  snow_pkt_info* info = NULL;

  /*  Performance indicators */
  uint32_t pkt_count = 0;
  uint32_t invalid_count = 0;
  uint32_t ap_count = 0;
  uint32_t mgt_count = 0;
  uint32_t data_count = 0;
  uint32_t ctrl_count = 0;

  assert(_pkthdr);
  assert(ptr);

  struct pcap_pkthdr* pkthdr = (struct pcap_pkthdr*)_pkthdr;

  pkt_count++;
  memset(hwaddr, 0, sizeof(hwaddr));
  double t_start = utils_now_millis();

  if (!pkt_tap_valid(ptr, pkthdr->len)) {
    debugLog("Invalid packet.");
    invalid_count++;
    goto skip_free;
  }

  int8_t dbm = pkt_tap_dbm_antsignal(ptr);
  if (dbm == -1) {
    goto skip_free;
  }

  // Code for the 802.11 layer of the packet
  ptr += pkt_tap_len(ptr);
  u_int8_t type = pkt_80211_type(ptr);
  u_int8_t subtype = pkt_80211_subtype(ptr);
  switch(type) {
    case MGT_FRAME:
      pkt_80211_mgt_hwaddr(ptr, hwaddr);
      pkt_80211_mgt_bssid(ptr, bssid);
      s_hwaddr = utils_hex_to_string(hwaddr, sizeof(hwaddr));
      s_bssid = utils_hex_to_string(bssid, sizeof(bssid));
      s_ssid = pkt_80211_mgt_ssid(ptr);
      mgt_count++;
      if (pkt_80211_is_ap(ptr) &&
          access_points != NULL &&
          s_update_ap_list(access_points, s_hwaddr) == true) {
        debugLog("*** New AP detected ! ***  %s", s_hwaddr);
        goto skip_free;
      }
      break;
    case DATA_FRAME:
      data_count++;
      if (ignoredata) {
        goto skip_free;
      }
      pkt_80211_data_hwaddr(ptr, hwaddr);
      pkt_80211_data_bssid(ptr, bssid);
      s_hwaddr = utils_hex_to_string(hwaddr, sizeof(hwaddr));
      s_bssid = utils_hex_to_string(bssid, sizeof(bssid));
      break;
    default:
      /* We do not handle any other frame type */
      ctrl_count++;
      goto skip_free;
  }

  /* Exit if the hwaddr come from the same OUI as ours */
  if (ignoreoui && oui != NULL) {
    if (( oui[0] == hwaddr[0] ) && (oui[1] == hwaddr[1]) && (oui[2] == hwaddr[2])) {
      goto skip_free;
    }
  }

  /*  If a registered access point */
  if (access_points != NULL && s_inc_ap_count(access_points, s_hwaddr)) {
    ap_count++;
    if (ignoreap) {
      goto skip_free;
    }
  }

  { // Late initialization
    info = pkt_snow_new();
    assert(info);
  }

  info->dbm = dbm;
  info->ts_sec = (uint32_t)pkthdr->ts.tv_sec;
  info->ts_msec = (uint32_t)pkthdr->ts.tv_usec / 1000;

  // Add 1 millisecond to the info structure if we have already received exactly the same timestamp before
  if (last_timestamp != NULL) {
    uint64_t new_timestamp = info->ts_sec*1000 + info->ts_msec;
    if (new_timestamp == *last_timestamp) {
      info->ts_msec++;
      new_timestamp++;
    }
    *last_timestamp = new_timestamp;
  }

  debugLog("packet #%d, len %d, ts %ld, dbm %d, MAC %s, BSSID %s, SSID %s, type %s, sub %02x",
      perf ? perf->pkt_count+pkt_count : 0, pkthdr->len, (long unsigned int)info->ts_sec, info->dbm,
      s_hwaddr, s_bssid, s_ssid, type == MGT_FRAME ? "MGT" : "DATA", subtype);

  info->hwhash = (uint64_t)fnv_64a_buf((void *)hwaddr, 6, seed);
  memcpy(info->mac, hwaddr, 6);
  memcpy(info->sig, hwaddr, 3);
  memcpy(info->bssid, bssid, 6);

  if (s_ssid != NULL) {
    info->ssid = strdup(s_ssid);
    info->ssidhash = (uint64_t)fnv_64a_buf((void *)s_ssid, strnlen(s_ssid, 32), seed);
  }

skip_free:

  if (s_hwaddr)
    free(s_hwaddr);
  if (s_bssid)
    free(s_bssid);
  if (s_ssid)
    free(s_ssid);

  if(perf) {
    perf-> pkt_count +=  pkt_count;
    perf-> invalid_count +=  invalid_count;
    perf-> ap_count +=  ap_count;
    perf-> mgt_count +=  mgt_count;
    perf-> data_count +=  data_count;
    perf-> ctrl_count +=  ctrl_count;
    perf->t_processing += utils_now_millis() - t_start;
  }

  return info;
}

void processing_destroy_packet(snow_pkt_info* info)
{
  pkt_snow_destroy(info);
}



// Test functions

uint8_t* s_test_setup_pkthdr_no_ssid()
{
  char fixture[] = {
    0x9f, 0xd4, 0x4b, 0x51, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x4d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x92, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00 };
  uint8_t* pkthdr = malloc(sizeof(fixture));
  memcpy(pkthdr, fixture, sizeof(fixture));
  return pkthdr;
}

uint8_t* s_test_setup_data_no_ssid()
{
  // ts 1363924127 :: dbm -37 :: src 60facddf56cf :: SSID (null) :: type MGT
  char fixture[] = {
    0x00, 0x00, 0x1a, 0x00, 0x2f, 0x48, 0x00, 0x00, 0xc4, 0x31, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xdb, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x60, 0xfa, 0xcd, 0xdf, 0x56, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x01, 0x00, 0x00, 0x01, 0x04, 0x02, 0x04, 0x0b, 0x16, 0x32, 0x08, 0x0c, 0x12, 0x18, 0x24,
    0x30, 0x48, 0x60, 0x6c, 0x2d, 0x1a, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x01, 0x03, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xdd, 0x1e,
    0x00, 0x90, 0x4c, 0x33, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x34,
    0xb1, 0x13 };
  uint8_t* data = malloc(sizeof(fixture));
  memcpy(data, fixture, sizeof(fixture));
  return data;
}

uint8_t* s_test_setup_pkthdr_foo_ssid()
{
  char fixture[] = {
    0x9f, 0xd4, 0x4b, 0x51, 0x00, 0x00, 0x00, 0x00, 0x48, 0x4d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00 };
  uint8_t* pkthdr = malloc(sizeof(fixture));
  memcpy(pkthdr, fixture, sizeof(fixture));
  return pkthdr;
}

uint8_t* s_test_setup_data_foo_ssid()
{
  // ts 1363924127 :: dbm -37 :: src 60facddf56cf :: SSID foo :: type MGT
  char fixture[] = {
    0x00, 0x00, 0x1a, 0x00, 0x2f, 0x48, 0x00, 0x00, 0xc4, 0x31, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xdb, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x60, 0xfa, 0xcd, 0xdf, 0x56, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x01, 0x00, 0x03, 0x66, 0x6f, 0x6f, 0x01, 0x04, 0x02, 0x04, 0x0b, 0x16, 0x32, 0x08, 0x0c,
    0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, 0x2d, 0x1a, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00,
    0x00, 0xdd, 0x1e, 0x00, 0x90, 0x4c, 0x33, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x34, 0xb1, 0x13 };
  uint8_t* data = malloc(sizeof(fixture));
  memcpy(data, fixture, sizeof(fixture));
  return data;
}

uint8_t* s_test_setup_pkthdr_weird_ssid()
{
  char fixture[] = {
    0x9f, 0xd4, 0x4b, 0x51, 0x00, 0x00, 0x00, 0x00, 0x48, 0x4d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00 };
  uint8_t* pkthdr = malloc(sizeof(fixture));
  memcpy(pkthdr, fixture, sizeof(fixture));
  return pkthdr;
}

uint8_t* s_test_setup_data_weird_ssid()
{
  // ts 1363924127 :: dbm -37 :: src 60facddf56cf :: SSID f?o :: type MGT
  char fixture[] = {
    0x00, 0x00, 0x1a, 0x00, 0x2f, 0x48, 0x00, 0x00, 0xc4, 0x31, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xdb, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x60, 0xfa, 0xcd, 0xdf, 0x56, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x01, 0x00, 0x03, 0x66, 0x91, 0x6f, 0x01, 0x04, 0x02, 0x04, 0x0b, 0x16, 0x32, 0x08, 0x0c,
    0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, 0x2d, 0x1a, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x04, 0x00,
    0x00, 0xdd, 0x1e, 0x00, 0x90, 0x4c, 0x33, 0x0c, 0x10, 0x19, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x34, 0xb1, 0x13 };
  uint8_t* data = malloc(sizeof(fixture));
  memcpy(data, fixture, sizeof(fixture));
  return data;
}

uint8_t* s_test_setup_pkthdr_comma_ssid()
{
  char fixture[] = {
    0x9f, 0xd4, 0x4b, 0x51, 0x00, 0x00, 0x00, 0x00, 0x48, 0x4d, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* packet length just after */
    0x99, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00 };
  uint8_t* pkthdr = malloc(sizeof(fixture));
  memcpy(pkthdr, fixture, sizeof(fixture));
  return pkthdr;
}

uint8_t* s_test_setup_data_comma_ssid()
{
  // ts 1363924127 :: dbm -37 :: src 60facddf56cf :: SSID foo, bar :: type MGT
  char fixture[] = {
    0x00, 0x00, 0x1a, 0x00, 0x2f, 0x48, 0x00, 0x00, 0xc4, 0x31, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xdb, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x60, 0xfa, 0xcd, 0xdf, 0x56, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x01, 0x00, 0x07, 0x66, 0x6f, 0x6f, 0x01, 0x62, 0x61, 0x72, 0x01, 0x04, 0x02, 0x04, 0x0b,
    0x16, 0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, 0x2d, 0x1a, 0x0c, 0x10, 0x19,
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02,
    0x00, 0x00, 0x04, 0x00, 0x00, 0xdd, 0x1e, 0x00, 0x90, 0x4c, 0x33, 0x0c, 0x10, 0x19, 0xff, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x34, 0xb1, 0x13 };
  uint8_t* data = malloc(sizeof(fixture));
  memcpy(data, fixture, sizeof(fixture));
  return data;
}

void processing_selftest (int verbose)
{

  uint8_t* pkthdr = NULL;
  uint8_t* data = NULL;
  snow_pkt_info* info = NULL;

  printf (" * processing_pcap with no ssid : ");
  pkthdr = s_test_setup_pkthdr_no_ssid();
  data = s_test_setup_data_no_ssid();
  info = processing_pcap_to_snow(true, true, true, NULL, NULL, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(info->ts_sec == 1363924127);
  assert(info->ts_msec == 740);
  assert(info->hwhash == 0x5057318babbdb5b2);
  assert(info->sig[0] == 0x60 && info->sig[1] == 0xfa && info->sig[2] == 0xcd);
  assert(info->dbm == -37);
  assert(info->ssid == NULL);
  free(pkthdr);
  free(data);
  processing_destroy_packet(info);
  printf ("OK\n");

  printf (" * processing_pcap with 'foo' ssid : ");
  pkthdr = s_test_setup_pkthdr_foo_ssid();
  data = s_test_setup_data_foo_ssid();
  info = processing_pcap_to_snow(true, true, true, NULL, NULL, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(info->ts_sec == 1363924127);
  assert(info->ts_msec == 740);
  assert(info->hwhash == 0x5057318babbdb5b2);
  assert(info->sig[0] == 0x60 && info->sig[1] == 0xfa && info->sig[2] == 0xcd);
  assert(info->dbm == -37);
  assert(streq(info->ssid, "foo"));
  free(pkthdr);
  free(data);
  processing_destroy_packet(info);
  printf ("OK\n");

  printf (" * processing_pcap with weird ssid : ");
  pkthdr = s_test_setup_pkthdr_weird_ssid();
  data = s_test_setup_data_weird_ssid();
  info = processing_pcap_to_snow(true, true, true, NULL, NULL, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(streq(info->ssid, "fo"));
  free(pkthdr);
  free(data);
  processing_destroy_packet(info);
  printf ("OK\n");

  printf (" * processing_pcap with a ssid containing an escape char ^A : ");
  pkthdr = s_test_setup_pkthdr_comma_ssid();
  data = s_test_setup_data_comma_ssid();
  info = processing_pcap_to_snow(true, true, true, NULL, NULL, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(streq(info->ssid, "foobar"));
  free(pkthdr);
  free(data);
  processing_destroy_packet(info);
  printf ("OK\n");

  printf (" * processing_pcap with two same-time measures : ");
  uint64_t timestamp = 0;
  pkthdr = s_test_setup_pkthdr_foo_ssid();
  data = s_test_setup_data_foo_ssid();
  info = processing_pcap_to_snow(true, true, true, NULL, &timestamp, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(info->ts_sec == 1363924127);
  assert(info->ts_msec == 740);
  assert(timestamp == 1363924127740);
  processing_destroy_packet(info);
  info = processing_pcap_to_snow(true, true, true, NULL, &timestamp, pkthdr, data, NULL, NULL, 0xdeadbeefdeadbeef);
  assert(info);
  assert(info->ts_sec == 1363924127);
  assert(info->ts_msec == 741);
  assert(timestamp == 1363924127741);
  free(pkthdr);
  free(data);
  processing_destroy_packet(info);
  printf ("OK\n");
}
