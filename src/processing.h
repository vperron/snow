/**
 * =====================================================================================
 *
 *   @file processing.h
 *
 *
 *        Version:  1.0
 *        Created:  03/21/2013 10:03:42 PM
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

#include "main.h"
#include "packet.h"

#include <czmq.h>

#ifndef _SNOW_PROCESSING_H_
#define _SNOW_PROCESSING_H_

#ifdef __cplusplus
extern "C" {
#endif

snow_pkt_info* processing_pcap_to_snow(
    bool ignoreap, bool ignoredata, bool ignoreoui,
    zhash_t* access_points, uint64_t* last_timestamp,
    uint8_t* pkthdr, uint8_t* ptr,
    snow_perf_monitor* perf,
    uint8_t* oui, uint64_t seed);

void processing_destroy_packet(snow_pkt_info* info);

void processing_selftest (int verbose);


#ifdef __cplusplus
}
#endif

#endif // _SNOW_PROCESSING_H_
