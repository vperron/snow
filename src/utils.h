/**
 * =====================================================================================
 *
 *   @file utils.h
 *
 *   
 *        Version:  1.0
 *        Created:  03/21/2013 10:33:22 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Utilities
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include "main.h"
#include <ctype.h>

#ifndef _SNOW_UTILS_H_
#define _SNOW_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define U32V(v) ((uint32_t)(v) & 0xffffffff)

#define SWAP32(value) (   (((value) >> 24) & 0xff) | \
    (((value) >> 8) & 0xff00) | \
    (((value) << 8) & 0xff0000) | \
    (((value) << 24) & 0xff000000) )

#define SWAP64(v) \
  (((uint64_t)SWAP32(U32V(v)) << 32) | (uint64_t)SWAP32(U32V(v >> 32)))

double utils_now_millis();
char* utils_escape_ssid(const char* input, int len);
char *utils_hex_to_string (const unsigned char *hex, int len);
char *utils_raw_mac_to_string (const unsigned char *mac);
bool utils_is_big_endian(void);
bool utils_is_printable(unsigned char c);
bool utils_escape_json_char(char c);

void utils_selftest (int verbose);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_UTILS_H_
