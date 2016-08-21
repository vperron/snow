/**
 * =====================================================================================
 *
 *   @file manuf.h
 *
 *   
 *        Version:  1.0
 *        Created:  12/16/2012 12:18:09 PM
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

#include <stdlib.h>
#include <czmq.h>

#ifndef _SNOW_MANUF_H_
#define _SNOW_MANUF_H_

#ifdef __cplusplus
extern "C" {
#endif

zhash_t* manuf_new(const char* filename);
void manuf_destroy(zhash_t* manuf);
char* manuf_frombin(zhash_t* manuf, const u_char* hwaddr);
char* manuf_fromstr(zhash_t* manuf, const char* s_hwaddr);

void manuf_selftest();

#ifdef __cplusplus
}
#endif

#endif // _SNOW_MANUF_H_
