/**
 * =====================================================================================
 *
 *   @file iwhelper.h
 *
 *   
 *        Version:  1.0
 *        Created:  12/15/2012 11:20:23 AM
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

#include "iwcontrol.h"

#ifndef _SNOW_IWHELPER_H_
#define _SNOW_IWHELPER_H_

#ifdef __cplusplus
extern "C" {
#endif

//  ---------------------------------------------------------------------
//  DEFINITIONS

#define IWHELPER_MAX_ATTEMPTS 5
#define IWHELPER_SMALL_TIMEO 100000 // usec, == 100msec



//  ---------------------------------------------------------------------
//  PROTOTYPES

int iwhelper_is_interface_up(const char *iface);
int iwhelper_down_interface(const char *iface);
int iwhelper_up_interface(const char *iface);
int iwhelper_enforce_mode(const char *iface, int mode);
int iwhelper_enforce_channel(const char *iface, int channel);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_IWCONTROL_H_
