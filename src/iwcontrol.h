/**
 * =====================================================================================
 *
 *   @file iwcontrol.h
 *
 *   
 *        Version:  1.0
 *        Created:  12/14/2012 03:27:05 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Wireless configuration routines declaration
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include <math.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_LINUX_WIRELESS_H
# include <linux/wireless.h>
#else
#  ifdef HAVE_NET_IF_H
#   include <net/if.h>
#  endif
#  ifdef HAVE_NET_IF_MEDIA_H
#   include <net/if_media.h>
#  endif
#endif

#ifndef _SNOW_IWCONTROL_H_
#define _SNOW_IWCONTROL_H_

#ifdef __cplusplus
extern "C" {
#endif

//  ---------------------------------------------------------------------
//  DEFINITIONS


//  ---------------------------------------------------------------------
//  PROTOTYPES

int iwcontrol_get_mode(const char *iface);
int iwcontrol_set_mode(const char *iface, int mode);
int iwcontrol_get_flags(const char *iface);
int iwcontrol_set_flags(const char *iface, int flags);
int iwcontrol_get_channel(const char *iface);
int iwcontrol_set_channel(const char *iface, int channel);

int iwcontrol_get_mac_address(const char *iface, u_char* out_hwaddr);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_IWCONTROL_H_
