/**
 * =====================================================================================
 *
 *   @file iwhelper.c
 *
 *   
 *        Version:  1.0
 *        Created:  12/15/2012 11:20:02 AM
 *
 *
 *   @section DESCRIPTION
 *
 *       Higher-level helper functions for iwcontrol
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include "main.h"
#include "iwhelper.h"

int iwhelper_down_interface(const char *iface) 
{
	int i;
	int flags = iwcontrol_get_flags(iface);
	for(i=0;i<IWHELPER_MAX_ATTEMPTS;i++) {
		assert(iwcontrol_set_flags(iface, flags & ~(IFF_RUNNING | IFF_UP)) != STATUS_ERROR);
		if(!iwhelper_is_interface_up(iface))
			return STATUS_OK;
		usleep(IWHELPER_SMALL_TIMEO);
	}
	return STATUS_ERROR;
}

int iwhelper_up_interface(const char *iface) 
{
	int i;
	int flags = iwcontrol_get_flags(iface);
	for(i=0;i<IWHELPER_MAX_ATTEMPTS;i++) {
		assert(iwcontrol_set_flags(iface, flags | IFF_UP) != STATUS_ERROR);
		if(iwhelper_is_interface_up(iface))
			return STATUS_OK;
		usleep(IWHELPER_SMALL_TIMEO);
	}
	return STATUS_ERROR;
}

int iwhelper_is_interface_up(const char *iface) 
{
	int flags = iwcontrol_get_flags(iface);
	return flags & (IFF_UP | IFF_RUNNING);
}

int iwhelper_enforce_mode(const char *iface, int mode) 
{
	int i;

	for(i=0;i<IWHELPER_MAX_ATTEMPTS;i++) {
		if(iwcontrol_set_mode(iface, mode) == STATUS_ERROR) {
			switch(errno) {
				case EBUSY:
					iwhelper_down_interface(iface);
					while(iwcontrol_set_mode(iface, mode) == STATUS_ERROR)
						usleep(IWHELPER_SMALL_TIMEO);
					break;
				default:
					return STATUS_ERROR;
			}
		}
		if(iwcontrol_get_mode(iface) == mode)
			return STATUS_OK;
	}

	return STATUS_ERROR;
}

int iwhelper_enforce_channel(const char *iface, int channel)
{
	return 0;
}
