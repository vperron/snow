/**
 * =====================================================================================
 *
 *   @file iwcontrol.c
 *
 *   
 *        Version:  1.0
 *        Created:  12/14/2012 03:26:18 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Wireless interface control routines
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include "main.h"
#include "utils.h"
#include "iwcontrol.h"

#define IWFREQ_1MHZ 1000000

typedef struct _iw_channel_assoc {
	int channel;
	int freq_mhz;
} iw_channel_assoc;

static iw_channel_assoc wlan_channels [] = {
	/* 2.4 GHz (802.11b/g/n) */
	{ 1, 2412 }, { 2, 2417 }, { 3, 2422 }, { 4, 2427 }, { 5, 2432 },
	{ 6, 2437 }, { 7, 2442 },	{ 8, 2447 }, { 9, 2452 },	{ 10, 2457 },
	{ 11, 2462 }, { 12, 2467 }, { 13, 2472 }, { 14, 2484 }, 
	/*  5 GHz (802.11a/h/j/n) */
	{ 36, 5180 },	{ 40, 5200 }, { 42, 5210 }, { 44, 5220 }, { 48, 5240 }, 
	{ 50, 5250 },	{ 52, 5260 }, { 56, 5280 }, { 58, 5290 }, { 60, 5300 }, { 64, 5320 },

	{ 149, 5745 }, { 152, 5760 }, { 153, 5765 }, { 157, 5785 }, { 160, 5800 },
	{ 161, 5805 }, { 165, 5825 }
};

/* Straight ftom wireless_tools */
static void iwconfig_float2freq(double in_val, struct iw_freq *out_freq) {
	if (in_val <= 165) {
		out_freq->m = (unsigned int) in_val;            
		out_freq->e = 0;
		return;
	}

	out_freq->e = (short) (floor(log10(in_val)));
	if(out_freq->e > 8) {  
		out_freq->m = ((long) (floor(in_val / pow(10,out_freq->e - 6)))) * 100; 
		out_freq->e -= 8;
	}  
	else {  
		out_freq->m = (unsigned int) in_val;            
		out_freq->e = 0;
	}  
}

static float iwcontrol_freq2channel(int freq) 
{
	int i;

	/* In case the driver returned one of the 14 2.4GHz-5GHz channels straight */
	/*  See http://en.wikipedia.org/wiki/List_of_WLAN_channels  */
	if (freq > 0 && freq < 196)
		return freq;

	for(i=0;i<sizeof(wlan_channels);i++) {
		if(freq == wlan_channels[i].freq_mhz)
			return wlan_channels[i].channel;
	}

	return STATUS_ERROR;
}

static float iwcontrol_channel2freq(int channel) 
{
	int i;

	for(i=0;i<sizeof(wlan_channels);i++) {
		if(channel == wlan_channels[i].channel)
			return wlan_channels[i].freq_mhz;
	}

	return STATUS_ERROR;
}
int iwcontrol_set_mode(const char *iface, int mode) 
{
	int sock;
	struct iwreq wrq;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, iface, IFNAMSIZ);
	wrq.u.mode = mode;

	if (ioctl(sock, SIOCSIWMODE, (caddr_t) &wrq) < 0) {
		errorLog("Could not set mode : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return STATUS_OK;
}

int iwcontrol_get_mode(const char *iface) 
{
	int sock;
	struct iwreq wrq;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, iface, IFNAMSIZ);

	if (ioctl(sock, SIOCGIWMODE, (caddr_t) &wrq) < 0) {
		errorLog("Could not get mode : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return wrq.u.mode;
}

int iwcontrol_get_flags(const char *iface) 
{
	int sock;
	struct ifreq ifr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&ifr, 0, sizeof(struct iwreq));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		errorLog("Could not read flags : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return ifr.ifr_flags;
}

int iwcontrol_get_mac_address(const char *iface, u_char* out_hwaddr)
{
	int sock;
	struct ifreq ifr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct iwreq));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);

  if (ioctl(sock, SIOCGIFHWADDR, (caddr_t) &ifr) < 0) {
		errorLog("Could not read mac address : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return -1;
	}

	close(sock);
  memcpy(out_hwaddr, (const unsigned char*)&ifr.ifr_hwaddr.sa_data, 6);
  return 0;
}

int iwcontrol_set_flags(const char *iface, int flags) 
{
	int sock;
	struct ifreq ifr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&ifr, 0, sizeof(struct iwreq));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_flags = flags;

	if (ioctl(sock, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		errorLog("Could not set flags : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return STATUS_OK;
}

int iwcontrol_is_mac80211(const char *iface) 
{
	char devlink[MAX_STRING_LEN];
	struct stat buf;

	snprintf(devlink, MAX_STRING_LEN, "/sys/class/net/%s/phy80211", iface);
	if (stat(devlink, &buf) != 0)
		return STATUS_ERROR;

	return STATUS_OK;
}    

int iwcontrol_get_channel(const char *iface) 
{
	int sock;
	struct iwreq iwr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&iwr, 0, sizeof(struct iwreq));
	strncpy(iwr.ifr_name, iface, IFNAMSIZ);

	if (ioctl(sock, SIOCGIWFREQ, (caddr_t) &iwr) < 0) {
		errorLog("Could not get channel : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return iwcontrol_freq2channel(iwr.u.freq.m);
}

int iwcontrol_set_channel(const char *iface, int channel) 
{
	int sock;
	struct iwreq wrq;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		errorLog("Could not create foo socket");
		return STATUS_ERROR;
	}

	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, iface, IFNAMSIZ);

	int in_ch = iwcontrol_channel2freq(channel);
#ifdef HAVE_LINUX_IWFREQFLAG
	wrq.u.freq.flags = IW_FREQ_FIXED;
#endif
	if (in_ch > 1024) 
		iwconfig_float2freq(in_ch * 1e6, &wrq.u.freq);
	else
		iwconfig_float2freq(in_ch, &wrq.u.freq);

	if (ioctl(sock, SIOCSIWFREQ, (caddr_t) &wrq) < 0) {
		errorLog("Could not set channel : err %d, '%s'",errno,strerror (errno));
		close(sock);
		return STATUS_ERROR;
	}

	close(sock);
	return STATUS_OK;
}
