/**
 * =====================================================================================
 *
 *   @file main.h
 *
 *   
 *        Version:  1.0
 *        Created:  09/20/2012 08:26:35 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       General headers
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include "platform.h"


#include <unistd.h>
#include <string.h> 
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h> 
#include <stdint.h> 
#include <syslog.h>

#ifndef _SNOW_MAIN_H_
#define _SNOW_MAIN_H_ 

#ifdef __cplusplus
extern "C" {
#endif


#define errorLog(fmt, ...) \
	do { \
		syslog(LOG_INFO,"%s [%s:%d] " fmt "\n", __func__,__FILE__,__LINE__, ##__VA_ARGS__); \
		fprintf(stderr,"%s [%s:%d] " fmt "\n", __func__,__FILE__,__LINE__, ##__VA_ARGS__); \
		fflush(stderr); \
	} while(0)

#if defined(DEBUG) && !defined(TESTING) && !defined(E2E_TESTING)
#define debugLog(fmt, ...) \
	do { \
		syslog(LOG_DEBUG,"%s [%s:%d] " fmt "\n", __func__,__FILE__,__LINE__, ##__VA_ARGS__); \
		printf("%s [%s:%d] " fmt "\n", __func__,__FILE__,__LINE__, ##__VA_ARGS__); \
		fflush(stdout); \
	} while(0)

#else
#define debugLog(fmt, ...) 
#endif

#define STATUS_OK 0
#define STATUS_ERROR -1

#define MAX_STRING_LEN 256

typedef struct _snow_perf_monitor {

	uint32_t pkt_count;
	uint32_t invalid_count;
	uint32_t ap_count;
	uint32_t mgt_count;
	uint32_t data_count;
	uint32_t ctrl_count;
	double t_processing;
	double t_total;

} snow_perf_monitor;



#ifdef __cplusplus
}
#endif

#endif // _SNOW_MAIN_H_
