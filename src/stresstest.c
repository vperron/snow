/**
 * =====================================================================================
 *
 *   @file main.c
 *
 *
 *        Version:  1.0
 *        Created:  09/20/2012 07:49:49 PM
 *
 *
 *   @section
 *
 *       Main driver loop
 *
 *   @section LICENSE
 *
 *
 *
 * =====================================================================================
 */

#include <uci.h>

#include "main.h"
#include "utils.h"
#include "processing.h"
#include "iwcontrol.h"
#include "iwhelper.h"
#include "zeromq.h"
#include "config.h"

#include <pcap.h>
#include <ctype.h>
#include <czmq.h>

//  ---------------------------------------------------------------------
//  DEFINITIONS

#define SNOW_IDENTITY "snow"
#define CONF_CAPTURE_IFACE       "snow.capture.iface"
#define CONF_CAPTURE_IGNOREAP    "snow.capture.ignoreap"
#define CONF_CAPTURE_IGNOREDATA  "snow.capture.ignoredata"
#define CONF_CAPTURE_TIMEOUT     "snow.capture.timeout"
#define CONF_CAPTURE_CAPSIZE     "snow.capture.capsize"
#define CONF_CAPTURE_WAIT_NTP    "snow.capture.wait_ntp"
#define CONF_CAPTURE_HASHMAC     "snow.capture.hash_mac"
#define CONF_CAPTURE_HASHSSID    "snow.capture.hash_ssid"

// Secret starting value for the hashing function
#define CONF_CAPTURE_HASHINIT    "snow.capture.hash_init"

#define CONF_TRANSMIT_ENDPOINT   "snow.transmit.endpoint"
#define CONF_TRANSMIT_ISBOUND    "snow.transmit.is_bound"

#define PROMISC_MODE_ON 1
#define WLAN_MODE_MONITOR 6
#define WLAN_MODE_MASTER 3

#define TV_TO_MICROSECS(ts) ((u_int64_t)ts.tv_sec * 1e6 + (u_int64_t)ts.tv_usec);

#define min(a,b) a < b ? a : b
#define max(a,b) a < b ? b : a

int is_running = 1;
pcap_t* pcap_handle;
int timeout = 60*1000;

typedef struct _snow_args {
  char* iface;
  zhash_t* access_points;

  void* socket;
  char* endpoint;
  bool is_bound;

  unsigned long long int seed;

  bool hash_mac;
  bool hash_ssid;
  bool ignoreap;
  bool ignoredata;
  bool wait_ntp;

  snow_perf_monitor* perf;
  uint64_t current_timestamp;

  char* status_file_name;

} snow_args;


//  ---------------------------------------------------------------------
//  CODE

static void s_help(void)
{
  printf("Usage: snow [-e PUB_ENDPOINT] -s [-i INTERFACE]\n"
           "  -s\tenables server-mode, binds the endpoint instead of connecting\n");
  exit(1);
}

static void s_handle_cmdline(snow_args* args, int argc, char** argv) {
  int flags = 0;

  while (1+flags < argc && argv[1+flags][0] == '-') {
    switch (argv[1+flags][1]) {
      case 'e':
        if (flags+2<argc) {
          flags++;
          args->endpoint = strndup(argv[1+flags],MAX_STRING_LEN);
        } else {
          errorLog("Error: Please specify a valid endpoint !");
        }
        break;
      case 'i':
        if (flags+2<argc) {
          flags++;
          args->iface = strndup(argv[1+flags],MAX_STRING_LEN);
        } else {
          errorLog("Error: Please specify a valid interface !");
        }
        break;
      case 's':
        args->is_bound = true;
        break;
      case 'h':
        s_help();
        break;
      default:
        errorLog("Error: Unsupported option '%s' !", argv[1+flags]);
        s_help();
        exit(1);
    }
    flags++;
  }

  if (argc < flags + 1)
    s_help();

}

static void s_dump_to_file(const char* filename, const char* data, int len) {
  FILE* file = fopen(filename, "w");
  if (file != NULL) {
    setvbuf(file, NULL, _IONBF, 0);
    fcntl(fileno(file), F_SETFL, fcntl(fileno(file), F_GETFL) | O_DSYNC | O_RSYNC);
    fprintf(file, "%s\n", data);
    fflush(file);
    fclose(file);
  }
}


static int s_hermes_send(void* socket, snow_pkt_info* data, bool hash_mac, bool hash_ssid, const char* status_file_name)
{
  time_t time;
  struct tm *tm;
  int rc;
  char formatted_date0[MAX_STRING_LEN];
  char formatted_date1[MAX_STRING_LEN];
  char my_timezone[7];
  char *prefix = NULL, *mac_hash = NULL, *str_bssid = NULL, *ssid_hash=NULL;
  char str_dbm[32];

  assert(socket);
  assert(data);

  tm = localtime((const time_t*)&data->ts_sec);
  assert(tm);

  // First gross string formatting
  strftime(formatted_date0, MAX_STRING_LEN, "%Y-%m-%dT%H:%M:%S.%%03u%%s", tm);

  // Add the timezone info if necessary and the milliseconds
  if (strftime(my_timezone, 7, "%z", tm) != 0) {
    my_timezone[6] = '\0';
    my_timezone[5] = my_timezone[4];
    my_timezone[4] = my_timezone[3];
    my_timezone[3] = ':';
    snprintf(formatted_date1,MAX_STRING_LEN, formatted_date0, data->ts_msec, my_timezone);
  } else {
    snprintf(formatted_date1,MAX_STRING_LEN, formatted_date0, data->ts_msec, "");
  }

  prefix = utils_hex_to_string(data->sig, 3);
  if (hash_mac) {
    mac_hash = utils_hex_to_string((uint8_t*)&data->hwhash, 8);
  } else {
    mac_hash = utils_hex_to_string((uint8_t*)&data->mac,6);
  }
  str_bssid = utils_hex_to_string((uint8_t*)&data->bssid,6);
  snprintf(str_dbm, 32, "%d", data->dbm);
  ssid_hash = utils_hex_to_string((uint8_t*)&data->ssidhash, 8);

  zmsg_t *msg = zmsg_new();
  zmsg_addstr (msg, "%s", formatted_date1);
  zmsg_addstr (msg, "%s", mac_hash);
  zmsg_addstr (msg, "%s", prefix);
  zmsg_addstr (msg, "%s", str_dbm);
  zmsg_addstr (msg, "%s", str_bssid);
  if (data->ssid != NULL) {
    if (hash_ssid) {
      zmsg_addstr (msg, "%s", ssid_hash);
    } else {
      zmsg_addstr (msg, "%s", data->ssid);
    }
  }
  rc = zmsg_send (&msg, socket);
  debugLog("[%s] hash %s, prefix %s, dbm %s, return code: %d, errno: %d", 
      formatted_date1, mac_hash, prefix, str_dbm, rc, errno);

  s_dump_to_file(status_file_name, formatted_date1, strlen(formatted_date1));

  free(prefix);
  free(mac_hash);
  free(str_bssid);
  free(ssid_hash);

  return STATUS_OK;
}

static void s_process_signal(int signo)
{
  is_running = 0;
  debugLog("Timeout waiting for packets, exiting.");
  pcap_breakloop(pcap_handle);
}

int main(int argc, char *argv[] )
{
  config_context* cfg_ctx;

  openlog("snow", LOG_CONS | LOG_PID, LOG_USER);

  snow_args* args = malloc(sizeof(snow_args));
  memset(args,0,sizeof(snow_args));

  cfg_ctx = config_new();

  args->seed = config_get_int64(cfg_ctx,CONF_CAPTURE_HASHINIT);

  if ((args->seed == 0) && (cfg_ctx->err != UCI_OK)) {
    errorLog("seed is currently not provisioned");
    config_destroy(cfg_ctx);
    free(args);
    exit(1);
  }

  config_get_str(cfg_ctx,CONF_CAPTURE_IFACE,&args->iface);
  int capsize = config_get_int(cfg_ctx,CONF_CAPTURE_CAPSIZE);
  timeout = config_get_int(cfg_ctx,CONF_CAPTURE_TIMEOUT);
  args->wait_ntp = config_get_bool(cfg_ctx, CONF_CAPTURE_WAIT_NTP);

  config_get_str(cfg_ctx,CONF_TRANSMIT_ENDPOINT,&args->endpoint);
  args->is_bound = config_get_bool(cfg_ctx, CONF_TRANSMIT_ISBOUND);


  args->hash_mac = config_get_bool(cfg_ctx, CONF_CAPTURE_HASHMAC);
  args->hash_ssid = config_get_bool(cfg_ctx, CONF_CAPTURE_HASHSSID);
  args->ignoreap = config_get_bool(cfg_ctx, CONF_CAPTURE_IGNOREAP);
  args->ignoredata = config_get_bool(cfg_ctx, CONF_CAPTURE_IGNOREDATA);

  config_get_str(cfg_ctx, "snow.meta.status_file_name", &args->status_file_name);
  if (args->status_file_name == NULL) {
    args->status_file_name = strdup("/tmp/snow_status");
  }

  s_handle_cmdline(args, argc, argv);
  if (args->iface == NULL) {
    errorLog("You have to specify a target interface through the command line !");
    config_destroy(cfg_ctx);
    free(args);
    exit(1);
  }


  signal(SIGINT, s_process_signal);
  signal(SIGTERM, s_process_signal);
  signal(SIGQUIT, s_process_signal);

  /*  Quit without NTP synchronization if needed */
  struct timeval tv;
  gettimeofday(&tv, NULL);
  if ((args->wait_ntp) && (tv.tv_sec < 32140800)) { // approx 1Y = anytime in 1970
    errorLog("NTP not synchronized, exiting.");
    config_destroy(cfg_ctx);
    free(args);
    exit(1);
  }

  zctx_t *zmq_ctx = zctx_new ();
  if (args->is_bound)
    args->socket = zeromq_create_socket(zmq_ctx, args->endpoint, ZMQ_PUSH, NULL, false, -1, -1);
  else
    args->socket = zeromq_create_socket(zmq_ctx, args->endpoint, ZMQ_PUSH, NULL, true, -1, -1);

  while (!zctx_interrupted && (is_running == 1)) {
    struct timespec tms;
    clock_gettime(CLOCK_REALTIME, &tms);
    snow_pkt_info info = {tms.tv_sec, tms.tv_nsec/1000, tms.tv_nsec, tms.tv_nsec,
      {(uint8_t)tms.tv_nsec & 0xff, 0xCD, 0xDE},
      {(uint8_t)tms.tv_nsec & 0xff, 0xCD, 0xDE, 0xAA, 0xBB, 0xCC},
      {(uint8_t)tms.tv_nsec & 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
      (int8_t)(tms.tv_sec & 0xff), "coucou"};
    s_hermes_send(args->socket, &info, args->hash_mac, args->hash_ssid, args->status_file_name);
    zclock_sleep(200);
  }

  config_destroy(cfg_ctx);
  zsocket_destroy(zmq_ctx,args->socket);
  zctx_destroy(&zmq_ctx);
  free(args);

  closelog();

  return 0;
}
