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
#include <sys/time.h>
#include <sys/resource.h>

//  ---------------------------------------------------------------------
//  DEFINITIONS

#define SNOW_IDENTITY "snow"
#define CONF_CAPTURE_IFACE       "snow.capture.iface"
#define CONF_CAPTURE_IGNOREAP    "snow.capture.ignoreap"
#define CONF_CAPTURE_IGNOREDATA  "snow.capture.ignoredata"
#define CONF_CAPTURE_TIMEOUT     "snow.capture.timeout"
#define CONF_CAPTURE_CAPSIZE     "snow.capture.capsize"
#define CONF_CAPTURE_PRIORITY    "snow.capture.priority"
#define CONF_CAPTURE_WAIT_NTP    "snow.capture.wait_ntp"
#define CONF_CAPTURE_HASHMAC     "snow.capture.hash_mac"
#define CONF_CAPTURE_HASHSSID    "snow.capture.hash_ssid"
#define CONF_CAPTURE_PROMISCUOUS "snow.capture.promiscuous"

// Secret starting value for the hashing function
#define CONF_CAPTURE_HASHINIT    "snow.capture.hash_init"

#define CONF_TRANSMIT_ENDPOINT   "snow.transmit.endpoint"
#define CONF_TRANSMIT_ISBOUND    "snow.transmit.is_bound"

#define WLAN_MODE_MONITOR 6
#define WLAN_MODE_MASTER 3

#define TV_TO_MICROSECS(ts) ((u_int64_t)ts.tv_sec * 1e6 + (u_int64_t)ts.tv_usec);

#define min(a,b) a < b ? a : b
#define max(a,b) a < b ? b : a

#define DEFAULT_PRIORITY 0

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
  bool ignoreoui;

  uint8_t oui[3];

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

// static void s_print_data(const uint8_t* p, int len)
// {
//   int i;
//   printf("-------------------------------------------\n");
//   for (i=0; i<len; i++){
//     printf("%02x ", p[i]);
//     if ( (i%32 == 0 && i!=0) || i==len-1 )
//       printf("\n");
//   }
// }

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


static int s_print_hashitem(const char *key, void *item, void *argument)
{
  uint32_t* count = (uint32_t*)item;
  debugLog("\t[%s] \t: \t%d", key, *count);
  return 0;
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

static void s_process_packet(uint8_t *arg, const struct pcap_pkthdr* pkthdr, const uint8_t * packet)
{
  snow_args* args = (snow_args*)arg;
  snow_pkt_info* info = processing_pcap_to_snow(args->ignoreap, args->ignoredata, args->ignoreoui,
                                                args->access_points, &args->current_timestamp,
                                                (uint8_t*)pkthdr, (uint8_t*)packet,
                                                args->perf, args->oui, args->seed);
  if (info != NULL) {
    s_hermes_send(args->socket, info, args->hash_mac, args->hash_ssid, args->status_file_name);
    processing_destroy_packet(info);
  }
  if ( zctx_interrupted ) {
    is_running = 0;
    pcap_breakloop(pcap_handle);
  }
}

static void s_process_signal(int signo)
{
  is_running = 0;
  debugLog("Timeout waiting for packets, exiting.");
  pcap_breakloop(pcap_handle);
}

int main(int argc, char *argv[] )
{
  int ret;
  uint8_t self_hwaddr[6];
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
  int priority = config_get_int(cfg_ctx,CONF_CAPTURE_PRIORITY);
  if (priority == STATUS_ERROR) {
    priority = DEFAULT_PRIORITY;
  }
  int promiscuous_mode = config_get_int(cfg_ctx,CONF_CAPTURE_PROMISCUOUS);
  if (promiscuous_mode == STATUS_ERROR) {
    promiscuous_mode = 1;  // enable promiscuous mode as default
  }
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

  args->perf = malloc(sizeof(snow_perf_monitor));
  memset(args->perf,0,sizeof(snow_perf_monitor));
  args->perf->t_total = utils_now_millis();
  args->access_points = zhash_new();

  s_handle_cmdline(args, argc, argv);
  if (args->iface == NULL) {
    errorLog("You have to specify a target interface through the command line !");
    config_destroy(cfg_ctx);
    free(args);
    exit(1);
  }

  int mode = iwcontrol_get_mode(args->iface);
  int channel = iwcontrol_get_channel(args->iface);
  int flags = iwcontrol_get_flags(args->iface);
  assert(mode != STATUS_ERROR);

  debugLog("Opening iface %s :: mode %d :: channel %d :: flags %08x",
      args->iface, mode, channel, flags);

  if (mode != WLAN_MODE_MONITOR)
    assert(iwhelper_enforce_mode(args->iface, WLAN_MODE_MONITOR) == STATUS_OK);

  assert(iwhelper_up_interface(args->iface) == STATUS_OK);

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

  if ((pcap_handle = pcap_open_live(args->iface,capsize,promiscuous_mode,timeout,NULL)) == NULL){
    errorLog("ERROR when trying to open pcap handle.");
    assert(false);
  }

  /* Open zeromq sockets */
  zctx_t *zmq_ctx = zctx_new ();
  if (args->is_bound)
    args->socket = zeromq_create_socket(zmq_ctx, args->endpoint, ZMQ_PUSH, NULL, false, -1, -1);
  else
    args->socket = zeromq_create_socket(zmq_ctx, args->endpoint, ZMQ_PUSH, NULL, true, -1, -1);

  /* Fetch the local OUI to ignore it */
  if (iwcontrol_get_mac_address(args->iface, self_hwaddr) == 0) {
    memcpy(&args->oui, self_hwaddr, 3);
    args->ignoreoui = true;
  }

  /* Lower its own priority */
  setpriority(PRIO_PROCESS, 0, priority);
  errorLog("priority %d, timeout %d", priority, timeout );

  /* Start listening loop */
  if ( pcap_loop(pcap_handle, -1, s_process_packet, (uint8_t *)args) == -1){
    errorLog("ERROR: %s", pcap_geterr(pcap_handle) );
    assert(false);
  }

  while (!zctx_interrupted && (is_running == 1)) {
    zclock_sleep(1000);
  }

  debugLog("===== ANALYTICS =====");

  debugLog("- packet counts -");
  debugLog("\tpkt_count\t:\t%d",args->perf->pkt_count);
  debugLog("\tivld_count\t:\t%d",args->perf->invalid_count);
  debugLog("\tmgt_count\t:\t%d",args->perf->mgt_count);
  debugLog("\tdata_count\t:\t%d",args->perf->data_count);
  debugLog("\tctrl_count\t:\t%d",args->perf->ctrl_count);

  debugLog("- access points -");
  debugLog("\tap_count\t:\t%d",args->perf->ap_count);
  zhash_foreach (args->access_points, s_print_hashitem, NULL);

  debugLog("- timings -");
  debugLog("\tt_processing\t:\t%lf", args->perf->t_processing);
  debugLog("\tper packet\t:\t%lf", args->perf->t_processing/args->perf->pkt_count);
  debugLog("\texec time\t:\t%lf", utils_now_millis() - args->perf->t_total);
  debugLog("===== eof =====");

  zhash_destroy(&args->access_points);
  pcap_close(pcap_handle);
  config_destroy(cfg_ctx);
  zsocket_destroy(zmq_ctx,args->socket);
  zctx_destroy(&zmq_ctx);
  free(args->perf);
  free(args);

  closelog();

  return 0;
}
