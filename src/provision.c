/**
 * =====================================================================================
 *
 *   @file provision.c
 *
 *
 *        Version:  1.0
 *        Created:  07/07/2014 09:42:49 PM
 *
 *
 *   @section
 *
 *      Automatic provisioning tool
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
#include "iwhelper.h"
#include "config.h"

#include <ctype.h>


//  ---------------------------------------------------------------------
//  CODE

int main(int argc, char *argv[] )
{
  int ret = -1;
  u_char hwaddr[6];
  char *mac_address = NULL;
  openlog("provision", LOG_CONS | LOG_PID, LOG_USER);
  if (argc > 1) {
    ret = iwcontrol_get_mac_address(argv[1], hwaddr);
  } else {
    ret = iwcontrol_get_mac_address("wlan0", hwaddr);
  }
  if (ret == 0) {
    mac_address = utils_raw_mac_to_string(hwaddr);
    if (mac_address != NULL) {
      printf("%s\n", mac_address);
      free(mac_address);
    }
  }

  closelog();
  return 0;
}
