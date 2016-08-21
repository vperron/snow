/**
 * =====================================================================================
 *
 *   @file utils.c
 *
 *
 *        Version:  1.0
 *        Created:  03/21/2013 10:32:14 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Utility functions
 *
 *   @section LICENSE
 *
 *
 *
 * =====================================================================================
 */


#include "utils.h"
#include <sys/time.h>

double utils_now_millis() {
  struct timeval t;
  gettimeofday(&t, NULL);
  return (t.tv_sec * 1000.0) + (t.tv_usec / 1000.0);
}

char* utils_escape_ssid(const char* input, int len) {

  unsigned char buf[512]; // SSID in a 802.11 packet can't be longer than 32 chars, but we'll need escaping
  memset(buf,0,sizeof(buf));
  int i=0, real_len = 0;

  for(i=0;i<len;i++) {
    unsigned char c = input[i];
    if (utils_is_printable(c)) {
      buf[real_len] = c;
      real_len++;
    }
  }
  if(real_len > 0) {
    return strdup((const char*)buf);
  }
  return NULL;
}

bool utils_escape_json_char(char c)
{
  char to_escape[] = "\""; // only escape double quotes
  int i;
  for(i=0;i<sizeof(to_escape);i++) {
    if (c == to_escape[i]) {
      return true;
    }
  }
  return false;
}

bool utils_is_printable(unsigned char c)
{
  // List comes from python.string.printable property
  unsigned char printable[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&'()*+,-./:;<=>?@[]^_`{|}~ ";
  int i;
  for(i=0;i<sizeof(printable);i++) {
    if (c == 0)
      continue;
    if (c == printable[i]) {
      return true;
    }
  }
  return false;
}

char *utils_hex_to_string (const unsigned char *hex, int len)
{
  char hex_char [] = "0123456789abcdef";
  char *string = malloc (len * 2 + 1);
  memset(string,0,len*2+1);
  int byte_nbr;
  for (byte_nbr = 0; byte_nbr < len; byte_nbr++) {
    string [byte_nbr * 2 + 0] = hex_char [hex [byte_nbr] >> 4];
    string [byte_nbr * 2 + 1] = hex_char [hex [byte_nbr] & 15];
  }
  return string;
}


char *utils_raw_mac_to_string (const unsigned char *mac)
{
  int full_len = 6 * 2 + 5 + 1;
  char hex_char [] = "0123456789abcdef";
  char *string = malloc(full_len); // chars, colons, last 0
  memset(string, 0, full_len);
  int byte_nbr;
  for (byte_nbr = 0; byte_nbr < 6; byte_nbr++) {
    string [byte_nbr * 3 + 0] = hex_char [mac [byte_nbr] >> 4];
    string [byte_nbr * 3 + 1] = hex_char [mac [byte_nbr] & 15];
    if (byte_nbr != 5) {
      string [byte_nbr * 3 + 2] = ':';
    }
  }
  return string;
}


bool utils_is_big_endian(void) {
  union {
    uint32_t i;
    char c[4];
  } bint = {0x01020304};
  return bint.c[0] == 1;
}


#ifdef TESTING

#define setUp() \
	do { \
    buf = NULL; \
	} while(0)

#define tearDown() \
	do { \
    if (buf != NULL) { \
      free(buf); \
    } \
	} while(0)

/* Test */
void utils_selftest(int verbose)
{
  char *buf;

  {
    printf (" * utils_escape_ssid with a double quote : ");
    setUp();

    buf = utils_escape_ssid("WEIRD\"SSID", strlen("WEIRD\"SSID"));
    assert(buf);
    assert(strcmp(buf, "WEIRDSSID") == 0);

    tearDown();
    printf ("OK\n");
  }

  {
    printf (" * utils_escape_ssid ENDING with TWO slashes : ");
    setUp();

    buf = utils_escape_ssid("WEIRDSSID", strlen("WEIRDSSID"));
    assert(buf);
    assert(strcmp(buf, "WEIRDSSID") == 0);

    tearDown();
    printf ("OK\n");
  }

  {
    printf (" * utils_escape_ssid with a backslash : ");
    setUp();

    buf = utils_escape_ssid("WEIRD\\\\SSID", strlen("WEIRD\\\\SSID"));
    assert(buf);
    assert(strcmp(buf, "WEIRDSSID") == 0);

    tearDown();
    printf ("OK\n");
  }

  {
    printf (" * utils_escape_ssid with any char ");
    setUp();

    char string[256];
    int i;
    for(i=0; i<256; i++) {
      string[i] = i;
    }
    buf = utils_escape_ssid(string, 256);
    assert(buf);
    assert(strcmp(buf, " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~") == 0);

    tearDown();
    printf ("OK\n");
  }


}

#endif
