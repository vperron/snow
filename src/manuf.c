/**
 * =====================================================================================
 *
 *   @file manuf.c
 *
 *   
 *        Version:  1.0
 *        Created:  12/16/2012 12:13:52 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Wireshark's manuf file manipulation
 *       
 *   @section LICENSE
 *
 *       
 *
 * =====================================================================================
 */

#include "main.h"
#include "manuf.h"
#include <stdio.h>

static char *s_hex_to_string (const unsigned char *hex, int len)
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

static int s_free_hashiten(const char *key, void *item, void *argument) 
{
	free(item);
	return 0;
}

zhash_t* manuf_new(const char* filename)
{
	u_int8_t hw0,hw1,hw2;
	char key[MAX_STRING_LEN];
	char manuf_buf[MAX_STRING_LEN];
	char buf[MAX_STRING_LEN];

	FILE* file = fopen(filename, "r");
	if(file == NULL) {
		errorLog("Opening of manuf file '%s' failed with: %s", filename, strerror(errno));
		return NULL;
	}
	
	int matches;
	zhash_t* manuf = zhash_new();
	while (fgets (buf, MAX_STRING_LEN, file)) {
		matches = sscanf(buf,"%02hhx:%02hhx:%02hhx %s", &hw0, &hw1, &hw2, manuf_buf);
		if(matches != 4)
			continue;
		snprintf(key,MAX_STRING_LEN,"%02x%02x%02x",hw0,hw1,hw2);
		zhash_insert(manuf,key,strdup(manuf_buf));
	}

	fclose (file);
	return manuf;
}

void manuf_destroy(zhash_t* manuf)
{
	assert(manuf);

	zhash_foreach(manuf,s_free_hashiten,NULL);
	zhash_destroy(&manuf);
}

char* manuf_frombin(zhash_t* manuf, const u_char* hwaddr)
{
	if(!manuf) /*  Silently exits. Manufacturer is NOT a critical thing. */
		return NULL;

	char* s_hwaddr = s_hex_to_string(hwaddr,3);
	char* name = (char*) zhash_lookup(manuf, s_hwaddr);
	free(s_hwaddr);
	return name;
}

char* manuf_fromstr(zhash_t* manuf, const char* s_hwaddr)
{
	u_char buf[3];

	if(!manuf) /*  Silently exits. Manufacturer is NOT a critical thing. */
		return NULL;

	int res = sscanf(s_hwaddr,"%02hhx%02hhx%02hhx", &buf[0], &buf[1], &buf[2]);
	if(res == 3) 
		return manuf_frombin(manuf, buf);

	return NULL;
}

void manuf_selftest()
{
	u_char hwaddr[6];
	zhash_t* manuf = manuf_new("manuf");
	assert(manuf);
	hwaddr[0] = 0x50;
	hwaddr[1] = 0xcc;
	hwaddr[2] = 0xf8;
	hwaddr[3] = 0xc6;
	hwaddr[4] = 0x30;
	hwaddr[5] = 0x2a;
	char* m = manuf_frombin(manuf, hwaddr);
	assert(streq(m,"SamsungE"));
	manuf_destroy(manuf);
}
