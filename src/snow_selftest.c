/**
 * =====================================================================================
 *
 *   @file snow_selftest.c
 *
 *
 *        Version:  1.0
 *        Created:  21/03/2013 04:57:14 PM
 *
 *
 *   @section DESCRIPTION
 *
 *       Selftest checks for snow. Modeled after self test code of
 *       zmqlib, from Pieter Hintjens
 *
 *   @section LICENSE
 *
 *
 *
 * =====================================================================================
 */

#include "main.h"
#include "processing.h"
#include "utils.h"


int main (int argc, char *argv [])
{
  bool verbose;
  if (argc == 2 && streq (argv [1], "-v"))
    verbose = true;
  else
    verbose = false;

  printf ("Running snow self tests...\n");

  processing_selftest(verbose);
  utils_selftest(verbose);

  printf ("Tests passed OK\n");
  return 0;
}
