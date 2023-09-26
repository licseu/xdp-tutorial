/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include <getopt.h>
#include "common_defines.h"

enum ops_type {
  ENUM_OPS_UNKOWN = 0,
  ENUM_OPS_ADD = 1,
  ENUM_OPS_DEL = 2,
  ENUM_OPS_GET = 3,
  ENUM_OPS_DUMP = 4,
  ENUM_OPS_MAX = ENUM_OPS_DUMP,
};

struct option_wrapper {
  struct option option;
  char *help;
  char *metavar;
  bool required;
};

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *long_options,
                        struct config *cfg, const char *doc);

#endif /* __COMMON_PARAMS_H */
