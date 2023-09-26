/* FreeBSD license */
static const char *__doc__ = "frop loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const char *default_filename = "fdrop_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf/fdrop";
const char *map_name    =  "fdrop_map_v1";

static inline struct xdp_program *load_bpf_and_pin_maps(struct config *cfg)
{
	/* In next assignment this will be moved into ../common/ */
	int prog_fd = -1;
	int err;
	struct bpf_object * obj;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = cfg->filename;
	xdp_opts.prog_name = cfg->progname;
	xdp_opts.opts = &opts;


	/* If flags indicate hardware offload, supply ifindex */
	/* if (cfg->xdp_flags & XDP_FLAGS_HW_MODE) */
	/* 	offload_ifindex = cfg->ifindex; */

	struct xdp_program *prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		fprintf(stderr, "ERR: loading program \n");
		exit(EXIT_FAIL_BPF);
	}
	obj = xdp_program__bpf_obj(prog);
	if (!obj) {
		fprintf(stderr, "ERR: loading obj from prog\n");
		exit(EXIT_FAIL_BPF);
	}

    char map_filename[PATH_MAX];
	int len = snprintf(map_filename, PATH_MAX, "%s/%s",
		       pin_basedir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		exit(EXIT_FAIL_BPF);
	}
	int pinned_map_fd = bpf_obj_get(map_filename);
	struct bpf_map    *map = bpf_object__find_map_by_name(obj, "fdrop_map_v1");
	bpf_map__reuse_fd(map, pinned_map_fd);

	err = xdp_program__attach(prog, cfg->ifindex, cfg->attach_mode, 0);
	if (err)
		exit(err);

	prog_fd = xdp_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: xdp_program__fd failed: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}
	return prog;
}

int main(int argc, char **argv)
{
    int err;
	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		/* TODO: Miss unpin of maps on unload */
		/* return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
	}

	struct xdp_program *program;


    char map_filename[PATH_MAX];
	int len = snprintf(map_filename, PATH_MAX, "%s/%s",
		       pin_basedir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		exit(EXIT_FAIL_BPF);
	}
    if (access(map_filename, F_OK ) == -1 ) {
        program = load_bpf_and_xdp_attach(&cfg);
        err = bpf_object__pin_maps(xdp_program__bpf_obj(program), pin_basedir);
        if (err) {
            exit(EXIT_FAIL_BPF);
        }
    } else {
        program = load_bpf_and_pin_maps(&cfg);
        if (!program)
            return EXIT_FAIL_BPF;
    }

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	return EXIT_OK;
}
