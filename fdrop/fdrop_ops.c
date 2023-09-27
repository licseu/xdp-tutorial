/* Free BSD license */
static const char *__doc__ = "frop operation program\n"
	" - operate drop_map via --dev name\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */
#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define FDROP_MAX_ENTRY 4096

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

    {{"ops",         required_argument,	NULL, '5' },
	 "the operation to the fdrop map, ie, add, del, get, dump", "<ops>", true},

	{{"src-ip",         required_argument,	NULL, '6' },
	 "the client src ip to block", "<saddr>", true},

	{{"dst-ip",         required_argument,	NULL, '7' },
	 "the server dst ip to block", "<daddr>", true},


	{{0, 0, NULL,  0 }}
};

#define FDROP_MAX_IP_STR_LEN 16
void u32_to_ip_str(uint32_t sip, char* str) {
	int ip = ntohl(sip);

    sprintf(str, "%u.%u.%u.%u",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF);
}

static inline int fdrop_map_add(int fdrop_map_fd, __u32 addr) {
	__u64 value = 0;
	int rtn;
	char ip_str[FDROP_MAX_IP_STR_LEN];

	u32_to_ip_str(addr, ip_str);

	rtn = bpf_map_lookup_elem(fdrop_map_fd, &addr, &value);
	if (rtn != 0)
		printf("add a new addr %s to fdrop map\n", ip_str);
	rtn = bpf_map_update_elem(fdrop_map_fd, &addr, &value, BPF_ANY);
	if (rtn != 0) {
		printf("failed to add addr %s to fdrop map\n", ip_str);
	} else {
		printf("success to add addr %s to fdrop map\n", ip_str);
	}
	return rtn;
}

static inline int fdrop_map_del(int fdrop_map_fd, __u32 addr) {
	int rtn;
	char ip_str[FDROP_MAX_IP_STR_LEN];
	
	u32_to_ip_str(addr, ip_str);

	rtn = bpf_map_delete_elem(fdrop_map_fd, &addr);
	if (rtn != 0) {
		if (errno == ENOENT) {
			printf("addr %s doesn't exist in fdrop map\n", ip_str);
			rtn = 0;
		} else {
			printf("failed to delete addr %s from fdrop map: %s\n", ip_str, strerror(errno));
		}
	} else {
		printf("success to delete addr %s from fdrop map\n", ip_str);
	}
	return rtn;
}

static inline int fdrop_map_get(int fdrop_map_fd, __u32 addr) {
	__u64 value = 0;
	int rtn;
	char ip_str[FDROP_MAX_IP_STR_LEN];
	
	u32_to_ip_str(addr, ip_str);
	rtn = bpf_map_lookup_elem(fdrop_map_fd, &addr, &value);
	if (rtn != 0) {
		printf("failed to get addr %s from fdrop map\n", ip_str);
		return rtn;
	}
	printf("the counter of addr %s is %llu \n", ip_str, value);
	return value;
}

static int fdrop_map_dump(int fdrop_map_fd) {
	__u64 value = 0;
	__u32 key = 0;
	__u32 next_key;
	while(bpf_map_get_next_key(fdrop_map_fd, &key, &next_key) == 0) {
		char ip_str[FDROP_MAX_IP_STR_LEN];
		bpf_map_lookup_elem(fdrop_map_fd, &next_key, &value);
		key = next_key;
		u32_to_ip_str(key, ip_str);
		printf("addr %-16s, counter: %llu\n", ip_str, value);
	}
	return 0;
}

const char *pin_basedir =  "/sys/fs/bpf/fdrop";

int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	int fdrop_map_fd;
	int err;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	fdrop_map_fd = open_bpf_map_file(pin_basedir, "fdrop_map_v1", &info);
	if (fdrop_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	printf("success to open bpf map under %s\n", pin_basedir);

	/* check map info, e.g. datarec is expected size */
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(__u64);
	map_expect.max_entries = FDROP_MAX_ENTRY;
	err = check_map_fd_info(&info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}


	switch(cfg.ops) {
		case ENUM_OPS_ADD:
			fdrop_map_add(fdrop_map_fd, cfg.saddr);
			break;
		case ENUM_OPS_DEL:
			fdrop_map_del(fdrop_map_fd, cfg.saddr);
			break;
		case ENUM_OPS_GET:
			fdrop_map_get(fdrop_map_fd, cfg.saddr);
			break;
		case ENUM_OPS_DUMP:
			fdrop_map_dump(fdrop_map_fd);
			break;
		default:
			printf("Unkown operation %d", cfg.ops);
			break;
	}
	return EXIT_OK;
}
