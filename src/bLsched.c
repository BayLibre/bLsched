/*
 * Copyright (C) 2017 Baylibre.
 * Copyright (C) 2014-2017 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Some of this code comes from forkstat:
 * Written by Colin Ian King <colin.king@canonical.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#define __USE_GNU
#include <sched.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>

#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#include "hlist.h"

#define PID_MAX 32768

static int verbose = 0;

static int v_printf(const char * restrict format, ...)
{
 	int ret;

	if (verbose <= 0)
		return 0;

	va_list args;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
}

static int vv_printf(const char * restrict format, ...)
{
	int ret;

	if (verbose <= 1)
		return 0;

	va_list args;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
}

static inline bool is_pid_valid(pid_t pid)
{
	return kill(pid, 0) == 0;
}

static int read_proc_file(pid_t pid, const char *field, char *buffer, int size)
{
	char fname[PATH_MAX];
	int len;
	int fp;

	if (pid)
		snprintf(fname, sizeof(fname), "/proc/%d/%s", pid, field);
	else
		snprintf(fname, sizeof(fname), "/proc/%s", field);

	fp = open(fname, O_RDONLY);
	if (!fp) {
		fprintf(stderr, "open(%s) failed: %s\n", fname, strerror(errno));
		return -1;
	}

	len = read(fp, buffer, size);
	if (len <= 0) {
		fprintf(stderr, "read(%s) failed: %s\n", fname, strerror(errno));
		close(fp);
		return -1;
	}
	buffer[len-1] = 0; /* remove trailing '\n' */

	close(fp);
	return len;
}

static cpu_set_t big_cpuset;
static cpu_set_t default_cpuset;
static int cpu_count;
static int threshold = 90;
static int interval = 1000;
static bool new_pid_boost;

DECLARE_HASHTABLE(pid_hash, 9);

struct pid_info {
	struct hlist_node hentry;
	pid_t pid;
	char comm[16+1];
	int64_t load_avg;
	int64_t last_update_time;
	int threshold;
	int in_big_cpuset;
};

static struct pid_info *pid_find(pid_t pid)
{
	struct pid_info *info = NULL;

	hash_for_each_possible(pid_hash, info, hentry, pid) {
		if (info->pid == pid)
			break;
	}
	return info;
}

static struct pid_info *pid_add(pid_t pid)
{
	struct pid_info *info;
	char buffer[4096];
	int len;

	if (getpgid(pid) == 0) {
		vv_printf("PID %d kernel thread\n", pid);
		return NULL;
	}
	if (!is_pid_valid(pid)) {
		v_printf("PID %d not valid\n", pid);
		return NULL;
	}

	info = pid_find(pid);
	if (info) {
		return info;
	}

	info = calloc(1, sizeof(*info));
	if (!info) {
		fprintf(stderr, "calloc(%lu) failed\n", sizeof(*info));
		return NULL;
	}

	info->pid = pid;
	len = read_proc_file(pid, "comm", buffer, sizeof(buffer));
	if (len > 0) {
		strncpy(info->comm, buffer, sizeof(info->comm)-1);
	}
	info->threshold = (threshold * 1024) / 100;

	hash_add(pid_hash, &info->hentry, (uint32_t)pid);
	vv_printf("%5d: %s added\n", pid, info->comm);

	return info;
}

static void pid_remove(pid_t pid)
{
	struct pid_info *info;
	struct hlist_node *next;

	hash_for_each_possible_safe(pid_hash, info, next, hentry, pid) {
		if (info->pid == pid) {
			hash_del(&info->hentry);
			vv_printf("%5d %16s: removed\n", pid, info->comm);
			free(info);
		}
	}
}

static void pid_iterate(void (func)(struct pid_info *))
{
	struct pid_info *info;
	int bkt;

	hash_for_each(pid_hash, bkt, info, hentry) {
		if (func) {
			func(info);
		}
	}
}

static volatile int dump_info;

static void signal_handler(int sig)
{
	dump_info = 1;
}

static int netlink_connect(void)
{
	int sock;
	struct sockaddr_nl addr;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) < 0) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static int netlink_listen(const int sock)
{
	struct iovec iov[3];
	struct nlmsghdr nlmsghdr;
	struct cn_msg cn_msg;
	enum proc_cn_mcast_op op;

	memset(&nlmsghdr, 0, sizeof(nlmsghdr));
	nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlmsghdr.nlmsg_pid = getpid();
	nlmsghdr.nlmsg_type = NLMSG_DONE;
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = sizeof(nlmsghdr);

	memset(&cn_msg, 0, sizeof(cn_msg));
	cn_msg.id.idx = CN_IDX_PROC;
	cn_msg.id.val = CN_VAL_PROC;
	cn_msg.len = sizeof(enum proc_cn_mcast_op);
	iov[1].iov_base = &cn_msg;
	iov[1].iov_len = sizeof(cn_msg);

	op = PROC_CN_MCAST_LISTEN;
	iov[2].iov_base = &op;
	iov[2].iov_len = sizeof(op);

	return writev(sock, iov, 3);
}

static int netlink_recv(const int sock)
{
	struct nlmsghdr *nlmsghdr;
	ssize_t len;
	char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];

	if ((len = recv(sock, buf, sizeof(buf), 0)) == 0) {
		return 0;
	}
	if (len == -1) {
		switch (errno) {
		case EINTR:
			return 0;
		case ENOBUFS:
			break;
		default:
			fprintf(stderr,"recv() failed: %s\n", strerror(errno));
			return -1;
		}
	}

	for (nlmsghdr = (struct nlmsghdr *)buf;
		NLMSG_OK (nlmsghdr, len);
		nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

		struct cn_msg *cn_msg;
		struct proc_event *proc_ev;
		struct pid_info *info = NULL;

		if ((nlmsghdr->nlmsg_type == NLMSG_ERROR) ||
			(nlmsghdr->nlmsg_type == NLMSG_NOOP))
			continue;

		cn_msg = NLMSG_DATA(nlmsghdr);
		if ((cn_msg->id.idx != CN_IDX_PROC) ||
			(cn_msg->id.val != CN_VAL_PROC))
			continue;

		proc_ev = (struct proc_event *)cn_msg->data;

		switch (proc_ev->what) {
		case PROC_EVENT_FORK:
			vv_printf("PROC_EVENT_FORK: %d->%d\n", proc_ev->event_data.fork.parent_pid,proc_ev->event_data.fork.child_pid);
			info = pid_add(proc_ev->event_data.fork.child_pid);
			break;
		case PROC_EVENT_EXEC:
			vv_printf("PROC_EVENT_EXEC: %d\n", proc_ev->event_data.exec.process_pid);
			info  = pid_add(proc_ev->event_data.exec.process_pid);
			break;
		case PROC_EVENT_COMM:
			vv_printf("PROC_EVENT_COMM: %d %s\n", proc_ev->event_data.comm.process_pid, proc_ev->event_data.comm.comm);
			break;
		case PROC_EVENT_EXIT:
			vv_printf("PROC_EVENT_EXIT: %d\n", proc_ev->event_data.exit.process_pid);
			pid_remove(proc_ev->event_data.exit.process_pid);
			break;
		default:
			break;
		}

		if (info) {
			if (new_pid_boost) {
				info->in_big_cpuset = 1;
				sched_setaffinity(info->pid, sizeof(big_cpuset), &big_cpuset);
			}
		}
	}
	return 0;
}

static void show_big_tasks(struct pid_info *info)
{
	if (info->in_big_cpuset)
		printf("%5d %16s: %dms\n", info->pid, info->comm, info->in_big_cpuset * interval);
}

#define MAX_CPUS 8
static unsigned int cpu_load[MAX_CPUS];

static void show_cpu_loads(void)
{
	int cpu;

	printf("CPU 0-%d:", cpu_count);
	for (cpu = 0; cpu < cpu_count; cpu++) {
		printf(" %c-%u%%", CPU_ISSET(cpu, &big_cpuset) ? 'b' : 'L', cpu_load[cpu]);
	}
	printf("\n");
}

static unsigned int get_cpu_load(int cpu, uint64_t load, uint64_t idle)
{
	static uint64_t prev_load[MAX_CPUS];
	static uint64_t prev_idle[MAX_CPUS];
	static uint64_t curr_load[MAX_CPUS];
	static uint64_t curr_idle[MAX_CPUS];
	unsigned int cpu_load;

	curr_load[cpu] = load;
	curr_idle[cpu] = idle;

	cpu_load = ((curr_load[cpu] - prev_load[cpu]) * 100) / ((curr_load[cpu] + curr_idle[cpu]) - (prev_load[cpu] + prev_idle[cpu]));

	prev_load[cpu] = curr_load[cpu];
	prev_idle[cpu] = curr_idle[cpu];

	return cpu_load;
}

static void get_cpu_loads(void)
{
	char buffer[4096];
	int len;
	char *s;
	int ret;

	len = read_proc_file(0, "stat", buffer, sizeof(buffer));
	if (len < 0)
		return;

	s = buffer;
	do {
		s = strchr(s, '\n');
		if (s) {
			int cpu;
			uint64_t tmp0, tmp1, tmp2, tmp3;
			++s;
			ret = sscanf(s, "cpu%d %lu %lu %lu %lu", &cpu, &tmp0, &tmp1, &tmp2, &tmp3);
			if (ret == 5 && cpu < MAX_CPUS) {
				cpu_load[cpu] = get_cpu_load(cpu,  tmp0 + tmp1 + tmp2, tmp3);
			}
		}
	} while (s && *s);
	if (verbose > 0)
		show_cpu_loads();
}

static int big_total_capacity;

static void get_big_total_capacity(void)
{
	int cpu;

	big_total_capacity = 0;

	for (cpu = 0; cpu < cpu_count; cpu++) {
		if (CPU_ISSET(cpu, &big_cpuset)) {
			if (cpu_load[cpu] < (100 - threshold)) {
				big_total_capacity += 1023;
			}
		}
	}
}

static bool big_has_capacity(int load_avg)
{
	if (big_total_capacity >= load_avg) {
		big_total_capacity -= load_avg;
		return true;
	} else
		return false;
}

static int64_t get_last_update_time(const char *buffer)
{
	int64_t last_update_time = -1;
	const char *s = strstr(buffer, "se.avg.last_update_time");
	if (!s) {
		fprintf(stderr, "%s not found\n", "se.avg.last_update_time");
		return -1;
	}
	sscanf(s, "%*[^0-9]%ld", &last_update_time);
	return last_update_time;
}

static int64_t get_load_avg(const char *buffer)
{
	int64_t load_avg = -1;
	const char *s = strstr(buffer, "se.avg.load_avg");
	if (!s) {
		fprintf(stderr, "%s not found\n", "se.avg.load_avg");
		return -1;
	}
	sscanf(s, "%*[^0-9]%ld", &load_avg);
	return load_avg;
}

static void load_avg_monitor(struct pid_info *info)
{
	char buffer[4096];
	int len;

	if (!is_pid_valid(info->pid)) {
		v_printf("PID %d not valid\n", info->pid);
		pid_remove(info->pid);
		return;
	}

	len = read_proc_file(info->pid, "sched", buffer, sizeof(buffer));
	if (len > 0) {
		int64_t tmp = get_last_update_time(buffer);
		if (tmp != info->last_update_time) {
			info->last_update_time = tmp;
			info->load_avg = get_load_avg(buffer);
		} else {
			info->load_avg = 0;
		}

		vv_printf("%5d %16s: load_avg %ld, left %dms\n", info->pid, info->comm, info->load_avg, info->in_big_cpuset * interval);

		if (!CPU_COUNT(&big_cpuset))
			return;

		if (info->load_avg > info->threshold) {
			if (!info->in_big_cpuset) {
				if (big_has_capacity(info->load_avg)) {
					v_printf("%5d %16s: move to big\n", info->pid, info->comm);
					sched_setaffinity(info->pid, sizeof(big_cpuset), &big_cpuset);
					info->in_big_cpuset = 3;
				} else {
					v_printf("%5d %16s: big no capacity\n", info->pid, info->comm);
				}
			}
		} else {
			if (info->in_big_cpuset && !--info->in_big_cpuset) {
				v_printf("%5d %16s: remove from big\n", info->pid, info->comm);
				sched_setaffinity(info->pid, sizeof(default_cpuset), &default_cpuset);
			}
		}
	}
}

static int bLsched(const int sock)
{
	int ret;
	int timeout = interval;
	struct sigaction usr1_action = {.sa_handler = signal_handler};

	ret = sigaction(SIGUSR1, &usr1_action, 0);
	if (ret < 0) {
		fprintf(stderr, "sigaction() failed, %s\n", strerror(errno));
		return ret;
	}

	while (1) {
		struct pollfd fdset[1];
		struct timeval t1, t2;
		int elapsed;

		fdset[0].fd = sock;
		fdset[0].events = POLLIN | POLLPRI;

		gettimeofday(&t1, 0);

		ret = poll(fdset, 1, timeout);

		gettimeofday(&t2, 0);
		timersub(&t2, &t1, &t2);
		elapsed = t2.tv_sec * 1000 + t2.tv_usec/1000;

		if (ret < 0) {
			if (errno == EINTR) {
				if (dump_info) {
					dump_info = 0;
					show_cpu_loads();
					printf("PID's in big cpuset:\n");
					printf("--------------------\n");
					pid_iterate(show_big_tasks);
				}
			} else {
				fprintf(stderr, "poll() failed, %s\n", strerror(errno));
				break;
			}
		} else if (ret == 0) { /* Timeout */
			vv_printf("Timeout\n");
			get_cpu_loads();
			get_big_total_capacity();
			pid_iterate(load_avg_monitor);
			timeout = interval;
		} else {
			ret = netlink_recv(sock);
			if (ret < 0) {
				fprintf(stderr, "netlink_recv() failed, %s\n", strerror(ret));
				break;
			}
			timeout -= elapsed;
			if (timeout < 0)
				timeout = 0;
		}
	}
	return ret;
}

static void add_existing_pids(void)
{
	pid_t pid;

	for (pid = 2; pid <= PID_MAX; pid++) {
		if (is_pid_valid(pid)) {
			pid_add(pid);
		}
	}
}

static void usage(const char *prog)
{
	printf("Usage: %s [-vbtinah]\n", prog);
	puts("  -v increase verbosity\n"
	     "  -b add big cpu\n"
	     "  -t load threshold in % for moving to big cpu (default 90)\n"
	     "  -i interval in ms for monitoring load avg. (default 1000)\n"
	     "  -n new pid boost\n"
	     "  -a add existing pid's\n"
	     "  -l LITTLE cpuset default\n"
	     "  -h help\n");
	exit(1);
}

int main(int argc, char * const argv[])
{
	int sock;
	int ret;
	int cpu;

	hash_init(pid_hash);

	CPU_ZERO(&big_cpuset);
	CPU_ZERO(&default_cpuset);
	sched_getaffinity(0, sizeof(default_cpuset), &default_cpuset);
	cpu_count = CPU_COUNT(&default_cpuset);

	for (;;) {
		int c = getopt(argc, argv, "vb:t:i:nal");
		if (c == -1)
			break;
		switch (c) {
		case 'v':
			verbose += 1;
			break;
		case 'b':
			cpu = atoi(optarg);
			CPU_SET(cpu, &big_cpuset);
			break;
		case 't':
			threshold = atoi(optarg);
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'n':
			new_pid_boost = true;
			break;
		case 'a':
			add_existing_pids();
			break;
		case 'l':
			CPU_XOR(&default_cpuset, &big_cpuset, &default_cpuset); /* remove big CPU's from default set */
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			break;
		}
	}

	v_printf("big cpus %d/%d, threshold %d%%\n", CPU_COUNT(&big_cpuset), CPU_COUNT(&default_cpuset), threshold);

	ret = sock = netlink_connect();
	if (ret < 0) {
		fprintf(stderr, "netlink_connect() failed: %s\n", strerror(ret));
		goto fail;
	}

	ret = netlink_listen(sock);
	if (ret < 0) {
		fprintf(stderr, "netlink_listen() failed: %s\n", strerror(ret));
		goto fail;
	}

	return bLsched(sock);

fail:
	return ret;
}