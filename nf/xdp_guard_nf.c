// SPDX-License-Identifier: GPL-2.0
/*
 * The block list again, as a netfilter hook instead of XDP: drop IPv4
 * packets from a few listed addresses at PRE_ROUTING, and count what passes
 * and what is dropped.
 *
 * It runs later than XDP, once the stack has built an skb and checked the
 * IP header, so each packet costs more. In exchange it sees every interface
 * in the namespace at once and needs no driver support.
 *
 *   insmod xdp_guard_nf.ko blocked=192.0.2.1,198.51.100.7
 *   cat /proc/net/xdp_guard_nf
 */

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>

#define MAX_BLOCKED 16

static char *blocked[MAX_BLOCKED];
static int nr_blocked;
module_param_array(blocked, charp, &nr_blocked, 0444);
MODULE_PARM_DESC(blocked, "IPv4 source addresses to drop, comma separated");

static __be32 blocked_addrs[MAX_BLOCKED];
static atomic64_t passed = ATOMIC64_INIT(0);
static atomic64_t dropped = ATOMIC64_INIT(0);

static bool is_blocked(__be32 saddr)
{
	int i;

	for (i = 0; i < nr_blocked; i++)
		if (blocked_addrs[i] == saddr)
			return true;
	return false;
}

static unsigned int guard_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	/* ip_rcv() has already checked the header is there and sane. */
	if (is_blocked(ip_hdr(skb)->saddr)) {
		atomic64_inc(&dropped);
		return NF_DROP;
	}
	atomic64_inc(&passed);
	return NF_ACCEPT;
}

static const struct nf_hook_ops guard_ops = {
	.hook = guard_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static int guard_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "passed %lld\ndropped %lld\n",
		   atomic64_read(&passed), atomic64_read(&dropped));
	for (i = 0; i < nr_blocked; i++)
		seq_printf(m, "blocked %pI4\n", &blocked_addrs[i]);
	return 0;
}

static int __init guard_init(void)
{
	int i, err;

	for (i = 0; i < nr_blocked; i++) {
		if (!in4_pton(blocked[i], -1, (u8 *)&blocked_addrs[i], -1, NULL)) {
			pr_err("xdp_guard_nf: '%s' is not an IPv4 address\n",
			       blocked[i]);
			return -EINVAL;
		}
	}

	if (!proc_create_single("xdp_guard_nf", 0444, init_net.proc_net,
				guard_show))
		return -ENOMEM;

	err = nf_register_net_hook(&init_net, &guard_ops);
	if (err) {
		remove_proc_entry("xdp_guard_nf", init_net.proc_net);
		return err;
	}
	return 0;
}

static void __exit guard_exit(void)
{
	nf_unregister_net_hook(&init_net, &guard_ops);
	remove_proc_entry("xdp_guard_nf", init_net.proc_net);
}

module_init(guard_init);
module_exit(guard_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Drop IPv4 packets from listed sources at PRE_ROUTING");
