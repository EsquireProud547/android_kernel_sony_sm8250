/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Re:Kernel inbound-network monitor.
 *
 * Mirrors the upstream LKM rekernel_netfilter.c: netfilter LOCAL_IN hooks
 * emit an event for uids that userspace opted in via ADD_MONITOR_NET.
 */

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/rtnetlink.h>

#include "rekernel.h"

#define PACKET_SIZE			256
#define REKERNEL_NET_UID_HASH_BITS	6

/* from rekernel.c */
extern int sendMessage(char *packet_buffer, uint16_t len);
extern bool rekernel_netlink_ready(void);

static void rekernel_netfilter_stop(void);
static DEFINE_HASHTABLE(rekernel_net_uid_map, REKERNEL_NET_UID_HASH_BITS);

struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_net_uid_mutex);

static bool net_uid_monitored(uid_t uid)
{
	struct uid_info *entry;

	hash_for_each_possible_rcu(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return true;
	}
	return false;
}

void net_uid_add(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	if (!net_uid_monitored(uid)) {
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(rekernel_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}
EXPORT_SYMBOL_GPL(net_uid_add);

void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	hash_for_each_possible(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}
EXPORT_SYMBOL_GPL(net_uid_del);

/* ---- socket kill helper (used by KILL_NET genl command) ---- */

static bool rekernel_sk_is_loopback(struct sock *sk)
{
	if (sk->sk_family == AF_INET)
		return ipv4_is_loopback(sk->sk_rcv_saddr) ||
		       ipv4_is_loopback(sk->sk_daddr);
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return ipv6_addr_loopback(&sk->sk_v6_rcv_saddr) ||
		       ipv6_addr_loopback(&sk->sk_v6_daddr);
#endif
	return false;
}

#define REKERNEL_MAX_KILL_SOCKS		1024

struct rekernel_sock_set {
	struct sock **socks;
	int count;
};

static int rekernel_collect_socket(const void *p, struct file *file,
				   unsigned int fd)
{
	struct rekernel_sock_set *set = (struct rekernel_sock_set *)p;
	struct socket *sock;
	struct sock *sk;

	(void)fd;

	if (set->count >= REKERNEL_MAX_KILL_SOCKS)
		return 1;

	if (!S_ISSOCK(file_inode(file)->i_mode))
		return 0;

	sock = file->private_data;
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;

	if ((sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
	    (sk->sk_protocol == IPPROTO_TCP || sk->sk_protocol == IPPROTO_UDP)) {
		if (sk->sk_protocol == IPPROTO_TCP) {
			if (rekernel_sk_is_loopback(sk))
				return 0;
			if (sk->sk_uid.val == SYSTEM_APP_UID)
				return 0;
		}
		sock_hold(sk);
		set->socks[set->count++] = sk;
	}
	return 0;
}

int rekernel_kill_net_connections(pid_t pid)
{
	struct task_struct *task;
	struct files_struct *files;
	struct pid *pid_struct;
	struct rekernel_sock_set set;
	int i, killed = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	set.count = 0;
	set.socks = kmalloc_array(REKERNEL_MAX_KILL_SOCKS,
				  sizeof(struct sock *), GFP_KERNEL);
	if (!set.socks) {
		put_task_struct(task);
		return -ENOMEM;
	}

	task_lock(task);
	files = task->files;
	if (files)
		iterate_fd(files, 0, rekernel_collect_socket, &set);
	task_unlock(task);

	put_task_struct(task);

	for (i = 0; i < set.count; i++) {
		struct sock *sk = set.socks[i];

		if (sk->sk_prot && sk->sk_prot->diag_destroy) {
			sk->sk_prot->diag_destroy(sk, ECONNABORTED);
			killed++;
		}
		sock_put(sk);
	}
	kfree(set.socks);

	return killed;
}
EXPORT_SYMBOL_GPL(rekernel_kill_net_connections);

/* ---- netfilter hooks ---- */

static inline uid_t line_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	return 0;
}

static unsigned int rekernel_pkg_ipv4_ipv6_in(void *priv,
					      struct sk_buff *socket_buffer,
					      const struct nf_hook_state *state)
{
	struct sock *sk;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	uid_t uid;
	struct net_device *dev = NULL;
	struct tcphdr *th;
	int data_len = 0;
	bool monitored;

	(void)priv;

	if (!socket_buffer || !socket_buffer->len || !state)
		return NF_ACCEPT;

	if (state->hook == NF_INET_LOCAL_IN)
		dev = state->in;
	if (!dev)
		return NF_ACCEPT;

	sk = skb_to_full_sk(socket_buffer);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = line_sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

	rcu_read_lock();
	monitored = net_uid_monitored(uid);
	rcu_read_unlock();
	if (!monitored)
		return NF_ACCEPT;

	if (ip_hdr(socket_buffer)->version == 4) {
		struct iphdr *iph4;
		unsigned int ip_hdr_len;

		if (!pskb_may_pull(socket_buffer, sizeof(struct iphdr)))
			return NF_ACCEPT;

		iph4 = ip_hdr(socket_buffer);
		if (iph4->protocol != IPPROTO_TCP)
			return NF_ACCEPT;

		ip_hdr_len = iph4->ihl << 2;
		if (!pskb_may_pull(socket_buffer,
				   ip_hdr_len + sizeof(struct tcphdr)))
			return NF_ACCEPT;

		iph4 = ip_hdr(socket_buffer);
		th = (struct tcphdr *)((unsigned char *)iph4 + ip_hdr_len);
		data_len = ntohs(iph4->tot_len) - ip_hdr_len - (th->doff << 2);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(socket_buffer)->version == 6) {
		struct ipv6hdr *iph6;

		if (!pskb_may_pull(socket_buffer, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;

		if (ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off,
				  NULL) != IPPROTO_TCP)
			return NF_ACCEPT;

		if (!pskb_may_pull(socket_buffer, thoff + sizeof(struct tcphdr)))
			return NF_ACCEPT;

		iph6 = ipv6_hdr(socket_buffer);
		th = (struct tcphdr *)(skb_network_header(socket_buffer) + thoff);
		data_len = ntohs(iph6->payload_len) -
			   (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
#endif
	} else {
		return NF_ACCEPT;
	}

	if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return NF_ACCEPT;

	if (rekernel_netlink_ready()) {
		char binder_kmsg[PACKET_SIZE];
		int len;

		if (ip_hdr(socket_buffer)->version == 4)
			len = scnprintf(binder_kmsg, sizeof(binder_kmsg),
					"type=Network,target=%d,proto=ipv4,data_len=%d;",
					uid, data_len);
#if IS_ENABLED(CONFIG_IPV6)
		else if (ip_hdr(socket_buffer)->version == 6)
			len = scnprintf(binder_kmsg, sizeof(binder_kmsg),
					"type=Network,target=%d,proto=ipv6,data_len=%d;",
					uid, data_len);
#endif
		else
			return NF_ACCEPT;

		sendMessage(binder_kmsg, len);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook		= rekernel_pkg_ipv4_ipv6_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook		= rekernel_pkg_ipv4_ipv6_in,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
};

int rekernel_netfilter_start(void)
{
	struct net *net;
	int rc = 0;

	hash_init(rekernel_net_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops,
					   ARRAY_SIZE(rekernel_nf_ops));
		if (rc)
			break;
	}
	rtnl_unlock();

	if (rc) {
		rekernel_netfilter_stop();
		return rc;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(rekernel_netfilter_start);

void rekernel_netfilter_stop(void)
{
	struct net *net;
	struct uid_info *entry;
	struct hlist_node *tmp;
	int bkt;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_nf_ops,
					ARRAY_SIZE(rekernel_nf_ops));
	}
	rtnl_unlock();

	synchronize_rcu();
	hash_for_each_safe(rekernel_net_uid_map, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
}
EXPORT_SYMBOL_GPL(rekernel_netfilter_stop);
