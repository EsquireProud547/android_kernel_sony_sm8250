/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Re:Kernel Netlink implementation for non-GKI/QGKI kernels.
 *
 * Supports both Generic Netlink (preferred, matches upstream LKM) and
 * legacy raw netlink (fallback). librekernel tries genl first and falls
 * back to legacy automatically.
 *
 * Design constraints:
 * - Never allocate Netlink skbs or create procfs nodes while holding
 *   binder spinlocks or RCU read-side locks.
 * - Binder events rely on callers (binder.c) to pass task/pid info;
 *   this file intentionally does not include struct binder_proc.
 * - Signal events use rekernel_is_frozen() to detect frozen state.
 * - Network monitoring is intentionally left out; enable it only after
 *   implementing the per-UID control interface librekernel expects.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <uapi/linux/android/binder.h>

#include "rekernel.h"

#define NETLINK_REKERNEL_MAX		26
#define NETLINK_REKERNEL_MIN		22
#define USER_PORT			100
#define PACKET_SIZE			256

/* Generic Netlink definitions matching upstream LKM */
#define REKERNEL_GENL_FAMILY_NAME	"rekernel"
#define REKERNEL_GENL_MCGRP_NAME	"events"

enum {
	REKERNEL_C_UNSPEC,
	REKERNEL_C_EVENT,
	REKERNEL_C_ADD_MONITOR_NET,
	REKERNEL_C_DEL_MONITOR_NET,
	REKERNEL_C_KILL_NET,
	REKERNEL_C_GET_VERSION,
	__REKERNEL_C_MAX,
};
#define REKERNEL_C_MAX			(__REKERNEL_C_MAX - 1)

enum {
	REKERNEL_A_UNSPEC,
	REKERNEL_A_MSG,
	REKERNEL_A_UID,
	REKERNEL_A_PID,
	__REKERNEL_A_MAX,
};
#define REKERNEL_A_MAX			(__REKERNEL_A_MAX - 1)

static int netlink_unit = NETLINK_REKERNEL_MIN;
static DEFINE_MUTEX(rekernel_init_mutex);

/* transport state */
static struct genl_family rekernel_genl_family;
static bool rekernel_genl_registered;
static struct sock *rekernel_netlink;
extern struct net init_net;

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry,
	*rekernel_version_entry;

static int rekernel_unit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", netlink_unit);
	return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_unit_show, NULL);
}

static int rekernel_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", REKERNEL_VERSION);
	return 0;
}

static int rekernel_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_version_show, NULL);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0))
static const struct proc_ops rekernel_unit_fops = {
	.proc_open	= rekernel_unit_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static const struct proc_ops rekernel_version_fops = {
	.proc_open	= rekernel_version_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations rekernel_unit_fops = {
	.open		= rekernel_unit_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations rekernel_version_fops = {
	.open		= rekernel_version_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif
#endif /* CONFIG_PROC_FS */

/* ---- Generic Netlink command handlers ---- */

static int rekernel_genl_get_version(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct sk_buff *reply;
	void *hdr;
	int ret;

	reply = genlmsg_new(nla_total_size(strlen(REKERNEL_VERSION) + 1),
			    GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
			  &rekernel_genl_family, 0,
			  REKERNEL_C_GET_VERSION);
	if (!hdr) {
		nlmsg_free(reply);
		return -ENOMEM;
	}

	if (nla_put_string(reply, REKERNEL_A_MSG, REKERNEL_VERSION)) {
		genlmsg_cancel(reply, hdr);
		nlmsg_free(reply);
		return -EMSGSIZE;
	}

	genlmsg_end(reply, hdr);
	ret = genlmsg_reply(reply, info);
	return ret;
}

static const struct nla_policy rekernel_genl_policy[REKERNEL_A_MAX + 1] = {
	[REKERNEL_A_MSG] = { .type = NLA_NUL_STRING,
			     .len = PACKET_SIZE - 1 },
	[REKERNEL_A_UID] = { .type = NLA_U32 },
	[REKERNEL_A_PID] = { .type = NLA_U32 },
};

static const struct genl_ops rekernel_genl_ops[] = {
	{
		.cmd	= REKERNEL_C_GET_VERSION,
		.doit	= rekernel_genl_get_version,
		.policy = rekernel_genl_policy,
	},
};

static struct genl_multicast_group rekernel_genl_mcgrps[] = {
	{ .name = REKERNEL_GENL_MCGRP_NAME, },
};

static struct genl_family rekernel_genl_family = {
	.name		= REKERNEL_GENL_FAMILY_NAME,
	.version	= 1,
	.maxattr	= REKERNEL_A_MAX,
	.netnsok	= true,
	.ops		= rekernel_genl_ops,
	.n_ops		= ARRAY_SIZE(rekernel_genl_ops),
	.mcgrps		= rekernel_genl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(rekernel_genl_mcgrps),
};

/* ---- Legacy raw netlink receive ---- */

static void netlink_rcv_msg(struct sk_buff *skbuffer)
{
	struct nlmsghdr *nlhdr;
	char *umsg;

	if (skbuffer->len < nlmsg_total_size(0))
		return;

	nlhdr = nlmsg_hdr(skbuffer);
	umsg = nlmsg_data(nlhdr);
	if (!umsg)
		return;

	if (!memcmp(umsg, "#proc_remove", min_t(size_t, 12, nlmsg_len(nlhdr)))) {
#ifdef CONFIG_PROC_FS
		if (rekernel_dir) {
			proc_remove(rekernel_dir);
			rekernel_dir = NULL;
			rekernel_unit_entry = NULL;
			rekernel_version_entry = NULL;
		}
#endif
	}
}

static struct netlink_kernel_cfg rekernel_cfg = {
	.input = netlink_rcv_msg,
};

bool rekernel_server_ready(void)
{
	return rekernel_genl_registered || rekernel_netlink != NULL;
}

/* ---- procfs helpers ---- */

#ifdef CONFIG_PROC_FS
static void rekernel_create_procfs(void)
{
	char buff[32];

	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir) {
		pr_err("Re:Kernel: failed to create /proc/rekernel\n");
		return;
	}

	rekernel_version_entry = proc_create("version", 0444, rekernel_dir,
					     &rekernel_version_fops);
	if (!rekernel_version_entry)
		pr_err("Re:Kernel: failed to create /proc/rekernel/version\n");

	/* legacy unit file only needed when raw netlink is active */
	if (rekernel_netlink) {
		snprintf(buff, sizeof(buff), "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir,
						  &rekernel_unit_fops);
		if (!rekernel_unit_entry)
			pr_err("Re:Kernel: failed to create /proc/rekernel/%s\n",
			       buff);
	}
}
#endif

/* ---- init ---- */

/*
 * Start the Netlink server during late init so that userspace can connect
 * immediately after boot, regardless of when the first frozen-target binder
 * event occurs.
 */
static int __init rekernel_late_init(void)
{
	int rc = start_rekernel_server();

	pr_info("Re:Kernel: late init %s\n", rc == 0 ? "OK" : "FAIL");
	return 0;
}
late_initcall(rekernel_late_init);

int start_rekernel_server(void)
{
	if (rekernel_server_ready())
		return 0;

	mutex_lock(&rekernel_init_mutex);

	/* Double-check after acquiring mutex */
	if (rekernel_server_ready())
		goto unlock;

	pr_info("Re:Kernel v%s starting...\n", REKERNEL_VERSION);

	/* 1) try Generic Netlink first (matches upstream LKM) */
	if (genl_register_family(&rekernel_genl_family) == 0) {
		rekernel_genl_registered = true;
		pr_info("Re:Kernel: Generic Netlink family registered\n");
	} else {
		pr_warn("Re:Kernel: failed to register genl family, falling back to legacy\n");

		/* 2) fall back to legacy raw netlink */
		for (netlink_unit = NETLINK_REKERNEL_MIN;
		     netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
			rekernel_netlink = netlink_kernel_create(&init_net,
								netlink_unit,
								&rekernel_cfg);
			if (rekernel_netlink)
				break;
		}

		if (!rekernel_netlink) {
			pr_err("Re:Kernel: failed to create legacy Netlink server!\n");
			netlink_unit = 0;
			goto unlock;
		}
		pr_info("Re:Kernel: legacy Netlink server on unit %d, port %d\n",
			netlink_unit, USER_PORT);
	}

#ifdef CONFIG_PROC_FS
	rekernel_create_procfs();
#endif

unlock:
	mutex_unlock(&rekernel_init_mutex);
	return rekernel_server_ready() ? 0 : -1;
}

/* ---- message sending ---- */

static int sendMessage(char *msg, uint16_t len)
{
	struct sk_buff *skbuffer;
	void *hdr;
	int ret;

	if (rekernel_genl_registered) {
		skbuffer = genlmsg_new(NLMSG_ALIGN(len + NLMSG_HDRLEN),
				       GFP_ATOMIC);
		if (!skbuffer) {
			pr_err_ratelimited("Re:Kernel: genlmsg alloc failure\n");
			return -1;
		}

		hdr = genlmsg_put(skbuffer, 0, 0, &rekernel_genl_family,
				  0, REKERNEL_C_EVENT);
		if (!hdr) {
			pr_err_ratelimited("Re:Kernel: genlmsg_put failure\n");
			nlmsg_free(skbuffer);
			return -1;
		}

		if (nla_put(skbuffer, REKERNEL_A_MSG, len, msg)) {
			pr_err_ratelimited("Re:Kernel: nla_put failure\n");
			nlmsg_free(skbuffer);
			return -1;
		}

		genlmsg_end(skbuffer, hdr);

		ret = genlmsg_multicast(&rekernel_genl_family, skbuffer, 0, 0,
					GFP_ATOMIC);
		/* -ESRCH means no listeners, not a real error */
		return (ret == -ESRCH) ? 0 : ret;
	}

	if (rekernel_netlink) {
		struct nlmsghdr *nlhdr;

		skbuffer = nlmsg_new(len, GFP_ATOMIC);
		if (!skbuffer) {
			pr_err_ratelimited("Re:Kernel: netlink alloc failure\n");
			return -1;
		}

		nlhdr = nlmsg_put(skbuffer, 0, 0, netlink_unit, len, 0);
		if (!nlhdr) {
			pr_err_ratelimited("Re:Kernel: nlmsg_put failure\n");
			nlmsg_free(skbuffer);
			return -1;
		}

		memcpy(nlmsg_data(nlhdr), msg, len);
		return netlink_unicast(rekernel_netlink, skbuffer, USER_PORT,
				       MSG_DONTWAIT);
	}

	return -1;
}

void rekernel_binder_reply(struct task_struct *target_tsk,
			   pid_t target_pid,
			   struct task_struct *proc_tsk,
			   pid_t proc_pid)
{
	char binder_kmsg[PACKET_SIZE];

	if (!target_tsk || !proc_tsk)
		return;
	if (target_pid == proc_pid)
		return;
	/* Match upstream Re:Kernel filter for reply events */
	if (task_uid(target_tsk).val > MAX_SYSTEM_UID)
		return;

	if (start_rekernel_server())
		return;

	/* Defensive: only report when the destination is actually frozen */
	if (!rekernel_is_frozen(target_tsk))
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
		 proc_pid, task_uid(proc_tsk).val,
		 target_pid, task_uid(target_tsk).val,
		 "SYNC_BINDER_REPLY", -1);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}

void rekernel_binder_transaction(struct task_struct *target_tsk,
				 pid_t target_pid,
				 struct task_struct *proc_tsk,
				 pid_t proc_pid,
				 struct binder_transaction_data *tr,
				 bool oneway)
{
	char binder_kmsg[PACKET_SIZE];

	if (!target_tsk || !proc_tsk)
		return;
	if (target_pid == proc_pid)
		return;
	if (task_uid(target_tsk).val <= MIN_USERAPP_UID)
		return;

	if (start_rekernel_server())
		return;

	/* Defensive: only report when the destination is actually frozen */
	if (!rekernel_is_frozen(target_tsk))
		return;

	if (oneway) {
		char buf_data[INTERFACETOKEN_BUFF_SIZE];
		char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
		size_t buf_data_size;
		int i = 0, j = 0;
		char *p;

		/* Upstream only extracts descriptor for these codes */
		if (tr->code < 29 || tr->code > 32)
			return;

		buf_data_size = min_t(size_t, tr->data_size,
				      INTERFACETOKEN_BUFF_SIZE);
		if (copy_from_user(buf_data, (char *)tr->data.ptr.buffer,
				   buf_data_size))
			return;

		p = buf_data + PARCEL_OFFSET;
		j = PARCEL_OFFSET + 1;
		while (i < INTERFACETOKEN_BUFF_SIZE - 1 &&
		       j < buf_data_size && *p != '\0') {
			buf[i++] = *p;
			j += 2;
			p += 2;
		}
		buf[i] = '\0';

		snprintf(binder_kmsg, sizeof(binder_kmsg),
			 "type=Binder,bindertype=transaction,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
			 proc_pid, task_uid(proc_tsk).val,
			 target_pid, task_uid(target_tsk).val,
			 buf, tr->code);
	} else {
		snprintf(binder_kmsg, sizeof(binder_kmsg),
			 "type=Binder,bindertype=transaction,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
			 proc_pid, task_uid(proc_tsk).val,
			 target_pid, task_uid(target_tsk).val,
			 "SYNC_BINDER", -1);
	}

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}

void rekernel_binder_overflow(struct task_struct *proc_task)
{
	char binder_kmsg[PACKET_SIZE];

	if (!proc_task)
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
		 task_tgid_nr(current), task_uid(current).val,
		 task_tgid_nr(proc_task), task_uid(proc_task).val,
		 "FREE_BUFFER_FULL", -1);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}

void rekernel_signal(int sig, struct task_struct *killer,
		     struct task_struct *dst)
{
	char binder_kmsg[PACKET_SIZE];

	if (!dst || !killer)
		return;

	if (start_rekernel_server())
		return;

	if (!rekernel_is_frozen(dst))
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;",
		 sig, task_tgid_nr(killer), task_uid(killer).val,
		 task_tgid_nr(dst), task_uid(dst).val);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}
