/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Re:Kernel implementation for non-GKI/QGKI kernels.
 *
 * This is a source-integrated port of the upstream LKM. It registers the
 * Generic Netlink family "rekernel" (the default upstream transport) and
 * mirrors the upstream event format as closely as possible.
 *
 * Design constraints:
 * - Never allocate Netlink skbs while holding binder spinlocks or RCU
 *   read-side locks.
 * - Binder events rely on callers (binder.c) to pass task/pid info; this
 *   file intentionally does not include struct binder_proc.
 * - Signal events use rekernel_is_frozen() to detect frozen state.
 * - Network monitoring is optional (CONFIG_REKERNEL_NETWORK).
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
#include <uapi/linux/android/binder.h>

#include "rekernel.h"
#include "rekernel_internal.h"

#define PACKET_SIZE			256

/* Stubs when network monitoring is disabled. */
#ifndef CONFIG_REKERNEL_NETWORK
void net_uid_add(uid_t uid) { }
void net_uid_del(uid_t uid) { }
int rekernel_kill_net_connections(pid_t pid) { return -EOPNOTSUPP; }
#endif

/* Generic Netlink definitions - must match upstream LKM ABI */
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

static bool rekernel_genl_registered;
static DEFINE_MUTEX(rekernel_init_mutex);

/* Forward declaration - the family struct is defined below the ops. */
static struct genl_family rekernel_genl_family;

/* ---- Generic Netlink command handlers ---- */

static int rekernel_genl_add_monitor_net(struct sk_buff *skb,
					 struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef CONFIG_REKERNEL_NETWORK
	net_uid_add(muid);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int rekernel_genl_del_monitor_net(struct sk_buff *skb,
					 struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef CONFIG_REKERNEL_NETWORK
	net_uid_del(muid);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static int rekernel_genl_kill_net(struct sk_buff *skb,
				  struct genl_info *info)
{
	pid_t pid;

	if (!info->attrs[REKERNEL_A_PID])
		return -EINVAL;

	pid = (pid_t)nla_get_u32(info->attrs[REKERNEL_A_PID]);
	return rekernel_kill_net_connections(pid);
}

static int rekernel_genl_get_version(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct sk_buff *reply;
	void *hdr;

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
	return genlmsg_reply(reply, info);
}

static const struct nla_policy rekernel_genl_policy[REKERNEL_A_MAX + 1] = {
	[REKERNEL_A_MSG] = { .type = NLA_NUL_STRING,
			     .len = PACKET_SIZE - 1 },
	[REKERNEL_A_UID] = { .type = NLA_U32 },
	[REKERNEL_A_PID] = { .type = NLA_U32 },
};

static const struct genl_ops rekernel_genl_ops[] = {
	{
		.cmd	= REKERNEL_C_ADD_MONITOR_NET,
		.doit	= rekernel_genl_add_monitor_net,
		.policy	= rekernel_genl_policy,
	},
	{
		.cmd	= REKERNEL_C_DEL_MONITOR_NET,
		.doit	= rekernel_genl_del_monitor_net,
		.policy	= rekernel_genl_policy,
	},
	{
		.cmd	= REKERNEL_C_KILL_NET,
		.doit	= rekernel_genl_kill_net,
		.policy	= rekernel_genl_policy,
	},
	{
		.cmd	= REKERNEL_C_GET_VERSION,
		.doit	= rekernel_genl_get_version,
		.policy	= rekernel_genl_policy,
	},
};

static const struct genl_multicast_group rekernel_genl_mcgrps[] = {
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

bool rekernel_netlink_ready(void)
{
	return rekernel_genl_registered;
}
EXPORT_SYMBOL_GPL(rekernel_netlink_ready);

/* ---- init / exit ---- */

static int __init rekernel_init(void)
{
	int rc;

	pr_info("Re:Kernel v%s starting...\n", REKERNEL_VERSION);

	rc = genl_register_family(&rekernel_genl_family);
	if (rc) {
		pr_err("Re:Kernel: failed to register genl family: %d\n", rc);
		return rc;
	}
	rekernel_genl_registered = true;

	pr_info("Re:Kernel: registered Generic Netlink family\n");

#ifdef CONFIG_REKERNEL_NETWORK
	rc = rekernel_netfilter_start();
	if (rc) {
		pr_err("Re:Kernel: failed to start netfilter: %d\n", rc);
		genl_unregister_family(&rekernel_genl_family);
		rekernel_genl_registered = false;
		return rc;
	}
#endif

	return 0;
}
late_initcall(rekernel_init);

int rekernel_netlink_start(void)
{
	if (rekernel_genl_registered)
		return 0;

	mutex_lock(&rekernel_init_mutex);
	if (!rekernel_genl_registered) {
		if (genl_register_family(&rekernel_genl_family) == 0)
			rekernel_genl_registered = true;
	}
	mutex_unlock(&rekernel_init_mutex);

	return rekernel_genl_registered ? 0 : -1;
}
EXPORT_SYMBOL_GPL(rekernel_netlink_start);

void rekernel_netlink_stop(void)
{
	if (rekernel_genl_registered) {
		rekernel_netfilter_stop();
		genl_unregister_family(&rekernel_genl_family);
		rekernel_genl_registered = false;
	}
}
EXPORT_SYMBOL_GPL(rekernel_netlink_stop);

/* ---- message sending ---- */

int sendMessage(char *packet_buffer, uint16_t len)
{
	struct sk_buff *socket_buffer;
	void *msg_head;
	int rc;

	if (!rekernel_genl_registered)
		return -1;

	socket_buffer = genlmsg_new(nla_total_size(len), GFP_ATOMIC);
	if (!socket_buffer) {
		pr_err_ratelimited("Re:Kernel: genlmsg alloc failure\n");
		return -1;
	}

	msg_head = genlmsg_put(socket_buffer, 0, 0, &rekernel_genl_family,
			       0, REKERNEL_C_EVENT);
	if (!msg_head) {
		pr_err_ratelimited("Re:Kernel: genlmsg_put failure\n");
		nlmsg_free(socket_buffer);
		return -1;
	}

	if (nla_put(socket_buffer, REKERNEL_A_MSG, len, packet_buffer)) {
		genlmsg_cancel(socket_buffer, msg_head);
		nlmsg_free(socket_buffer);
		return -1;
	}

	genlmsg_end(socket_buffer, msg_head);

	/*
	 * -ESRCH means no listeners; that is normal when no tombstone app
	 * has subscribed yet and should not be treated as an error.
	 */
	rc = genlmsg_multicast(&rekernel_genl_family, socket_buffer, 0, 0,
			       GFP_ATOMIC);
	return (rc == -ESRCH) ? 0 : rc;
}
EXPORT_SYMBOL_GPL(sendMessage);

/* ---- binder events ---- */

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
	if (task_uid(target_tsk).val > MAX_SYSTEM_UID)
		return;

	if (rekernel_netlink_start())
		return;

	if (!rekernel_is_frozen(target_tsk))
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
		 proc_pid, task_uid(proc_tsk).val,
		 target_pid, task_uid(target_tsk).val,
		 "SYNC_BINDER_REPLY", -1);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}
EXPORT_SYMBOL_GPL(rekernel_binder_reply);

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

	if (rekernel_netlink_start())
		return;

	if (!rekernel_is_frozen(target_tsk))
		return;

	if (oneway) {
		char buf_data[INTERFACETOKEN_BUFF_SIZE];
		char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
		size_t buf_data_size;
		int i = 0, j = 0;
		char *p;

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
EXPORT_SYMBOL_GPL(rekernel_binder_transaction);

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
EXPORT_SYMBOL_GPL(rekernel_binder_overflow);

/* ---- signal events ---- */

void rekernel_signal(int sig, struct task_struct *killer,
		     struct task_struct *dst)
{
	char binder_kmsg[PACKET_SIZE];

	if (!dst || !killer)
		return;

	if (rekernel_netlink_start())
		return;

	if (!rekernel_is_frozen(dst))
		return;

	if (sig != SIGKILL && sig != SIGTERM && sig != SIGABRT && sig != SIGQUIT)
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;",
		 sig, task_tgid_nr(killer), task_uid(killer).val,
		 task_tgid_nr(dst), task_uid(dst).val);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}
EXPORT_SYMBOL_GPL(rekernel_signal);
