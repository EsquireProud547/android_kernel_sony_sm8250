/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Re:Kernel legacy Netlink implementation for non-GKI/QGKI kernels.
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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <uapi/linux/android/binder.h>

#include "rekernel.h"

#define NETLINK_REKERNEL_MAX		26
#define NETLINK_REKERNEL_MIN		22
#define USER_PORT			100
#define PACKET_SIZE			256

static struct sock *rekernel_netlink;
extern struct net init_net;
static int netlink_unit = NETLINK_REKERNEL_MIN;
static DEFINE_MUTEX(rekernel_init_mutex);

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
	return rekernel_netlink != NULL;
}

int start_rekernel_server(void)
{
	char buff[32];

	if (rekernel_netlink)
		return 0;

	mutex_lock(&rekernel_init_mutex);

	/* Double-check after acquiring mutex */
	if (rekernel_netlink)
		goto unlock;

	pr_info("Re:Kernel v%s starting...\n", REKERNEL_VERSION);

	for (netlink_unit = NETLINK_REKERNEL_MIN;
	     netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
		rekernel_netlink = netlink_kernel_create(&init_net, netlink_unit,
							 &rekernel_cfg);
		if (rekernel_netlink)
			break;
	}

	if (!rekernel_netlink) {
		pr_err("Re:Kernel: failed to create Netlink server!\n");
		netlink_unit = 0;
		goto unlock;
	}

	pr_info("Re:Kernel: Netlink server on unit %d, port %d\n",
		netlink_unit, USER_PORT);

#ifdef CONFIG_PROC_FS
	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir) {
		pr_err("Re:Kernel: failed to create /proc/rekernel\n");
	} else {
		snprintf(buff, sizeof(buff), "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir,
						  &rekernel_unit_fops);
		if (!rekernel_unit_entry)
			pr_err("Re:Kernel: failed to create /proc/rekernel/%s\n",
			       buff);

		rekernel_version_entry = proc_create("version", 0444,
						     rekernel_dir,
						     &rekernel_version_fops);
		if (!rekernel_version_entry)
			pr_err("Re:Kernel: failed to create /proc/rekernel/version\n");
	}
#endif

unlock:
	mutex_unlock(&rekernel_init_mutex);
	return rekernel_netlink ? 0 : -1;
}

static int sendMessage(char *msg, uint16_t len)
{
	struct sk_buff *skbuffer;
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

	if (task_uid(killer).val == task_uid(dst).val)
		return;

	snprintf(binder_kmsg, sizeof(binder_kmsg),
		 "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;",
		 sig, task_tgid_nr(killer), task_uid(killer).val,
		 task_tgid_nr(dst), task_uid(dst).val);

	sendMessage(binder_kmsg, strlen(binder_kmsg));
}
