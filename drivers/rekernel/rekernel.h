/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __REKERNEL_H
#define __REKERNEL_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <uapi/linux/android/binder.h>
#include <linux/cgroup.h>
#include <linux/freezer.h>

/*
 * Re:Kernel version. Keep in sync with upstream LKM REKERNEL_MAJOR_VERSION.
 */
#define REKERNEL_VERSION		"10.0"

#define MIN_USERAPP_UID			(10000)
#define MAX_SYSTEM_UID			(2000)
#define SYSTEM_APP_UID			(1000)
#define INTERFACETOKEN_BUFF_SIZE	(140)
#define PARCEL_OFFSET			(16)
#define RESERVE_ORDER			(17)
#define WARN_AHEAD_SPACE		(1 << RESERVE_ORDER)

/*
 * Freeze predicate matching upstream LKM line_is_frozen() for 4.19.
 */
static inline bool rekernel_is_frozen(struct task_struct *task)
{
	if (cgroup_task_frozen(task) || cgroup_task_freeze(task))
		return true;
	if (!task->group_leader)
		return true;
	return frozen(task->group_leader) || freezing(task->group_leader);
}

/* Transport state */
extern bool rekernel_netlink_ready(void);
extern int rekernel_netlink_start(void);
extern void rekernel_netlink_stop(void);

/*
 * Network monitoring control. Defined unconditionally so callers can compile;
 * implementations are no-ops when CONFIG_REKERNEL_NETWORK is disabled.
 */
extern void net_uid_add(uid_t uid);
extern void net_uid_del(uid_t uid);
extern int rekernel_kill_net_connections(pid_t pid);

/*
 * Binder hooks. Callers must pass the source/target task pointers and pids
 * extracted from struct binder_proc; rekernel.c does not know the layout of
 * struct binder_proc (private to binder.c).
 */
extern void rekernel_binder_reply(struct task_struct *target_tsk,
				  pid_t target_pid,
				  struct task_struct *proc_tsk,
				  pid_t proc_pid);
extern void rekernel_binder_transaction(struct task_struct *target_tsk,
					pid_t target_pid,
					struct task_struct *proc_tsk,
					pid_t proc_pid,
					struct binder_transaction_data *tr,
					bool oneway);

/* Binder alloc hook - caller must ensure server is ready */
extern void rekernel_binder_overflow(struct task_struct *proc_task);

/* Signal hook */
extern void rekernel_signal(int sig, struct task_struct *killer,
			    struct task_struct *dst);

#endif /* __REKERNEL_H */
