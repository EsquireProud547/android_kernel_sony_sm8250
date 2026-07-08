/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __REKERNEL_H
#define __REKERNEL_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <uapi/linux/android/binder.h>
#include <linux/cgroup.h>
#include <linux/freezer.h>

#define REKERNEL_VERSION		"10.0-legacy"
#define MIN_USERAPP_UID			10000
#define MAX_SYSTEM_UID			2000
#define INTERFACETOKEN_BUFF_SIZE	140
#define PARCEL_OFFSET			16

enum report_type {
	BINDER,
	SIGNAL,
	NETWORK
};

enum binder_subtype {
	REPLY,
	TRANSACTION,
	OVERFLOW
};

static inline bool jobctl_frozen(struct task_struct *task)
{
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
}

static inline bool frozen_task_group(struct task_struct *task)
{
	return (jobctl_frozen(task) || cgroup_freezing(task));
}

/* Netlink server state */
extern bool rekernel_server_ready(void);
extern int start_rekernel_server(void);

/*
 * Binder hooks. Callers must pass the source/target task pointers and
 * pids extracted from struct binder_proc; rekernel.c does not know the
 * layout of struct binder_proc (which is private to binder.c).
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

/* Binder alloc hook - only call if rekernel_server_ready() */
extern void rekernel_binder_overflow(struct task_struct *proc_task);

/* Signal hook */
extern void rekernel_signal(int sig, struct task_struct *killer,
			    struct task_struct *dst);

#endif /* __REKERNEL_H */
