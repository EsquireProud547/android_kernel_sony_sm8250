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

struct binder_proc;

/* Netlink server state */
extern bool rekernel_server_ready(void);
extern int start_rekernel_server(void);

/* Binder hooks - call after binder_proc_transaction() returns */
extern void rekernel_binder_reply(struct binder_proc *target_proc,
				  struct binder_proc *proc);
extern void rekernel_binder_transaction(struct binder_proc *target_proc,
					struct binder_proc *proc,
					struct binder_transaction_data *tr,
					int return_error);

/* Binder alloc hook - only call if rekernel_server_ready() */
extern void rekernel_binder_overflow(struct task_struct *proc_task);

/* Signal hook */
extern void rekernel_signal(int sig, struct task_struct *killer,
			    struct task_struct *dst);

#endif /* __REKERNEL_H */
