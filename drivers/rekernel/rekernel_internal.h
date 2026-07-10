/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __REKERNEL_INTERNAL_H
#define __REKERNEL_INTERNAL_H

/*
 * Internal cross-file declarations for the built-in Re:Kernel port.
 * These are not part of the public ABI; rekernel.h is the public header.
 */

#ifdef CONFIG_REKERNEL_NETWORK
extern int rekernel_netfilter_start(void);
extern void rekernel_netfilter_stop(void);
#else
static inline int rekernel_netfilter_start(void) { return 0; }
static inline void rekernel_netfilter_stop(void) { }
#endif

extern int sendMessage(char *packet_buffer, uint16_t len);
extern bool rekernel_netlink_ready(void);

#endif /* __REKERNEL_INTERNAL_H */
