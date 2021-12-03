/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SYSCALL_SEQUENCE_H
#define _LINUX_SYSCALL_SEQUENCE_H

#include <uapi/linux/syscall_sequence.h>

#define UNINITIALIZED -1

struct syscall_state_machine {
  refcount_t refs;
  char *machine;
};

struct syscall_location_info {
  refcount_t refs;
  int number_of_locations;
  size_t *syscall_locations;
};

struct syscall_state {
  int flags;
  int current_state;
  char in_signal;
  struct syscall_state_machine *machine;
	struct syscall_location_info *syscall_rips;
};

extern int syscall_sequence(void);
extern void syscall_sequence_filter_get(struct task_struct *tsk);
extern void syscall_sequence_filter_release(struct task_struct *tsk);

#endif /* _LINUX_SYSCALL_SEQUENCE_H */