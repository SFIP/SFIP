#ifndef _UAPI_LINUX_SYSCALL_SEQUENCE_H
#define _UAPI_LINUX_SYSCALL_SEQUENCE_H

/* Valid flags for syscall_sequence syscall */
#define SYSCALL_SEQUENCE_GET_NUM_SYSCALLS (1UL << 0)
#define SYSCALL_SEQUENCE_SET_STATE_MACHINE (1UL << 1)
#define SYSCALL_SEQUENCE_SET_SYSCALL_RIPS (1UL << 2)
#define SYSCALL_SEQUENCE_LOG_VIOLATIONS (1UL << 3)


struct syscall_state_machine_user {
  char *machine;
};

struct syscall_location_info_user {
  int number_of_locations;
  size_t *syscall_locations;
};

#endif /* _UAPI_LINUX_SYSCALL_SEQUENCE_H */