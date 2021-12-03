// SPDX-License-Identifier: GPL-2.0
/*
 * linux/kernel/syscall_sequence.c
 *
 * Copyright 2021  sfip authors <sfip@protonmail.com>
 */
#define pr_fmt(fmt) "syscall sequence: " fmt

#include <linux/refcount.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/coredump.h>
#include <linux/kmemleak.h>
#include <linux/nospec.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/syscall_sequence.h>

static void __get_syscall_sequence_filter_machine(struct syscall_state_machine *machine) {
	refcount_inc(&machine->refs);
}

static void __get_syscall_sequence_filter_locations(struct syscall_location_info *loc_info) {
	refcount_inc(&loc_info->refs);
}

static void __release_filter_machine(struct syscall_state_machine *machine) {
	// decrease ref count and check if it reached zero
	// if so, free all the memory
	if(refcount_dec_and_test(&machine->refs)) {
		kfree(machine->machine);
		kfree(machine);
	}
}

static void __release_filter_locations(struct syscall_location_info *loc_info) {
	// decrease ref count and check if it reached zero
	// if so, free all the memory
	if(refcount_dec_and_test(&loc_info->refs)) {
		kfree(loc_info->syscall_locations);
		kfree(loc_info);
	}
}

static void __syscall_sequence_filter_get(struct task_struct *tsk) {
	struct syscall_state_machine *machine = tsk->sys_state.machine;
	struct syscall_location_info *locs = tsk->sys_state.syscall_rips;
	if(machine)
		__get_syscall_sequence_filter_machine(machine);
	if(locs)
		__get_syscall_sequence_filter_locations(locs);
}

/* syscall_sequence_filter_get - increments the reference count of the filter on @tsk */
void syscall_sequence_filter_get(struct task_struct *tsk) {
	__syscall_sequence_filter_get(tsk);
}

static void __syscall_sequence_filter_release(struct task_struct *tsk) {
	struct syscall_state_machine *machine = tsk->sys_state.machine;
	struct syscall_location_info *locs = tsk->sys_state.syscall_rips;

	/* Detach task from its filters. */
	current->sys_state.machine = NULL;
	current->sys_state.syscall_rips = NULL;
	if(machine)
		__release_filter_machine(machine);
	if(locs)
		__release_filter_locations(locs);
}

void syscall_sequence_filter_release(struct task_struct *tsk) {
	__syscall_sequence_filter_release(tsk);
}

static char* get_state_machine(void) {
	return current->sys_state.machine->machine;
}

static int copy_state_machine(struct syscall_state_machine_user user_machine) {
	long machine_size = sizeof(char) * NR_syscalls * NR_syscalls;

	// Allocate memory for our machine
	current->sys_state.machine->machine = kmalloc(machine_size, GFP_KERNEL);
	if(unlikely(!get_state_machine())) {
		kfree(current->sys_state.machine);
		return -ENOMEM;
	}

	// copy the actual state machine to the kernel struct
	if(copy_from_user(get_state_machine(), user_machine.machine, machine_size)) {
		pr_alert("Error: Could not copy full state machine\n");
		kfree(current->sys_state.machine->machine);
		kfree(current->sys_state.machine);
		return -EINVAL;
	}

	return 0;
}

static int set_state_machine(struct syscall_state_machine_user __user *machine) {
	int ret;
	struct syscall_state_machine_user user_machine;
	if(unlikely(!machine))
		return -EINVAL;

	// allocate memory for our machine struct
	current->sys_state.machine = kmalloc(sizeof(struct syscall_state_machine), GFP_KERNEL);
	if(unlikely(!current->sys_state.machine))
		return -ENOMEM;

	// we copy all state machine values to the kernel
	if(copy_from_user(&user_machine, machine, sizeof(struct syscall_state_machine_user))) {
		pr_alert("Error: Could not copy state machine structure\n");
		kfree(current->sys_state.machine);
		return -EINVAL;
	}

	if((ret = copy_state_machine(user_machine))) {
		kfree(current->sys_state.machine);
		return ret;
	}

	current->sys_state.current_state = UNINITIALIZED;
	refcount_set(&(current->sys_state.machine->refs), 1);
	return 0;
}

static int set_syscall_rips(struct syscall_location_info_user __user *syscall_locs) {
	int ret, sys_nr;
	struct syscall_location_info_user *user_info;
	if(unlikely(!syscall_locs)) {
		return -EINVAL;
	}

	// allocate memory for our syscall_rips struct
	current->sys_state.syscall_rips = kmalloc(sizeof(struct syscall_location_info) * (NR_syscalls + 1), GFP_KERNEL); // plus 1 for our wildcard
	if(unlikely(!current->sys_state.syscall_rips)) {
		pr_alert("Error allocating memory\n");
		return -ENOMEM;
	}

	user_info = kmalloc(sizeof(struct syscall_location_info_user) * (NR_syscalls + 1), GFP_KERNEL); // plus 1 for our wildcard
	if(unlikely(!user_info)) {
		pr_alert("Error allocating memory\n");
		kfree(current->sys_state.syscall_rips);
		return -ENOMEM;
	}

	if(copy_from_user(user_info, syscall_locs, sizeof(struct syscall_location_info_user) * (NR_syscalls + 1))) { // plus 1 for our wildcard
		pr_alert("Error copying syscall locations\n");
		kfree(current->sys_state.syscall_rips);
		return -EINVAL;
	}

	for(sys_nr=0; sys_nr<=NR_syscalls; sys_nr++) {
		size_t *syscall_locations = user_info[sys_nr].syscall_locations;
		int num_syscall_locations = user_info[sys_nr].number_of_locations;
		current->sys_state.syscall_rips[sys_nr].number_of_locations = num_syscall_locations;

		current->sys_state.syscall_rips[sys_nr].syscall_locations = kmalloc(sizeof(size_t) * num_syscall_locations, GFP_KERNEL);
		if(unlikely(!current->sys_state.syscall_rips[sys_nr].syscall_locations)) {
			ret = -ENOMEM;
			goto error_alloc;
		}

		if(copy_from_user(current->sys_state.syscall_rips[sys_nr].syscall_locations, syscall_locations, sizeof(size_t) * num_syscall_locations)) {
			ret = -EINVAL;
			goto error_copy;
		}
	}

	kfree(user_info);
	refcount_set(&(current->sys_state.syscall_rips->refs), 1);
	return 0;

error_alloc:
	sys_nr--;
error_copy:
	for(; sys_nr>=0; sys_nr--) {
		kfree(current->sys_state.syscall_rips[sys_nr].syscall_locations);
	}
	kfree(current->sys_state.syscall_rips);
	kfree(user_info);
	return ret;
}

static int check_state(long sys_nr) {
	int *current_state = &current->sys_state.current_state;
	char *state_machine;
	int ret;

	// we currently do not support signal, so hacky way to circumvent the limitation is we always allow all syscalls while we are in one by setting the current state to UNIINITIALZED
	// proper way would be for the compiler to additional generate a per signal state machine, but this is future work
	if (current->sys_state.in_signal)
		*current_state = UNINITIALIZED;

	if (WARN_ON(current->sys_state.machine == NULL))
		return -EFAULT;
	state_machine = current->sys_state.machine->machine;

	// if the syscall is unitialized, we always allow the first transition but set the current_state to the currently executing syscall
	if(*current_state == UNINITIALIZED) {
		pr_debug("Current state is unitialized, setting it to %ld\n", sys_nr);
		*current_state = sys_nr;
		return 0;
	}

	pr_debug("Trying to transition from %d to %ld, state machine value is %d\n", *current_state, sys_nr, state_machine[*current_state * NR_syscalls + sys_nr]);
	if(state_machine[*current_state * NR_syscalls + sys_nr])
		return 0;
	ret = -EFAULT;

	pr_debug("Could not transition from %d to %ld, state machine value is %d\n", *current_state, sys_nr, state_machine[*current_state * NR_syscalls + sys_nr]);

	if(current->sys_state.flags & SYSCALL_SEQUENCE_LOG_VIOLATIONS)
		return 0;

	return ret;
}

static int check_rips(long sys_nr) {
	int index;
	struct syscall_location_info loc_info, wildcard; // wildcard is just needed for our PoC as there are some edge cases where we can't find the syscall number, but this can be solved
	// the ip points to the instruction following the syscall, so we substract the length of the syscall (0x2) to get the actual address
	size_t rip = current_pt_regs()->ip - 0x2;

	if (WARN_ON(current->sys_state.syscall_rips == NULL))
		return -EFAULT;
	loc_info = current->sys_state.syscall_rips[sys_nr];
	wildcard = current->sys_state.syscall_rips[NR_syscalls]; // our wildcards are in the last spot, where no actual syscall exists

	// by default, we always allow the exit syscalls
	// this is in line with the original seccomp mode where this syscall is always allowed
	if(sys_nr == __NR_exit_group || sys_nr == __NR_exit)
		goto found;

	// check if we have a syscall at the current RIP. If so, we return 0, otherwise -EFAULT
	for(index=0; index<loc_info.number_of_locations; index++) {
		if(rip == loc_info.syscall_locations[index])
			goto found;
	}

	pr_debug("Could not find a syscall instruction for syscall %lu at %px, checking wildcards\n", sys_nr, (void*)rip);

	for(index=0; index<wildcard.number_of_locations; index++) {
		if(rip == wildcard.syscall_locations[index])
			goto found;
	}
	pr_debug("Could not find a syscall instruction at %px that is marked as a wildcard\n", (void*)rip);
	if(!(current->sys_state.flags & SYSCALL_SEQUENCE_LOG_VIOLATIONS))
		return -EFAULT;

found:
	return 0;
}

static int __syscall_sequence(void) {
	int ret = 0;
	long sys_nr = syscall_get_nr(current, current_pt_regs());
	pr_debug("Executing syscall in __syscall_sequence: %ld\n", sys_nr);

	switch(current->sys_state.flags & ~SYSCALL_SEQUENCE_LOG_VIOLATIONS) {
		case SYSCALL_SEQUENCE_SET_STATE_MACHINE:
			ret = check_state(sys_nr);
			break;
		case SYSCALL_SEQUENCE_SET_SYSCALL_RIPS:
			ret = check_rips(sys_nr);
			break;
		case SYSCALL_SEQUENCE_SET_STATE_MACHINE | SYSCALL_SEQUENCE_SET_SYSCALL_RIPS:
			if((ret = check_state(sys_nr))) {
				break;
			}
			ret = check_rips(sys_nr);
			break;
		default:
			pr_alert("Syscall checking was requested but combination of flags is not supported\n");
			ret = -EPERM;
	}

	if(ret)
		goto error;

	// we passed our check and will continue executing the syscall, hence we update the current state of our machine
	current->sys_state.current_state = sys_nr;

	return ret;

error:
	do_group_exit(SIGSYS);
	return 0;
}

int syscall_sequence(void) {
	return __syscall_sequence();
}

static long do_syscall_sequence(struct syscall_state_machine_user __user *machine, struct syscall_location_info_user __user *syscall_locs, unsigned long flags) {
	int ret;
	if(unlikely(!(flags & SYSCALL_SEQUENCE_GET_NUM_SYSCALLS) && !(flags & SYSCALL_SEQUENCE_SET_STATE_MACHINE) && !(flags & SYSCALL_SEQUENCE_SET_SYSCALL_RIPS)))
		return -EINVAL;

	// check if only the number of syscalls provided by the kernel is requested
	if (flags & SYSCALL_SEQUENCE_GET_NUM_SYSCALLS) {
		return NR_syscalls;
	}

	/*
	* Installing a syscall sequence filter requires that the task has
	* CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	* This avoids scenarios where unprivileged tasks can affect the
	* behavior of privileged children.
	*/
	if(!task_no_new_privs(current) && !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN) && current->sys_state.flags)
		return -EACCES;

	if (flags & SYSCALL_SEQUENCE_SET_STATE_MACHINE) {
		ret = set_state_machine(machine);
		// if the RIPS flag is not set, we need to set it to NULL
		if(!(flags & SYSCALL_SEQUENCE_SET_SYSCALL_RIPS))
			current->sys_state.syscall_rips = NULL;
	}

	if (flags & SYSCALL_SEQUENCE_SET_SYSCALL_RIPS) {
		// TODO: if this fails and SET_STATE_MACHINE is also set, we need to free the memory for the state machine and initial state
		ret = set_syscall_rips(syscall_locs);
		// if the MACHINE flag is not set, we need to set it to NULL
		if(!(flags & SYSCALL_SEQUENCE_SET_STATE_MACHINE))
			current->sys_state.machine = NULL;
	}

	current->sys_state.flags = flags;
	current->sys_state.in_signal = 0;
	// setting this flag is required, otherwise we won't run before the syscall is actually executed
	set_task_syscall_work(current, SYSCALL_SEQUENCE);

	return ret;
}

SYSCALL_DEFINE3(syscall_sequence, struct syscall_state_machine_user __user *, machine, struct syscall_location_info_user __user *, syscall_locs, unsigned long, flags) {
	return do_syscall_sequence(machine, syscall_locs, flags);
}
