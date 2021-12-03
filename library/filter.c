#define GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <elf.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <link.h>
#include <string.h>
#include <libgen.h>

#if defined __has_include
#  if __has_include (<linux/syscall_sequence.h>)
#    include <linux/syscall_sequence.h>
#    include <syscall.h>
#  else
#    define FILTER_NOT_SUPPORTED
#    include "header.h"
#    pragma message ( "Couldn't find <linux/syscall_sequence.h>, using our manual header file" )
#  endif
#else
#  define FILTER_NOT_SUPPORTED
#  include "header.h"
#  pragma message ( "Couldn't find <linux/syscall_sequence.h>, using our manual header file" )
#endif

#include "cJSON.h"

static inline void freep(void *p) {
  free(*(void**) p);
}
#define _cleanup_free_ __attribute((cleanup(freep)))

#define debug(...) do { if(show_debug) printf(__VA_ARGS__); } while(0)

struct data {
  struct syscall_state_machine_user *machine;
  struct syscall_location_info_user *location_filters;
};

static uint64_t nospecrdtsc() {
  uint64_t a, d;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

static char *get_elf() {
  FILE* f = fopen("/proc/self/exe", "rb");
  fseek(f, 0, SEEK_END);
  size_t fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  char* elf = (char*)malloc(fsize);
  int read = fread(elf, 1, fsize, f);
  (void)read; // just to suppress the warning, don't want to edit every makefile with -Wno-unused-results
  fclose(f);

  return elf;
}

static cJSON* get_filter_data(char *elf, int show_debug) {
  Elf64_Ehdr* hdr = (Elf64_Ehdr*)elf;

  Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + hdr->e_shoff);
  Elf64_Shdr symtab = shdr[hdr->e_shstrndx];

  for(int i = 0; i < hdr->e_shnum; i++) {
    if((strcmp((char*)(elf + symtab.sh_offset + shdr[i].sh_name), ".note.state_filtering") == 0) && shdr[i].sh_type == SHT_NOTE) {
      Elf64_Nhdr note = *((Elf64_Nhdr*) (elf + shdr[i].sh_offset));
      debug("Filters @ %zx (len: %zd, note size: %d, note type: 0x%x)\n", shdr[i].sh_addr, shdr[i].sh_size, note.n_descsz, note.n_type);

      if(note.n_type == 0x403) {
        _cleanup_free_ char *filter = (char*) malloc(sizeof(char) * note.n_descsz);
        if(!filter) {
          debug("Memory allocation failed, terminating now\n");
          // exit(1);
          return NULL;
        }
        // section addr + size of the note section to skip meta data + sizeof(uint64_t) to skip the name and its padding for 4-byte alignment
        memcpy(filter, (void*)(elf + shdr[i].sh_offset + sizeof(Elf64_Nhdr) + sizeof(uint64_t)), sizeof(char) * note.n_descsz);
        return cJSON_Parse(filter);
      }
    }
  }

  return NULL;
}

static void generate_state_machine_filter(cJSON *callgraph, char *machine, long num_syscalls, int show_debug) {
  cJSON *state;
  cJSON_ArrayForEach(state, callgraph) {
    int sys_nr = atoi(state->string);
    if(sys_nr == -1)
      continue;
    cJSON *new_state;
    cJSON_ArrayForEach(new_state, state) {
      debug("state: %d, new state %d\n", sys_nr, new_state->valueint);
      machine[sys_nr * num_syscalls + new_state->valueint] = 1;
    }
  }
}

static int adjust_syscall_offset(char *elf, cJSON *offsets, struct syscall_location_info_user *locations, int show_debug, int num_syscalls) {
  Elf64_Ehdr* hdr = (Elf64_Ehdr*)elf;

  Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + hdr->e_shoff);
  Elf64_Shdr shstr = shdr[hdr->e_shstrndx];
  Elf64_Shdr *symtab = NULL;
  Elf64_Shdr *strtab = NULL;
  for(int index = 0; index < hdr->e_shnum; index++) {
    if(shdr[index].sh_type == SHT_SYMTAB)
      symtab = &shdr[index];
    if(shdr[index].sh_type == SHT_STRTAB)
      strtab = &shdr[index];
  }

  for (size_t j = 0; j < symtab->sh_size/symtab->sh_entsize; j++) {
    Elf64_Sym sym;
    size_t symbol_offset = symtab->sh_offset + j * sizeof(Elf64_Sym);

    memmove(&sym, elf + symbol_offset, sizeof(sym));
    // we are only interested in functions, skip the rest
    if(ELF64_ST_BIND(sym.st_info) == STT_FUNC)
      continue;
    char function_name[256];
    strncpy(function_name, elf + strtab->sh_offset + sym.st_name, sizeof(function_name));

    cJSON *function_json = cJSON_GetObjectItem(offsets, function_name);
    if(function_json) {
      cJSON *syscall;
      cJSON_ArrayForEach(syscall, function_json) {
        cJSON *location;
        int sys_nr = num_syscalls; // this is our wildcard position, so if json says -1 as syscall number we have a wildcard
        if (strcmp(syscall->string, "-1") != 0)
          sys_nr = atoi(syscall->string);
        int num_elements = cJSON_GetArraySize(syscall);
        struct syscall_location_info_user *_info = &locations[sys_nr];
        _info->syscall_locations = realloc(_info->syscall_locations, (_info->number_of_locations + num_elements) * sizeof(size_t));
        if(!_info->syscall_locations)
          continue;
        cJSON_ArrayForEach(location, syscall) {
          _info->syscall_locations[_info->number_of_locations] = sym.st_value + location->valueint;
          debug("%s, %d: %zx\n", function_name, sys_nr, _info->syscall_locations[_info->number_of_locations]);
          _info->number_of_locations++;
        }
      }
    }
  }

  return 0;
}


// TODO: stop leaking memory with the json string if an error occurs
static void __attribute__((section(".filter"), constructor)) setup_filter() {
  size_t start = nospecrdtsc();
  int flags = 0;
  int show_debug = !!getenv("DEBUG");

  if (getenv("SKIP"))
    return;

  debug("[+] Syscall enforcement starting ...\n");

  if(getenv("LOG_VIOLATIONS"))
    flags |= SYSCALL_SEQUENCE_LOG_VIOLATIONS;

  struct data filter = { .machine = NULL, .location_filters = NULL };

  #ifdef FILTER_NOT_SUPPORTED
  long num_syscalls = 448;
  #else
  long num_syscalls = syscall(SYS_syscall_sequence, NULL, NULL, SYSCALL_SEQUENCE_GET_NUM_SYSCALLS);
  #endif
  debug("Number of syscalls: %ld\n", num_syscalls);

  char *elf = get_elf();

  cJSON *json = get_filter_data(elf, show_debug);
  if(!json) {
    printf("Error, could not parse json from elf\n");
    return;
    // exit(EXIT_FAILURE);
  }
  if(show_debug) {
    char *json_print = cJSON_Print(json);
    printf("%s\n", json_print);
    cJSON_free(json_print);
  }

  cJSON *callgraph = cJSON_GetObjectItem(json, "callgraph");
  cJSON *sysloc = cJSON_GetObjectItem(json, "sysloc");

  if(callgraph && !getenv("OF_ONLY")) {
    filter.machine = malloc(sizeof(struct syscall_state_machine_user));
    if(!filter.machine) {
      printf("Error allocating memory for state machine\n");
      // exit(EXIT_FAILURE);
      return;
    }
    filter.machine->machine = malloc(sizeof(char) * num_syscalls * num_syscalls);
    if(!filter.machine->machine) {
      printf("Error allocating memory for actual state machine\n");
      free(filter.machine);
      return;
      // exit(EXIT_FAILURE);
    }
    memset(filter.machine->machine, 0, sizeof(char) * num_syscalls * num_syscalls);
    generate_state_machine_filter(callgraph, filter.machine->machine, num_syscalls, show_debug);
    flags |= SYSCALL_SEQUENCE_SET_STATE_MACHINE;
  }

  if(sysloc && !getenv("CG_ONLY")) {
    cJSON *offsets = cJSON_GetObjectItem(sysloc, "offsets");
    cJSON *wildcards = cJSON_GetObjectItem(sysloc, "wildcards");
    if (offsets) {
      // allocate +1 for our wildcards
      filter.location_filters = calloc(num_syscalls + 1, sizeof(struct syscall_location_info_user));
      if(!filter.location_filters) {
        printf("Error allocating memory, exiting\n");
        return;
      }

      adjust_syscall_offset(elf, offsets, filter.location_filters, show_debug, num_syscalls);

      if(wildcards) {
        adjust_syscall_offset(elf, wildcards, filter.location_filters, show_debug, num_syscalls);
      }
      flags |= SYSCALL_SEQUENCE_SET_SYSCALL_RIPS;

      if(show_debug) {
        for(int sys_nr = 0; sys_nr<=num_syscalls; sys_nr++) {
          struct syscall_location_info_user *_info = &filter.location_filters[sys_nr];
          int num = _info->number_of_locations;
          if(!num)
            continue;
          printf("Syscall %d\n", sys_nr);
          printf("\tNumber of locations: %d\n", num);
          for(int i=0; i<num; i++) {
            printf("\t\t%zx\n", _info->syscall_locations[i]);
          }
        }
      }
    }
  }

  cJSON_Delete(json);
  // if this is not set, then we run on a kernel that does not support our filtering
  long ret = syscall(SYS_syscall_sequence, filter.machine, filter.location_filters, flags);
  if(ret) {
    debug("[-] Installing filters failed: %ld\n", ret);
    // exit(EXIT_FAILURE);
    return;
  }

  debug("filtering active, took %zd cycles\n", nospecrdtsc() - start);
}
