/*
  Copyright 2019 Emilien GOBILLOT

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  13-Oct-2019   Emilien Gobillot Created This.
*/

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct key_t {
    char fname[64];
    char comm[64];
    u32 pid;
    u32 sysid;
};

struct value_t {
    u32 counter;
    u64 startTime; // used as a temporary value
    u64 cumLat; // cumulated latency spent in fname
};

// map is a key/value storage
BPF_HASH(map, struct key_t, struct value_t, 1024*32);

//line below will be replaced
ACTIVATEALLSYSCALL
ACTIVATELATENCY

static int do_enter(void * ctx, char * fname){
    struct key_t key = {};
    struct value_t valZero = {0,0,0};
    struct value_t *pValue;
    u64 stime = bpf_ktime_get_ns();

    // Build the key
    // Get function name => key.fname
    // Get process name => key.comm
    // Get the PID ==> key.pid (is a u32 so store only pid)
    strcpy(key.fname, fname);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    // better use lookup_or_init() rather than lookup()
    // Lookup the key in the map, and return a pointer to its value if it
    // exists, else initialize the key's value to the second argument.
    pValue = map.lookup_or_init(&key, &valZero);
    if(!pValue)
        return 0;

    pValue->counter++;
    pValue->startTime = stime; // usefull to let userspace clear old map entries

    // update the map
    map.update(&key, pValue);

    return 0;
}
#ifdef LATENCY
static int do_return(void * ctx, char * fname){
    struct key_t key = {};
    struct value_t *pValue;
    // set asap the endtime to improve precision
    u64 endTime = bpf_ktime_get_ns();

    //Build the key ...
    strcpy(key.fname, fname);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    // ... to lookup its value
    pValue=map.lookup(&key);
    if(!pValue || pValue->startTime == 0)
        return 0;

    pValue->cumLat += endTime - pValue->startTime;
    // now update the map
    map.update(&key, pValue);

    return 0;
}
#endif //LATENCY

#ifdef TRACEPOINT
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct key_t key = {};
    struct value_t valZero = {0,0,0};
    struct value_t *pValue;
    u64 stime = bpf_ktime_get_ns();

    // Build the key
    // Get id of the syscall => key.sysid
    // Get process name => key.comm
    // Get the PID ==> key.pid (is a u32 so store only pid)
    key.sysid = args->id;
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    // better use lookup_or_init() rather than lookup()
    // Lookup the key in the map, and return a pointer to its value if it
    // exists, else initialize the key's value to the second argument.
    pValue = map.lookup_or_init(&key, &valZero);
    //if(!pValue)
    //    return 0;
    pValue->counter++;
    pValue->startTime = stime;

    // update the map
    map.update(&key, pValue);

    return 0;
}
#ifdef LATENCY
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct key_t key = {};
    struct value_t *pValue;
    // set asap the endtime to improve precision
    u64 endTime = bpf_ktime_get_ns();

    //Build the key ...
    key.sysid = args->id;
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    // ... to lookup its value
    pValue=map.lookup(&key);
    if(!pValue)
        return 0;

    pValue->cumLat += endTime - pValue->startTime;
    // now update the map
    map.update(&key, pValue);

    return 0;
}
#endif //LATENCY
#endif //TRACEPOINT