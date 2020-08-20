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

  17-Apr-2020   Emilien Gobillot Created This.
*/

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct key_t {
    char fname[64];
    char comm[64];
    u32 pid;
};

struct value_t {
    u32 counter;
    u64 startTime; // used as a temporary value
    u64 cumLat; // cumulated latency spent in fname
};

// map is a key/value storage
BPF_HASH(map, struct key_t, struct value_t, 1024);

//line below will be replaced
ACTIVATELATENCY

int usdt_gc_start(struct pt_regs *ctx) {
    struct key_t key = {"garbage_collector","",0};
    struct value_t valZero = {0,0,0};
    struct value_t *pValue;
    u64 stime = bpf_ktime_get_ns();

    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    pValue = map.lookup_or_try_init(&key, &valZero);
    if(!pValue) {
            return 0;
    }

    pValue->counter++;
    pValue->startTime = stime; // usefull to let userspace clear old map entries

    // update the map
    map.update(&key, pValue);

    return 0;
}


int usdt_gc_done(struct pt_regs *ctx) {
    struct key_t key = {"garbage_collector","",0};
    struct value_t defaultVal = {1,0,0};
    struct value_t *pValue;
    u64 endTime = bpf_ktime_get_ns();

    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();
    defaultVal.startTime = endTime; // in case we did not catch the enter --> cumLat = 0

    pValue = map.lookup_or_try_init(&key, &defaultVal);
    if (!pValue) {
        return 0;
    }

    pValue->cumLat += endTime - pValue->startTime;
    // update the map
    map.update(&key, pValue);

    return 0;
}

int usdt_enter(struct pt_regs *ctx) {
    uint64_t addr;
    struct key_t key = {};
    struct value_t valZero = {0,0,0};
    struct value_t *pValue;
u32 ret;
    u64 stime = bpf_ktime_get_ns();

    // Build the key
    // Get function name => key.fname
    // Get process name => key.comm
    // Get the PID ==> key.pid (is a u32 so store only pid)
    bpf_usdt_readarg(2, ctx, &addr);
    ret = bpf_probe_read_str(&key.fname, sizeof(key.fname), (void *)addr);
    if (ret < 0) {
        return 0;
    }
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();

    // Better use lookup_or_try_init() than lookup_or_init().
    // The problem is that lookup_or_try_init comes with v0.12
    // of the bcc tools.
    // Lookup the key in the map, and return a pointer to its value if it
    // exists, else initialize the key's value to the second argument.
    pValue = map.lookup_or_try_init(&key, &valZero);
    if(!pValue) {
            return 0;
    }

    pValue->counter++;
    pValue->startTime = stime; // usefull to let userspace clear old map entries

    // update the map
    map.update(&key, pValue);

    return 0;
}


#ifdef LATENCY
int usdt_return(struct pt_regs *ctx) {
    uint64_t addr;
    struct key_t key = {};
    struct value_t defaultVal = {1,0,0};
    struct value_t *pValue;
    u32 ret;
    u64 endTime = bpf_ktime_get_ns();
    // Build the key
    // Get function name => key.fname
    // Get process name => key.comm
    // Get the PID ==> key.pid (is a u32 so store only pid)
    bpf_usdt_readarg(2, ctx, &addr);
    ret = bpf_probe_read_str(&key.fname, sizeof(key.fname), (void *)addr);
    if (ret < 0) {
        return 0;
    }
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    key.pid = bpf_get_current_pid_tgid();
    // Better use lookup_or_try_init() than lookup_or_init().
    // The problem is that lookup_or_try_init comes with v0.12 of the bcc tools
    // Lookup the key in the map, and return a pointer to its value if it
    // exists, else initialize the key's value to the second argument.In that
    // case, it means this is the frst time we see this function.
    // So init it with defaultVal.
    defaultVal.startTime = endTime; // in case we did not catch the enter
    pValue = map.lookup_or_try_init(&key, &defaultVal);
    if (!pValue) {
        return 0;
    }

    pValue->cumLat += endTime - pValue->startTime;
    // update the map
    map.update(&key, pValue);

    return 0;
}
#endif //LATENCY