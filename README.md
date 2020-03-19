# calltop
## This program provides a lightweight real-time view of system calls on Linux.

It uses eBPF to trace and report stats on system calls. So far it is limited to system call, but next release will come with function tracing from different language. By default it traces every system calls for every processes. It then prints the info in a *top-like* manner.

### Features
 - display call rate and latency of all the system calls sorted by PID,process name, or stats.
 - top like output.
    - increase / decrease refresh rate
    - sort stats (pid, process name, total count, rate)
    - reset stats
 - filtering at the command line: 
    - on the function name
    - on PIDs
    - on process names
 - dynamic filtering
 - batch mode

![alt text](https://github.com/egobillot/calltop/raw/master/calltop.gif "calltop")

### Feature in the roadmap
 - use USDT and uprobe to catch function calls
 - integration with graphing tools
 - details stats on a given function

### Installation
This tools is written in python and do not need external python packages.

#### iovisor/bcc packages
It requires the following packages:
``` bash
$ dpkg  -l | grep -e bpfcc
ii  bpfcc-tools           0.8.0-4       all          tools for BPF Compiler Collection (BCC)
ii  libbpfcc              0.8.0-4       amd64        shared library for BPF Compiler Collection (BCC)
ii  python-bpfcc          0.8.0-4       all          Python wrappers for BPF Compiler Collection (BCC)
ii  python3-bpfcc         0.8.0-4       all          Python 3 wrappers for BPF Compiler Collection (BCC)
```

You will need to install the above packages.It is already packaged in the major Linux distributions. The packages name may change according to the distribs. The minimum version is 0.8.0. For package versions between 0.5.0 and 0.8.0, it will work if you add manually this file : ![syscall.py](https://github.com/iovisor/bcc/blob/master/src/python/bcc/syscall.py)
For a more detailed installation documentation please refer to the ![official one](https://github.com/iovisor/bcc/blob/master/INSTALL.md). 

Developped by Emilien Gobillot
