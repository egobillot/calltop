# calltop - eBPF powered tracing tool
## This program provides a lightweight real-time view of **system calls** and traces **python function calls**.

It uses eBPF (linux only) to trace and report stats on system calls and functions/methods calls from python (other languages will be supported soon). By default it traces every system calls for every processes. It then prints the info in a *top-like* manner.

You can also trace python from your application by selecting its pid within the tool.

![alt text](https://github.com/egobillot/calltop/raw/master/calltop.gif "calltop")

### Features
 - display number, rate and latency of system calls or python functions/methods calls.
 - top like output.
    - increase / decrease refresh rate
    - sort stats (pid, process name, total count, rate)
    - reset stats
 - filtering at the command line:
    - on the function name
    - on PIDs
    - on process names
 - filtering in the tool
   - filter dynamically on process name
 - batch mode
 - trace userspace application functions (so far limited to python)


### Feature in the roadmap
 - use uprobe to catch function calls
 - integration with graphing tools
 - details stats on a given function

### How to use this tool
The usage output brings most of the information
```
# sudo ./calltop.py -h
usage: calltop.py [-h] [-e SYSCALL] [-i INTERVAL] [-p PID] [-c COMM] [-d] [-l]
                  [-b]

display realtime view of the Linux syscalls. It uses eBPF to do the tracing

optional arguments:
  -h, --help            show this help message and exit
  -e SYSCALL, --syscall SYSCALL
                        the of syscalls to trace : -e read,write,sendto
  -i INTERVAL, --interval INTERVAL
                        set the interval in sec : -i 0.5
  -p PID, --pid PID     filter on pids : --pid 10001,10002,10003
  -c COMM, --comm COMM  filter on comm : --comm nginx,memcache,redis
  -d, --debug           print eBPF code
  -l, --latency         display latency of func
  -b, --batch           print output in batch mode

```
Then when the tool is running you can :
- filter on process name : [f] key. Type the filter and press ENTER
- trace function/method call from python on your app : [u] key. Type pid of the process you want to trace and press ENTER to validate. It attaches USDT to this pid.
- reset the datas : 'z' key
- sort processes with the arrow key (right and left key)
   - you can sort on pid, process name, rate and total call number.
   - you can also revert the sort (increasing or decreasing order) by pressing R keys.
- sort the stats within each each process. You can select to sort it on :
   - function name
   - latency
   - call/s
   - Total



### Installation
This tool is written in python and do not need external python packages.

#### iovisor/bcc packages
It requires the following packages:
``` bash
$ dpkg  -l | grep -e bpfcc
ii  bpfcc-tools           0.12.0-2       all          tools for BPF Compiler Collection (BCC)
ii  libbpfcc              0.12.0-2       amd64        shared library for BPF Compiler Collection (BCC)
ii  python-bpfcc          0.12.0-2       all          Python wrappers for BPF Compiler Collection (BCC)
ii  python3-bpfcc         0.12.0-2       all          Python 3 wrappers for BPF Compiler Collection (BCC)
```

You will need to install the above packages. It is already packaged in the major Linux distributions. The packages name may change according to the distribs. The minimum version is 0.12.0. If your distribution is not packaging v0.12 or later, you can follow the detailed installation guide of the [iovisor/bcc project](https://github.com/iovisor/bcc/blob/master/INSTALL.md). 

### Docker Images
You can find Dockerfiles. This will help you to test the tool. Because of the container, you will be limited to syscall tracing. Python tracing is not supported in container because we can't *see* the host processes).

Have fun !

Developped by Emilien Gobillot
