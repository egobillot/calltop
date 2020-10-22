# calltop - eBPF powered tracing tool
## This program provides a lightweight real-time view of **system calls** and traces **python/java/php/ruby function calls**.

It uses eBPF (linux only) to trace and report stats on system calls and functions/methods calls from python/java/php/ruby (other languages will be supported soon). By default it traces every system calls for every processes. It then prints the info in a *top-like* manner.

You can also trace python from your application by selecting its pid within the tool.

![alt text](https://github.com/egobillot/calltop/raw/master/demo/calltop_python_tracing.gif "python tracing")

### Features
 - display number, rate and latency of system calls or functions/methods calls.
 - top like output.
    - increase / decrease refresh rate
    - sort stats (pid, process name, total count, rate)
    - reset stats
 - filtering at the command line:
    - on the function name
    - on PIDs
    - on process names
 - filtering in the tool
   - filter dynamically on process name, command line, pid, system call, or function.
 - batch mode
 - trace userspace application functions.


### Feature in the roadmap
 - use uprobe to catch function calls
 - integration with graphing tools
 - details stats on a given function

### How to use this tool
The usage output brings most of the information
```
# sudo ./calltop.py -h
usage: calltop.py [-h] [-e SYSCALL] [-i INTERVAL] [-p PID] [-c COMM]
                  [--no-latency] [-b]

It prints realtime view of the Linux syscalls but also languages method calls.
It uses eBPF to do the tracing. So it is working only on Linux.

optional arguments:
  -h, --help            show this help message and exit
  -e SYSCALL, --syscall SYSCALL
                        -e open,read,write,sendto. Used to trace ONLY specific
                        syscalls. It uses kprobe. Without this option
                        TRACEPOINT are used to get all syscalls.
  -i INTERVAL, --interval INTERVAL
                        Set the interval in sec : -i 0.5
  -p PID, --pid PID     Filter on pids : --pid 10001,10002,10003
  -c COMM, --comm COMM  Filter on comm : --comm nginx,memcache,redis
  --no-latency          Do not display latency of the functions you trace. It
                        saves a few nanoseconds per call.
  -b, --batch           Print output in batch mode
```
Then when the tool is running you can :
- filter on process name : [f] key. Type the filter and press ENTER
   - The filter should look like this : 
     - `pid:1234`
     - `sys:read,comm:nginx`
     - `sys:bpf,comm:calltop`
     - `fn:print_body,comm:calltop,pid:1234`
- trace function/method call from python/java/php/ruby in your app : [t] key. Type pid of the process you want to trace and press ENTER to validate. It attaches USDT to this pid.
- reset the datas : 'z' key
- print the command line : 'c' key
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

To build and run this container use these command lines. You need to be root and add the privileged flag to run it.
```
$ docker build . -t calltop --file calltop.bcc@master.Dockerfile
$ sudo docker run -it -v /sys:/sys  -v /lib/modules:/lib/modules -v /usr/src/:/usr/src --privileged calltop
```

Have fun !

Developped by Emilien Gobillot
