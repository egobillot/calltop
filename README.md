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

![alt text](https://github.com/egobillot/calltop/raw/master/calltop.gif "calltop")

### Feature in the roadmap
 - use USDT and uprobe to catch function calls
 - batch mode
 - integration with graphing tools
 - details stats on a given function

Developped by Emilien Gobillot
