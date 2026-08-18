#!/usr/bin/env python3
# Copyright 2019 Emilien GOBILLOT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 13-Oct-2019   Emilien Gobillot Created This.


import argparse
import ctypes
import os
import sys
import threading
import traceback
from collections import deque
from time import monotonic_ns, sleep

from bcc import BPF, USDT, USDTException, utils
from bcc.syscall import syscall_name

# Global definition
DEBUG = 0
INACT_THRSLD = 1000000000
# number of samples kept to draw the call rate history of a function
RATE_HISTORY = 60

lang_prop = {
    'python': {
        'method_id': 2,
        'in': {'fn_in': 'function__entry', 'gc_in': 'gc__start'},
        'out': {'fn_out': 'function__return', 'gc_out': 'gc__done'}
    },
    'ruby': {
        'method_id': 2,
        'in': {'fn_in': 'method__entry', 'gc_in': 'gc__sweep__begin'},
        'out': {'fn_out': 'method__return', 'gc_out': 'gc__sweep__end'}
    },
    'php': {
        'method_id': 1,
        'in': {'fn_in': 'function__entry'},
        'out': {'fn_out': 'function__return'}
    },
    'java': {
        'method_id': 4,
        'in': {'fn_in': 'method__entry'},
        'out': {'fn_out': 'method__return'}
    }
}


class CtCollection:
    """This is a class used to define a collection of doc.
    """
    def __init__(self):
        self.doctionary = {}  # doctionary is a dictionary of docs.

    def collection_update(self, new_doc, default_intvl=1.0):
        """Update an existing document in the collection. If the
        document does not exist in the colelction, then add it.
            Args:
                new_doc (CtDoc) : A document to be updated
                default_intvl (float) : sampling interval, used to
                compute a call rate for a brand new stat.
        """
        doc = self.lookup_or_create(new_doc.pid, new_doc.comm)
        for ct_stat in new_doc.ct_stat_list:
            doc.update_doc_stats(ct_stat, default_intvl)

    def lookup_or_create(self, pid, comm):
        """Return the doc with the given pid and comm if it exists,
        else create and insert it.
            Args :
                pid (int) : pid of the process
                comm (str) : name of the process
            Returns :
                doc (CtDoc) : The doc new one or already existing
        """
        # lookup
        key = str(pid) + str(comm)
        doc = self.doctionary.get(key, None)
        # or create if look up failed
        if doc is None:
            doc = CtDoc(pid, comm)
            key = str(pid) + str(comm)
            self.doctionary[key] = doc

        return doc

    def drop(self):
        """Drop a collection and all its documents. It drops also
        all the stats in docs.
        """
        for doc in self.doctionary.values():
            del doc
        self.doctionary.clear()

    def write_output(self):
        """ Generate the output strings related to this collection.

            Returns:
                output (bytes): a build string containing the header,
                the pid, the process, the function, the latency, the
                call rate, the total count for every doc in this.
                collection.
        """
        # Build the header
        output = b'%6s' % b'Pid'
        output += b'%17s' % b'Process name'
        output += b'%32s' % b'Function'
        output += b'%16s' % b'latency(us)'
        output += b'%16s' % b'Call/s'
        output += b'%16s\n' % b'Total'
        # build the output string.
        for doc in self.doctionary.values():
            output += doc.write_output()

        return output

    def reset_info(self):
        for doc in self.doctionary.values():
            doc.total_func_cnt_per_intvl = 0
            doc.reset_info()


class CtDoc:
    """This class define the document of a collection. A doc is made
    up of a pid and a process name (comm). pid and comm identify a
    process (and not only pid). The document conatins also a list of
    stats of system calls or functions. A document is also made up
    of a 2 global counters that are the sum of each system call /
    function counters during the interval of from the begining.

        Attributes:
            pid (int) : The pid
            comm (str) : The process name
            total_func_cnt (int) : The sum of each counters in this doc
            total_func_time (int) : The sum of each latencies in this doc
            total_func_cnt_per_intvl (int) : The sum of each function call
            counters in this doc during the interval.
            ct_stat_list (:obj:`list` of :obj:`ct_stat_list`) : The
            list of stat for each functions/syscall
            counter_ref (:obj:`dict`) : function name is the key, the number of
            call the value
            cum_lat_ref (:obj:`dict`) : function name is the key, cumulated
            latency the value
            stat_time (:obj:`dict`) : It stores the informtion useful to
            compute with precision the call rate. This is a dictionary where
            function name is the key, and the value an array [timestamp, intvl]
    """
    def __init__(self, pid, comm):
        self.pid = pid
        self.comm = comm
        self.cmdline = self.pidToCmdline(pid, comm)
        self.total_func_cnt = 0  # the sum of each func call count in this doc
        self.total_func_time = 0  # the sum of each func call latency in this doc
        self.total_func_cnt_per_intvl = 0  # the sum of each func call rates
        self.ct_stat_list = []
        # we want to keep the reference counter and cumulated Latency.
        # when a stat for a function is reset, keep the reference in
        # counter_ref and cum_lat_ref.
        # This is a dict where k=funcname and v=counter (from ebpf)
        self.counter_ref = {}
        # This is a dict where k=funcname and v=cumulated Latency (from ebpf)
        self.cum_lat_ref = {}
        # This is a dict where k=funcname and v=[timestamp, intvl]
        # where timestamp is the time of last access, and intvl the interval
        # between the current insertion and the previous.
        self.stat_time = {}

    def __delitem__(self):
        del (self.ct_stat_list)

    def update_doc_stats(self, new_stat, default_intvl=1.0):
        """Update the stat of the doc with this new stat.
        If it does not yet exists, add it to the doc.

            Args:
                new_stat (ctStats) : the freshly read counters
                default_intvl (float) : sampling interval. It is used as
                the elapsed time for the very first sample of a stat,
                when no previous timestamp is available yet.
        """
        for func_call in self.ct_stat_list:
            if func_call.name == new_stat.name:
                func_call.update_stats(new_stat,
                                       self.counter_ref[func_call.name],
                                       self.cum_lat_ref[func_call.name])
                self.total_func_cnt += new_stat.cnt_per_intvl
                self.total_func_time += new_stat.cum_lat_per_intvl
                self.total_func_cnt_per_intvl += new_stat.cnt_per_intvl
                # set timestamp and compute new interval
                ts = monotonic_ns() * 1e-9
                intvl = ts - self.stat_time[new_stat.name][0]
                self.stat_time[new_stat.name] = [ts, intvl]
                if intvl <= 0:
                    intvl = default_intvl
                func_call.rps = func_call.cnt_per_intvl / intvl
                return

        # not already there so add it
        self.counter_ref[new_stat.name] = 0
        self.cum_lat_ref[new_stat.name] = 0
        self.ct_stat_list.append(new_stat)
        self.total_func_cnt += new_stat.cnt_per_intvl
        self.total_func_time += new_stat.cum_lat_per_intvl
        self.total_func_cnt_per_intvl += new_stat.cnt_per_intvl
        new_stat.rps = new_stat.cnt_per_intvl / max(default_intvl, 1e-9)
        # initial values are the timestamp and 0 for intvl
        # div by 0 will be manage at the display time
        self.stat_time[new_stat.name] = [monotonic_ns() * 1e-9, 0]

    def keep_previous_count(self, ct_stat):
        """The stats has been deleted. Preciseley counters and cum_lat has been
        clear/delitem from the eBPF map. In order to keep consistent infos, we
        need to save the previous values : the references.
            Args:
                ct_stat : (ctStats) The stat that has been reset
        """
        self.counter_ref[ct_stat.name] += ct_stat.total
        self.cum_lat_ref[ct_stat.name] += ct_stat.cum_lat

    def write_output(self):
        """ Generate the output strings related to this doc.

            Returns:
                output (bytes): a build string containing the pid, the
                process, the function, the latency, the call rate,
                the total count for each ctStat in this ctDoc.
        """
        output = b''
        for ct_stat in self.ct_stat_list:
            output += b'%6d' % self.pid
            output += b'%17s' % self.comm
            output += ct_stat.write_output()
        return output

    def reset_info(self):
        for ct_stat in self.ct_stat_list:
            ct_stat.reset_info()

    def pidToCmdline(self, pid, comm):
        try:
            with open('/proc/%s/cmdline' % pid, 'r') as f:
                cmd = f.read().replace('\00', ' ')
                return str.encode(cmd)
        except IOError:
            return comm


class ctStats:
    """ctStats is used to get latency or call counters for a given
    function call.

    Attributes:
        name (str): Name of the function traced
        cnt_per_intvl (int): nb of call to function during the interval
        cum_lat_per_intvl (int): cumulated time spent in func during the intvl
        total (int): nb of call to function from the begining
        cum_lat (int): cumulated time (ns) spent in the func from the begining
        avg_lat (float): cumulated time (ns) spent in the func during the intvl
        nb_sample (int): nb of sample
        rps (float): calls per second during the last interval
        rate_history (:obj:`deque` of :obj:`float`): the last RATE_HISTORY
        call rates. It is what the sparkline of the ui is drawn from.
    """
    def __init__(self, name, cum_count, cum_lat):
        self.name = name
        self.cnt_per_intvl = cum_count  # count during the interval
        self.cum_lat_per_intvl = cum_lat  # sum of lat during interval
        self.total = cum_count  # total over time (keep increasing)
        self.cum_lat = cum_lat
        self.avg_lat = 0 if cum_count == 0 else float(cum_lat / cum_count)
        self.nb_sample = 1  # first sample
        self.rps = 0.0  # call rate of the last interval
        self.rate_history = deque([], maxlen=RATE_HISTORY)

    def update_stats(self, stat, counter_ref, cum_lat_ref):
        """Update the information of a ctStats. It mainly manage the case
        where the counter and cum_lat from the eBPF has been cleared. In this
        we keep the previous value (called a reference), in order not to loose
        the real value. Why don't we cleared the map from eBPF after each
        access ? Because map.clear or map.__delitem(key) are not atomic. And
        if maps are access at a high frequency and we clear it, the
        probability to face race condition is high. So the workaround it to
        clear the data only when it has not been updated for a few seconds. In
        that case, it is more likely (but no stricly guaranted) data will
        remain in a valid state. It makes the code less _natural_ but results
        are accurate.

        Args:
            stat (ctStats): Update the current stats with value from
            stat args.
            counter_ref (int): Use this value as the previous reference
            for counter before clear
            cum_lat_ref (int):  Use this value as the previous reference
            for cumulated latency before clear
        """
        # BUG : when this stats has been zeroed and
        # if self.total == stat.total ( old value is == new value)
        # then nothing will be added. And in that specific case it should
        # should not happen so often, but need to fixe it.
        if int(self.total) == int(stat.total):
            return  # counter have not been updated

        # count per interval = new count - old  count
        self.cnt_per_intvl = stat.total - self.total + counter_ref

        # time spent per interval
        self.cum_lat_per_intvl = stat.cum_lat - self.cum_lat + cum_lat_ref

        # update the Total with the one give by eBPF counter
        self.total = counter_ref + stat.total

        # update the cumulated Latency
        self.cum_lat = cum_lat_ref + stat.cum_lat

        # compute the avg latency
        if self.cnt_per_intvl == 0:
            self.avg_lat = 0
        else:
            self.avg_lat = float(self.cum_lat_per_intvl / self.cnt_per_intvl)

        # increment sample count
        self.nb_sample += 1

    def write_output(self):
        """ Generate the output strings related to this ctStats.

            Returns:
                output (bytes): a build string containing the function,
                the latency, call rate, the total count.
        """
        output = b'%32s' % self.name
        output += b'%16d' % (self.avg_lat / 1000)
        output += b'%16d' % self.cnt_per_intvl
        output += b'%16d\n' % self.total
        return output

    def reset_info(self):
        """Called right before each sampling. It archives the call rate
        of the interval that just ended, then zeroes the per interval
        counters. A function that is not called anymore keeps being
        sampled, with a rate of 0.
        """
        self.rate_history.append(self.rps)
        self.rps = 0.0
        self.cnt_per_intvl = 0


class Display:
    """Base class of the output. It only holds what is common to every
    kind of output : the collection to print and the sampling interval.
    """
    def __init__(self, ctCollection):
        self.collection = ctCollection
        self.die = False
        self.refresh_intvl = 1

    def print_header(self, string):
        """Prints string at the first line.

            Args:
                string (str): the string to print.
        """
        pass

    def print_body(self):
        """Prints the collected stats."""
        pass

    def set_refresh_intvl(self, rate):
        """Set refresh_intvl.

            Args:
                rate(int) : the rate.
        """
        self.refresh_intvl = rate


class BatchDisplay(Display):
    """Plain text output, one block of lines per interval. Meant to be
    piped into a file or another program.
    """

    def print_body(self):
        print(self.collection.write_output().decode())

    def print_header(self, string):
        print(string)


class TimeSpec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]


def debug(filename, s,):
    with open(filename, 'a') as f:
        f.write('%s\n' % s)


def create_and_load_bpf(syscalls='all', lat=True):
    """ This function read the ebpf.c file and save it into a string.
    A part of the ebp.c is generated by this function.
    To trace specific syscall list we append a syscall_enter_'syscall_name'
    and syscall_return_'syscall_name' function for every syscall.
    To trace every syscall, tracepoints are used on sys_enter an sys_exit.
    In this case the #define TRACEPOINT is added.
    For latency #define LATENCY is added.
        Args:
            syscalls (:obj:`list` of :obj:`str`): syscall name.
            lat (bool) : activate or not the latency in the eBPF.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/ebpf.c', 'r') as ebpf_src:
        prog = ebpf_src.read()

    if lat:
        prog = prog.replace('ACTIVATELATENCY', '#define LATENCY', 1)
    else:
        prog = prog.replace('ACTIVATELATENCY', '#undef LATENCY', 1)

    if 'all' in syscalls:  # we use TRACEPOINT in that case
        prog = prog.replace('ACTIVATEALLSYSCALL', '#define TRACEPOINT', 1)
    else:  # we append 2 functions per syscall to the ebpf
        prog = prog.replace('ACTIVATEALLSYSCALL', '#undef TRACEPOINT', 1)

        i = 0
        # for every syscalls, create the functions run when
        # we enter in and return from syscall
        for fname in syscalls:
            i += 1
            prog += """
            int syscall_enter_%s(void * ctx) {
                syscall_enter(ctx,"%s");
                return 0;
            }   """ % (fname, fname)
            prog += """
            #ifdef LATENCY
            int syscall_return_%s(void * ctx) {
                syscall_return(ctx,"%s");
                return 0;
            }
            #endif""" % (fname, fname)

    # if DEBUG:
    #     print(prog)
    #     exit(0)
    # load the bpf code in kernel
    b = BPF(text=prog)

    if 'all' not in syscalls:
        attach_kprobe_to_syscall(b, syscalls)

    return b


def attach_kprobe_to_syscall(b, syscall_list):
    """Loop over all the syscall list and attach 2 kprobes, the first
    on the function entrance (kprobe) the second on the exit (kretprobe)
    to get the latency.
        Args:
            b(BPF object). This is the object to define bpf program.
            syscall_list (:obj:`list` of :obj:`str`): syscall name
    """
    for fname in syscall_list:
        try:
            syscall_name = b.get_syscall_fnname(fname)
            # exec syscall_enter_%s' (bpf) when we enter in syscall_name
            b.attach_kprobe(event=syscall_name,
                            fn_name='syscall_enter_%s' % fname)
            # exec syscall_return_%s' (bpf) when we return from syscall_name
            b.attach_kretprobe(event=syscall_name,
                               fn_name='syscall_return_%s' % fname)
        except Exception:
            print('Failed to attach to kprobe %s' % syscall_name)


def enable_all_probes(u, lang_prop, lang, latency):
    segments = lang_prop[lang]['in']
    segments_latency = lang_prop[lang]['out']
    all_segments = segments.copy()
    if latency:
        all_segments.update(segments_latency)

    for usdt_fn in all_segments:
        u.enable_probe_or_bail(all_segments[usdt_fn], '%s' % usdt_fn)


def attach_usdt_to_pid(pid, bpf_dict, lock, lat=False):
    """Attach USDT probes to a running python/java/php/ruby process.

    It detects the language of the process, then compiles and loads a
    dedicated bpf program. Compiling takes a while, so this is better
    called from a worker thread.

        Args:
            pid (int) : the pid to trace
            bpf_dict (dict) : where the loaded BPF object is stored
            lock (threading.Lock) : protects bpf_dict from the sampler
            lat (bool) : also trace the latency of the functions
        Returns:
            (bool, str) : whether the probes could be attached, and a
            message meant to be shown to the user.
    """
    pid = int(pid)
    if not os.path.exists('/proc/%s' % pid):
        return False, 'no such process'

    if pid in bpf_dict:
        return False, 'already traced'

    def list_lang(x): return [(v) for v in x]

    lang = utils.detect_language(list_lang(lang_prop), pid)
    if lang not in list_lang(lang_prop):
        return False, ('no python, java, php or ruby runtime detected. '
                       'Only these can be traced with USDT probes.')

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/usdt.c', 'r') as usdt_src:
            prog = usdt_src.read()
        u = USDT(pid=pid)
        enable_all_probes(u, lang_prop, lang, lat)

        prog = prog.replace('#DATAINDEX', '%d' % lang_prop[lang]['method_id'])

        if lat:
            prog = prog.replace('ACTIVATELATENCY', '#define LATENCY', 1)
        else:
            prog = prog.replace('ACTIVATELATENCY', '#undef LATENCY', 1)

        bpf = BPF(text=prog, usdt_contexts=[u])
    except USDTException as e:
        return False, ('the process has no USDT probe. It has to be built '
                       'with them (%s)' % e)

    with lock:
        bpf_dict[pid] = [u, bpf]

    return True, 'tracing %s function calls' % lang


class CtBackend:
    """Owns the eBPF programs and feeds the collection with their maps.

    This is the only object that talks to bcc. The display gets it and
    only calls sample() and attach_probe().

        Attributes:
            collection (CtCollection) : where the stats are stored
            pid_list (:obj:`list` of :obj:`str`) : pids to keep, or -1
            comm_list (:obj:`list` of :obj:`str`) : comms to keep, or all
            latency (bool) : whether latency is traced
            bpf_dict (dict) : a dictionary of BPF obj where the key is
            the pid in case of usdt, or 'syscall' for the bpf that
            collects the syscalls. The value is an array like
            [USDT, BPF] or [None, BPF] for syscalls.
    """

    def __init__(self, collection, pid_list=None, comm_list=None,
                 latency=True):
        self.collection = collection
        self.pid_list = pid_list or ['-1']
        self.comm_list = comm_list or ['all']
        self.latency = latency
        self.bpf_dict = {}
        # attaching a usdt probe happens in another thread than the
        # sampling, so bpf_dict has to be protected.
        self.lock = threading.Lock()

    @property
    def traced_pids(self):
        """The pids currently traced with USDT probes."""
        return [k for k in list(self.bpf_dict.keys()) if k != 'syscall']

    def load_syscall_probes(self, syscalls):
        """Compile and load the bpf program collecting the syscalls."""
        bpf = create_and_load_bpf(syscalls=syscalls, lat=self.latency)
        with self.lock:
            self.bpf_dict['syscall'] = [None, bpf]

    def attach_probe(self, pid):
        """Attach USDT probes to pid. Returns (ok, message)."""
        return attach_usdt_to_pid(pid, self.bpf_dict, self.lock,
                                  lat=self.latency)

    def sample(self, interval):
        """Read the data from every bpf map and add it to the
        collection. Entries that have not been updated for
        INACT_THRSLD are removed from the map, their value being kept
        as a reference in the collection.

            Args:
                interval (float) : the sampling interval. Only used to
                compute the rate of a function seen for the first time.
        """
        # reset the rate for each doc in the collection
        self.collection.reset_info()
        now = monotonic_ns()

        with self.lock:
            bpf_list = list(self.bpf_dict.values())

        for usdt_obj, bpf in bpf_list:
            # if usdt_obj is None then this is the bpf for the syscalls
            for k, v in bpf['map'].items():
                zeroed = False
                if v.startTime < now - INACT_THRSLD:
                    try:
                        bpf['map'].__delitem__(k)
                    except KeyError:
                        pass  # Ok, delete failed, maybe next time ?
                    else:
                        zeroed = True
                if (k.pid == 0):
                    continue
                if str(k.pid) not in self.pid_list and '-1' not in self.pid_list:
                    continue
                if (k.comm.decode() not in self.comm_list
                        and 'all' not in self.comm_list):
                    continue
                # fname is empty with TRACEPOINT on raw_syscall
                if not usdt_obj and not k.fname:
                    k.fname = syscall_name(k.sysid)
                if not usdt_obj:
                    k.fname = b'[%s]' % k.fname
                else:
                    k.fname = b'{%s}' % k.fname

                sc = ctStats(k.fname, v.counter, v.cumLat)
                # lookup the doc in the collection. If it does'not
                # exists then create it.
                doc = self.collection.lookup_or_create(k.pid, k.comm)
                # update the stats for this doc
                doc.update_doc_stats(sc, interval)
                if zeroed is True:
                    doc.keep_previous_count(sc)


def run_batch(display, backend):
    """Batch mode main loop. Sleep, sample the bpf maps then print.

        Args:
            display (BatchDisplay) : the output
            backend (CtBackend) : the eBPF side of the tool
    """
    while display.die is False:
        try:
            sleep(display.refresh_intvl)
            backend.sample(display.refresh_intvl)
            display.print_body()
        except KeyboardInterrupt:
            break


def run_top(collection, backend, interval, latency):
    """Interactive mode. Start the textual application, it drives the
    sampling by itself.

        Args:
            collection (CtCollection) : where the stats are stored
            backend (CtBackend) : the eBPF side of the tool
            interval (float) : the sampling interval
            latency (bool) : False when started with --no-latency
    """
    try:
        from calltop_tui import CallTopApp
    except ImportError as e:
        print('The interactive mode needs the textual library : \n'
              '    pip3 install textual\n'
              'or use the batch mode : calltop.py -b\n'
              '(%s)' % e)
        sys.exit(1)

    CallTopApp(collection, backend,
               refresh_intvl=interval, latency=latency).run()


def main():
    """Main function. Parse the args, load the eBPF programs then run
    either the interactive or the batch output.
    """
    parser = argparse.ArgumentParser(
        description='''It prints realtime view of the Linux syscalls
        but also languages method calls. It uses eBPF to do the tracing.
        So it is working only on Linux.''')
    parser.add_argument('-e', '--syscall',
                        help='''-e open,read,write,sendto.
                        Used to trace ONLY specific syscalls. It uses
                        kprobe. Without this option TRACEPOINT are used
                        to get all syscalls.''',
                        default='all'
                        )
    parser.add_argument('-i', '--interval',
                        help='''Set the interval in sec
                        : -i 0.5 ''',
                        default='1'
                        )
    parser.add_argument('-p', '--pid',
                        help='''Filter on pids
                        : --pid 10001,10002,10003''',
                        default='-1'
                        )
    parser.add_argument('-c', '--comm',
                        help='''Filter on comm
                        : --comm nginx,memcache,redis''',
                        default='all'
                        )

    parser.add_argument('--no-latency',
                        help='''Do not display latency of the functions
                        you trace. It saves a few nanoseconds per call.''',
                        action='store_true',
                        default=False)

    parser.add_argument('-b', '--batch',
                        help='Print output in batch mode',
                        action='store_true',
                        default=False)

    args = parser.parse_args()

    # get syscalls list
    syscall_list = args.syscall.split(',')

    # get pid list
    pid_list = args.pid.split(',')

    # get comm name list
    comm_list = args.comm.split(',')

    # set the latency and batch
    latency = not args.no_latency
    interval = float(args.interval)

    st_coll = CtCollection()  # create a collection
    backend = CtBackend(st_coll, pid_list, comm_list, latency)

    try:
        backend.load_syscall_probes(syscall_list)
    except Exception as e:
        if str(e) == 'Failed to compile BPF text':
            print('It fails compiling and load the eBPF. '
                  'You need to have root access.')
        else:
            traceback.print_exc()
        return

    # attach usdt probes on the pids given on the command line
    for pid in pid_list:
        try:
            backend.attach_probe(int(pid))
        except (ValueError, Exception):
            pass

    if args.batch:
        display = BatchDisplay(st_coll)
        display.set_refresh_intvl(interval)
        display.print_header('Collecting first data ...')
        run_batch(display, backend)
    else:
        run_top(st_coll, backend, interval, latency)


if __name__ == '__main__':
    main()
