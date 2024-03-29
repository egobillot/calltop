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
import curses
import curses.ascii
import os
import threading
import traceback
from time import monotonic_ns, sleep

from bcc import BPF, USDT, USDTException, utils
from bcc.syscall import syscall_name

# Global definition
DEBUG = 0
INACT_THRSLD = 1000000000

# create a dictionary of BPF obj where :
# - key is pid in case of usdt or 'syscall' for the bpf that collects syscalls
# - value is an array like [USDT, BPF] or [None, BPF] for syscalls
bpf_dict = {}
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

    def collection_update(self, new_doc):
        """Update an existing document in the collection. If the
        document does not exist in the colelction, then add it.
            Args:
                new_doc (CtDoc) : A document to be updated
        """
        doc = self.lookup_or_create(new_doc.pid, new_doc.comm)
        for ct_stat in new_doc.ct_stat_list:
            doc.update_doc_stats(ct_stat)

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

    def update_doc_stats(self, new_stat):
        """Update the stat of the doc with this new stat.
        If it does not yet exists, add it to the doc.
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
                return

        # not already there so add it
        self.counter_ref[new_stat.name] = 0
        self.cum_lat_ref[new_stat.name] = 0
        self.ct_stat_list.append(new_stat)
        self.total_func_cnt += new_stat.cnt_per_intvl
        self.total_func_time += new_stat.cum_lat_per_intvl
        self.total_func_cnt_per_intvl += new_stat.cnt_per_intvl
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
    """
    def __init__(self, name, cum_count, cum_lat):
        self.name = name
        self.cnt_per_intvl = cum_count  # count during the interval
        self.cum_lat_per_intvl = cum_lat  # sum of lat during interval
        self.total = cum_count  # total over time (keep increasing)
        self.cum_lat = cum_lat
        self.avg_lat = 0 if cum_count == 0 else float(cum_lat / cum_count)
        self.nb_sample = 1  # first sample

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
        """
        set count to 0
        """
        self.cnt_per_intvl = 0


class Display:
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

    def print_footer(self, string):
        """Prints string in the footer.

            Args:
                string (str): the string to print.
        """
        pass

    def reset(self):
        """Reset the display
        """
        pass

    def read_key(self):
        """Catches keys pressed, and associates an action for each key.
        """
        pass

    def set_refresh_intvl(self, rate):
        """Set refresh_intvl.

            Args:
                rate(int) : the rate.
        """
        self.refresh_intvl = rate


class BatchDisplay(Display):

    def __init__(self, ctCollection):
        self.collection = ctCollection
        self.die = False
        self.refresh_intvl = 1

    def print_body(self):
        print(self.collection.write_output().decode())

    def print_header(self, string):
        print(string)


class TopDisplay(Display):

    def __init__(self, ctCollection):
        self.h = 0
        self.w = 0
        self.w_padding = 0  # used to fill all the screen
        self.scr = 0
        self.top_line_idx = 0
        self.bottom_line_idx = 0
        self._init_display()
        self.collection = ctCollection
        self.die = False
        self.refresh_intvl = 1
        # {columnName, id, current Sort, sortable, sortOrder}
        self.columns = [
            {'name': '%6s' % 'Pid', 'id': 'pid',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': True, 'stat_sortable': False,
             'order': 1, 'stat_order': 1,
             },
            {'name': '%33s' % 'Function', 'id': 'fname',
             'cur_coll_sort': False, 'doc_current_sort': True,
             'sortable': False, 'stat_sortable': True,
             'order': 1, 'stat_order': 1
             },
            {'name': '%16s' % 'Latency(us)', 'id': 'latency',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': False, 'stat_sortable': True,
             'order': -1, 'stat_order': -1
             },
            {'name': '%16s' % 'Intv. Lat.(ms)', 'id': 'total_lat',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': False, 'stat_sortable': True,
             'order': -1, 'stat_order': -1
             },
            {'name': '%10s' % 'Call/s', 'id': 'rate',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': True, 'stat_sortable': True,
             'order': -1, 'stat_order': -1
             },
            {'name': '%16s' % 'Total Call', 'id': 'total',
             'cur_coll_sort': True, 'doc_current_sort': False,
             'sortable': True, 'stat_sortable': True,
             'order': -1, 'stat_order': -1
             },
            {'name': '%16s' % 'Total Time(ms)', 'id': 'totaltime',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': True, 'stat_sortable': True,
             'order': -1, 'stat_order': -1
             },
            {'name': '  %s' % 'Process name', 'id': 'process',
             'cur_coll_sort': False, 'doc_current_sort': False,
             'sortable': True, 'stat_sortable': False,
             'order': 1,  'stat_order': 1
             }
        ]

        self.doc_reverse_order = True
        self.ctstat_reverse_order = False
        self.filter_on = False
        self.probe_mode_on = False
        self.cmdline_mode = False
        self.filter = {'txt': b'', 'comm': b'',
                       'sys': b'', 'fn': b'', 'pid': b''}
        self.pid_to_probe = b''

    def _get_display_size(self):
        """return getmaxyx from curses.

            Returns:
                width, height (int,int): width and height of the terminal.
        """
        return self.scr.getmaxyx()

    def _update_refresh_intvl(self, direction):
        """Increase or decrease the refresh rate.

            Args:
                direction (int): -1 to decrease the refresh rate
                (increase frequency). +1 to increase the refresh
                rate (decrease frequency). If refresh rate is in
                the interval ]1; infinity[ then increase/decrease
                will add/remove 1/-1. If refresh rate is in [0; 1],
                changes is done by 0.1.
        """
        if abs(direction) == 1:
            if self.refresh_intvl == 1 and direction == 1:
                self.refresh_intvl = 2
            elif self.refresh_intvl > 1:
                self.refresh_intvl = int(self.refresh_intvl) + 1 * direction
            else:
                self.refresh_intvl += 1 * direction * 0.1

            self.refresh_intvl = max(self.refresh_intvl, 0.1)

    def _init_display(self):
        """Init of the curses display. Prepare also 4 pairs of
        colors : text colors, background colors.
        """
        self.scr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.scr.keypad(True)
        self.scr.clear()
        self.w, self.h = self._get_display_size()
        curses.start_color()
        if curses.COLORS < 256:
            # there is 0 shades of Grey !!
            mygrey = curses.COLOR_BLACK
            myblack = curses.COLOR_BLACK
        else:
            mygrey = 237
            myblack = 233
        # alternate color for the body with mygrey/myblack
        curses.init_pair(1, curses.COLOR_WHITE, myblack)
        curses.init_pair(2, curses.COLOR_YELLOW, mygrey)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_WHITE)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_RED)

    def print_body(self):
        """Print the data in a top like manner. Loops over all the
        collection and print stats related to pid/process/funcname.
        """
        self.scr.erase()
        self.h, self.w = self._get_display_size()
        self._print_tab_header()
        y_index = -1
        color_id = 0
        for doc in sorted(filter(self._filter_doc,
                          self.collection.doctionary.values()),
                          key=self._sort_key_doc,
                          reverse=self.doc_reverse_order):
            first = True
            first_stat = True
            for stat in sorted(filter(self._filter_stat, doc.ct_stat_list),
                               key=self._sort_key_ctStat,
                               reverse=self.ctstat_reverse_order):
                if first_stat:
                    color_id += 1
                    first_stat = False

                y_index += 1
                if ((y_index < self.top_line_idx) or
                        (y_index - self.top_line_idx > self.h - 3)):
                    continue
                # Workaround for the very first data of each stats
                # in this case intvl == 0, so self.refresh_intvl is used.
                # doc.stat_time[stat.name][1] is the interval.
                if doc.stat_time[stat.name][1] == 0:
                    doc.stat_time[stat.name][1] = self.refresh_intvl

                rps = stat.cnt_per_intvl / doc.stat_time[stat.name][1]
                latency = b'%.2f' % float(stat.avg_lat / 1000)
                cum_latency = float(stat.cum_lat_per_intvl / 1000000)
                total_time = float(stat.cum_lat / 1000000)

                if first:
                    pid = b'%d' % doc.pid
                    if self.cmdline_mode:
                        comm = b'%s' % doc.cmdline
                    else:
                        comm = b'%s' % doc.comm
                    first = False
                else:
                    pid = comm = b''

                line = b'%6s' % pid
                line += b'%33s' % stat.name
                line += b'%16s' % latency
                line += b'%16d' % cum_latency
                line += b'%10d' % rps
                line += b'%16d' % stat.total
                line += b'%16d' % total_time
                line += b'  %s' % comm

                color = color_id % 2 + 1  # alternate color from pair 1 and 2
                self._print_line(y_index + 1 - self.top_line_idx,
                                 line, False, color)
        self.bottom_line_idx = y_index
        self.print_footer(b'[z:reset] [<,>,left,right:sort] [Up,Down:move] '
                          b'[f:filter] [t:trace funcs] '
                          b'[+,-:sampling=%1.1fs]'
                          % (self.refresh_intvl))

    def read_key(self):
        """Catches keys pressed, and associates an action for each key.
        - key up/down scroll page by 1 line up or down
        - page up/down scroll page by 1 page up or down
        - 'z' to reset counter
        - '<' and '>' to sort inside doc
        - right / left key to sort the collection (processes)
        - 's' and 'e' to reach start or end of the display
        - 'q' to quit
        - 'r' revert sort  order
        - '+' and '-' to inc or decr refresh interval
        - 'f' to filter on process name
        - 't' to add usdt on process
        """
        while self.die is False:
            try:
                # timeout is mandatory to terminate this thread when we quit.
                self.scr.timeout(250)
                key = self.scr.getch()
                if key == curses.KEY_UP:
                    self._move(-1)  # move up
                elif key == curses.KEY_DOWN:
                    # move down
                    self._move(1)
                elif key == curses.KEY_PPAGE:
                    # move up
                    self._move(1 - self.h)
                elif key == curses.KEY_NPAGE:
                    # move down by one page
                    self._move(self.h - 1)
                elif key == ord('s'):  # s for start
                    # go back to first line
                    self._move(0, 'a')
                elif key == ord('e'):  # e for end
                    # go back to last line
                    self._move(1e12, 'a')
                elif key == ord('z'):  # z for reset
                    self._reset_collection()
                elif key == ord('<'):  # < key
                    # sort on left column
                    self._change_ctstat_sort_order(-1)
                elif key == ord('>'):  # > key
                    # sort on right column
                    self._change_ctstat_sort_order(1)
                elif key == 260:  # left key
                    # sort on left column
                    self._change_sort_column(-1)
                elif key == 261:  # right key
                    # sort on right column
                    self._change_sort_column(1)
                elif key == ord('q'):  # q for quit
                    self.die = True
                    break
                elif key == ord('r'):
                    # reverse sort
                    self._reverse_sort_order()
                elif key == ord('+'):
                    # increase sampling rate
                    self._update_refresh_intvl(+1)
                elif key == ord('-'):
                    # decrease sampling rate
                    self._update_refresh_intvl(-1)
                elif key == ord('f'):
                    # filter on comm name
                    self._set_dynamic_filter()
                elif key == ord('t'):
                    # run usdt
                    self._set_usdt_probe()
                elif key == ord('c'):
                    self.cmdline_mode = not self.cmdline_mode
            except KeyboardInterrupt:
                break

    def _move(self, y, mode='r'):
        """Scroll the page up or down.

            Args:
                y (int): if mode is relative, y is the nb of line to
                scroll up (y<0) or down (y>0). if mode is absolute, y
                will the first line of the screen.
                mode (string) : 'r' or 'a' : relative or absolute scroll.
        """

        if mode == 'r':
            self.top_line_idx = max(self.top_line_idx + y, 0)
            self.top_line_idx = min(self.top_line_idx, self.bottom_line_idx)
        elif mode == 'a':
            self.top_line_idx = max(y, 0)
            self.top_line_idx = min(y, self.bottom_line_idx)
        else:
            return

        self.print_body()

    def _filter_doc(self, doc):
        if (self.filter['pid'] == b'' or doc.pid == self.filter['pid']) and \
            (self.filter['comm'] in doc.comm or
                self.filter['comm'] in doc.cmdline):
            return True
        return False

    def _filter_stat(self, stat):
        if self.filter['sys'] in stat.name and self.filter['fn'] in stat.name:
            return True
        return False

    def _sort_key_doc(self, doc):
        """Customize the sort order for 'sorted' python function.

            Args:
                doc (:obj:`doc`): the element used to do the sort

            Returns:
                The value on wich to make the sort order
        """
        for column in self.columns:
            if column['cur_coll_sort'] is True:
                if column['id'] == 'pid':
                    return doc.pid
                elif column['id'] == 'process':
                    return doc.comm.lower()
                elif column['id'] == 'rate':
                    return doc.total_func_cnt_per_intvl
                elif column['id'] == 'total':
                    return doc.total_func_cnt
                elif column['id'] == 'totaltime':
                    return doc.total_func_time

    def _sort_key_ctStat(self, ct_stat):
        """Customize the sort order for 'sorted' python function.

            Args:
                doc (:obj:`ctStat`): the element used to do the sort

            Returns:
                The value on wich to make the sort order
        """
        for column in self.columns:
            if column['doc_current_sort'] is True:
                if column['id'] == 'rate':
                    # I should return the rps but I do an approx
                    # and return the cnt_per_interval
                    return ct_stat.cnt_per_intvl
                elif column['id'] == 'total':
                    return ct_stat.total
                elif column['id'] == 'latency':
                    return ct_stat.avg_lat
                elif column['id'] == 'total_lat':
                    return ct_stat.cum_lat_per_intvl
                elif column['id'] == 'totaltime':
                    return (ct_stat.cum_lat)
                else:
                    return ct_stat.name.lower()

    def _reverse_sort_order(self):
        """Reverse the sort order. Takes the columns attribute,
        look for the current sort column and reverse its order value
        (-1 or +1). Finally set the reverse_order boolean attribute used
        by the sorted function.
        """
        for column in self.columns:
            if column['cur_coll_sort'] is True:
                column['order'] = -1 * column['order']
                if column['order'] == 1:
                    self.doc_reverse_order = False
                elif column['order'] == -1:
                    self.doc_reverse_order = True
                break

    def _change_sort_column(self, shift):
        """Change the column on wich we do the sort. Used to
        set the current column on wich we do the sort. Set also
        the reverse_order attribute accordingly.

            Args :
                shift (int): 1 means we use the next right column
                to do the sort. -1 means it is the left one.
        """
        if shift == 1:  # shift right
            columns = self.columns
        elif shift == -1:  # shift left
            columns = reversed(self.columns)
        foundCurrent = False
        for column in columns:
            if foundCurrent is False and column['cur_coll_sort'] is True:
                previous = column
                foundCurrent = True
                continue  # found the current, now set the next
            if foundCurrent is True and column['sortable'] is True:
                # We have found one; set previous to false and current to True
                previous['cur_coll_sort'] = False
                column['cur_coll_sort'] = True
                # Order according to the saved value
                if column['order'] == 1:
                    self.doc_reverse_order = False
                elif column['order'] == -1:
                    self.doc_reverse_order = True
                break

    def _change_ctstat_sort_order(self, shift):
        """Change the column on wich we do the sort of stats.
        Set also the reverse_order attribute accordingly.

            Args :
                shift (int): 1 means we use the next right column
                to do the sort. -1 means it is the left one.
        """
        if shift == 1:  # shift right
            columns = self.columns
        elif shift == -1:  # shift left
            columns = reversed(self.columns)
        foundCurrent = False
        for column in columns:
            if foundCurrent is False and column['doc_current_sort'] is True:
                previous = column
                foundCurrent = True
                continue  # found the current, now set the next
            if foundCurrent is True and column['stat_sortable'] is True:
                # We have found one; set previous to false and current to True
                previous['doc_current_sort'] = False
                column['doc_current_sort'] = True
                if column['id'] == 'fname':
                    self.ctstat_reverse_order = False
                else:
                    self.ctstat_reverse_order = True
                break

    def _set_dynamic_filter(self):
        """Configure a filter on comm name (process name), command line,
        system call, funcion or pid.
        """
        self.filter_on = True
        f = self.filter
        while True:
            k = self.scr.getch()
            if k == curses.ascii.ESC:
                f['txt'] = f['comm'] = f['fn'] = f['pid'] = f['sys'] = b''
                break  # exit filtering mode
            elif k == curses.ascii.NL:  # Enter key
                # curses.ascii.NL = 10
                break  # validate the filter
            elif k >= 32 and k < 127:
                f['txt'] += chr(k).encode()
            elif k == 263:  # backspace
                f['txt'] = f['txt'][:-1]
            else:
                continue

        f['comm'] = f['fn'] = f['pid'] = f['sys'] = b''

        for filter_item in f['txt'].split(b','):
            if filter_item.startswith(b'sys:'):
                f['sys'] = filter_item.split(b'sys:')[1]
            elif filter_item.startswith(b'fn:'):
                f['fn'] = filter_item.split(b'fn:')[1]
            elif filter_item.startswith(b'comm:'):
                f['comm'] = filter_item.split(b'comm:')[1]
            elif filter_item.startswith(b'pid:'):
                f['pid'] = int(filter_item.split(b'pid:')[1])
            else:
                f['comm'] = filter_item

        self.filter_on = False
        self.print_body()

    def _set_usdt_probe(self):
        """Set a USDT probe on pid.
        """
        self.probe_mode_on = True
        while True:
            k = self.scr.getch()
            if k == curses.ascii.ESC:
                self.pid_to_probe = b''
                break  # exit
            elif k == curses.ascii.NL:  # Enter key
                # curses.ascii.NL = 10
                break  # validate the probe
            elif k >= 48 and k < 58:  # only digit
                self.pid_to_probe += chr(k).encode()
            elif k == 263:  # backspace
                self.pid_to_probe = self.pid_to_probe[:-1]
            else:
                continue
            self.print_body()

        try:
            pid = int(self.pid_to_probe)
            attach_usdt_to_pid(pid, lat=True)
        except ValueError:
            pass

        self.pid_to_probe = b''
        self.probe_mode_on = False
        self.print_body()

    def _reset_collection(self):
        """Zero counters of the collection. And clear the map
        from the eBPF (TODO).

        TODO need also to clear the bpf_dict[pid][1]['map']

        """
        self.collection.drop()
        self.top_line_idx = 0
        self.print_body()

    def reset(self):
        """Reset the curses screen.
        """
        curses.nocbreak()
        self.scr.keypad(False)
        curses.echo()
        curses.endwin()

    def _print_line(self, y, line, highlight, colorpair):
        """Print a line at a given position with color option.

            Args:
                y (int): The vertical position of the line
                line (str): the text to print
                highlight (bool): highlight or not the line
                colorpair (int): curses colors. see curses.init_pair
        """
        if y > self.h - 1:
            return
        option = 0
        if highlight:
            option += curses.A_DIM

        option += curses.color_pair(colorpair)
        padded_line = line.ljust(self.w, b' ')
        self.scr.addstr(y, 0, padded_line[:self.w - 1], option)

    def _print_tab_header(self):
        """Create and print the top Header.
        """
        opt = curses.color_pair(3)
        opt_selected = curses.color_pair(5)

        w_index = 0
        for column in self.columns:
            color = opt  # set color to opt
            # column['cur_coll_sort'] The column used to sort over the coll
            if column['cur_coll_sort'] is True:
                color = opt_selected  # set color to white/red
            # column['doc_current_sort'] The column used to sort inside doc
            if column['doc_current_sort'] is True:
                color += curses.A_STANDOUT
            if w_index >= self.w:  # line will be out of the screen
                break              # and curses does an ERR in this case
            else:
                margin_right = self.w - w_index
                col = (column['name'])[:margin_right]
            self.scr.addstr(0, w_index, col, color)
            w_index += len(column['name'])

        # now add padding to the header tab
        if w_index < self.w:
            self.w_padding = self.w - w_index
            self.scr.addstr(0, w_index, ' ' * (self.w_padding), color)

    def print_header(self, string):
        """Prints string at the first line. header's height = 1 row.

            Args:
                string (str): the string to print.
        """
        self._print_line(0, string, False, 3)

    def print_footer(self, string):
        """Prints string in the footer. footer's height = 1 row

            Args:
                string (str): the string to print.
        """
        if self.filter_on is True:
            self._print_line(self.h - 1,
                             b'Filter: ' + self.filter['txt'],
                             False,
                             5)
        elif self.probe_mode_on is True:
            self._print_line(self.h - 1,
                             b'Attach probe to: ' + self.pid_to_probe,
                             False,
                             5)

        else:
            self._print_line(self.h - 1, string, False, 4)


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


def attach_usdt_to_pid(pid, lat=False):
    global bpf_dict

    # first make sure the pid exists
    if not os.path.exists('/proc/%s' % pid):
        return

    def list_lang(x): return [(v) for v in x]

    lang = utils.detect_language(list_lang(lang_prop), pid)
    if lang not in list_lang(lang_prop):
        return

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/usdt.c', 'r') as usdt_src:
            prog = usdt_src.read()
        u = USDT(pid=int(pid))
        enable_all_probes(u, lang_prop, lang, lat)

        prog = prog.replace('#DATAINDEX', '%d' % lang_prop[lang]['method_id'])

        if lat:
            prog = prog.replace('ACTIVATELATENCY', '#define LATENCY', 1)
        else:
            prog = prog.replace('ACTIVATELATENCY', '#undef LATENCY', 1)

        bpf_dict[pid] = [u, BPF(text=prog, usdt_contexts=[u])]

    except USDTException:
        return


def run(display, bpf_dict, pid_list, comm_list):
    """ Main loop. Sleep, then read the data from bpf map in the
    bpf_dict and add it to the collection.
        Args:
            bpf_dict(BPF object dictionary). A BPF object is the main
            object for defining a BPF program and interacting with its
            output. This dict  will contains BPFs for usdt and one BPF
            for the syscalls.
            pid_list (:obj:`list` of :obj:`str`) : list of pids you
            want to trace.
            comm_list (:obj:`list` of :obj:`str`) : list of process
            name you want to trace.
    """
    while display.die is False:
        try:
            sleep(display.refresh_intvl)
            # reset the rate for each doc in the collection
            display.collection.reset_info()
            now = monotonic_ns()
            for bpf_arr in bpf_dict.values():
                usdt_obj = bpf_arr[0]  # if None then is the bpf for syscall
                bpf = bpf_arr[1]
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
                    if str(k.pid) not in pid_list and '-1' not in pid_list:
                        continue
                    if k.comm.decode() not in comm_list and 'all' not in comm_list:
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
                    doc = display.collection.lookup_or_create(k.pid, k.comm)
                    # update the stats for this doc
                    doc.update_doc_stats(sc)
                    if zeroed is True:
                        doc.keep_previous_count(sc)

            display.print_body()
        except KeyboardInterrupt:
            break

    display.print_header(b'Exiting ...')
    display.reset()
    display.die = True  # will terminate the thread for keyboard


def main():
    """Main function.
        Args:
            display (TopDisplay) : object use to print in a 'top' like manner
    """
    global bpf_dict
    display = None
    try:
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
        batch = args.batch

        b = create_and_load_bpf(syscalls=syscall_list, lat=latency)
        bpf_dict['syscall'] = [None, b]

        st_coll = CtCollection()  # create a collection
        if batch is True:
            display = BatchDisplay(st_coll)  # display of the collection
        else:
            display = TopDisplay(st_coll)  # display of the collection
            # Create a daemon thread for the keyboard short key
            # daemon threads are killed when the main process exits.
            t = threading.Thread(target=display.read_key, daemon=True)
            t.start()

        display.set_refresh_intvl(float(args.interval))
        display.print_header(b'Collecting first data ...')

        for pid in pid_list:
            attach_usdt_to_pid(int(pid), lat=latency)
        run(display, bpf_dict, pid_list, comm_list)

    except Exception as e:
        if display:
            display.print_header(b'Exiting...')
            display.reset()
            display.die = True  # will terminate the thread for keyboard
        if str(e) == 'Failed to compile BPF text':
            print('It fails compiling and load the eBPF. '
                  'You need to have root access.')
        else:
            traceback.print_exc()


if __name__ == '__main__':
    main()
