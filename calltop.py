#!/usr/bin/env python
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
import sys
import threading
import traceback
from time import sleep

from bcc import BPF
from bcc.syscall import syscall_name

# Global definition
DEBUG = 0
INACT_THRSLD = 1000000000


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
        output = b'%6s' % 'Pid'
        output += b'%17s' % 'Process name'
        output += b'%21s' % 'Function'
        output += b'%16s' % 'latency(us)'
        output += b'%16s' % 'Call/s'
        output += b'%16s\n' % 'Total'
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
        self.total_func_cnt = 0  # the sum of each func call count in this doc
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
                self.total_func_cnt_per_intvl += new_stat.cnt_per_intvl
                # set timestamp and compute new interval
                ts = monotonic_time() * 1e-9
                intvl = ts - self.stat_time[new_stat.name][0]
                self.stat_time[new_stat.name] = [ts, intvl]
                return

        # not already there so add it
        self.counter_ref[new_stat.name] = 0
        self.cum_lat_ref[new_stat.name] = 0
        self.ct_stat_list.append(new_stat)
        self.total_func_cnt += new_stat.cnt_per_intvl
        self.total_func_cnt_per_intvl += new_stat.cnt_per_intvl
        # initial values are the timestamp and 0 for intvl
        # div by 0 will be manage at the display time
        self.stat_time[new_stat.name] = [monotonic_time() * 1e-9, 0]

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
        first = True
        for ct_stat in self.ct_stat_list:
            output += b'%6d' % self.pid
            output += b'%17s' % self.comm
            output += ct_stat.write_output()
        return output

    def reset_info(self):
        for ct_stat in self.ct_stat_list:
            ct_stat.reset_info()


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
        self.avg_lat = float(cum_lat / cum_count)  # avg latency during intvl.
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
        output = b'%21s' % self.name
        output += b'%16d' % self.avg_lat
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
        print(self.collection.write_output())

    def print_header(self, string):
        print(string)


class TopDisplay(Display):

    def __init__(self, ctCollection):
        self.h = 0
        self.w = 0
        self.scr = None
        self.top_line_idx = 0
        self.bottom_line_idx = 0
        self._init_display()
        self.collection = ctCollection
        self.die = False
        self.refresh_intvl = 1
        # {columnName, id, current Sort, sortable, sortOrder}
        self.sort_column = [{'name': '%6s' % 'Pid', 'id': 'pid',
                             'curSort': False, 'sortable': True, 'order': 1},
                            {'name': '%17s' % 'Process name', 'id': 'process',
                             'curSort': False, 'sortable': True, 'order': 1},
                            {'name': '%21s' % 'Function', 'id': 'fname',
                             'curSort': False, 'sortable': False, 'order': 1},
                            {'name': '%16s' % 'Latency(us)', 'id': 'rate',
                             'curSort': False, 'sortable': False, 'order': -1},
                            {'name': '%16s' % 'Call/s', 'id': 'rate',
                             'curSort': False, 'sortable': True, 'order': -1},
                            {'name': '%16s' % 'Total', 'id': 'total',
                             'curSort': True, 'sortable': True, 'order': -1}
                            ]
        self.reverse_order = True
        self.filter_on = False
        self.comm_filter = b''

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
        self.h, self.w = self._get_display_size()
        self.scr.clear()
        self._print_tab_header()
        y_index = -1
        doc_id = 0
        for doc in sorted(self.collection.doctionary.values(),
                          key=self._sort_key,
                          reverse=self.reverse_order):
            first = True
            # Aplly filter if it exists
            if (self.comm_filter.lower()) in doc.comm.lower():
                doc_id += 1
                for stat in doc.ct_stat_list:
                    y_index += 1
                    if ((y_index < self.top_line_idx) or
                            (y_index - self.top_line_idx > self.h - 3)):
                        continue
                    # Workaround for the very first data of each stats
                    # int his case intvl == 0, so self.refresh_intvl is used.
                    # doc.stat_time[stat.name][1] is the interval.
                    if doc.stat_time[stat.name][1] == 0:
                        doc.stat_time[stat.name][1] = self.refresh_intvl

                    rps = stat.cnt_per_intvl / doc.stat_time[stat.name][1]
                    latency = b'%.2f' % float(stat.avg_lat / 1000)

                    if first:
                        pid = b'%d' % doc.pid
                        comm = doc.comm
                        first = False
                    else:
                        pid = comm = b''

                    line = b'%6s ' % pid
                    line += b'%16s ' % comm
                    line += b'%20s ' % stat.name
                    line += b'%15s ' % latency
                    line += b'%15d ' % rps
                    line += b'%15d' % stat.total

                    color = doc_id % 2 + 1  # alternate color from pair 1 and 2
                    self._print_line(y_index + 1 - self.top_line_idx,
                                     line, False, color)
        self.bottom_line_idx = y_index
        self.print_footer(b'z: reset| >/<: sort| +/-: incr/decr sampling rate'
                          b'| UP/Down (%d/%d)  [refresh=%1.1fs]'
                          % (self.top_line_idx,
                             self.bottom_line_idx,
                             self.refresh_intvl))
        self.scr.refresh()

    def read_key(self):
        """Catches keys pressed, and associates an action for each key.
        - key up/down scroll page by 1 line up or down
        - page up/down scroll page by 1 page up or down
        - 'z' to reset counter
        - '<' and '>' to sort
        - 'q' to quit
        - 'r' revert sort  order
        - '+' and '-' to inc or decr refresh interval
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
                elif key == ord('<') or key == 260:  # < or left key
                    # sort on left column
                    self._change_sort_column(-1)
                elif key == ord('>') or key == 261:  # > or right key
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

        self.scr.erase()
        self.print_body()

    def _sort_key(self, doc):
        """Customize the sort order for 'sorted' python function.

            Args:
                doc (:obj:`doc`): the element used to do the sort

            Returns:
                The value on wich to make the sort order
        """
        for idx, val in enumerate(self.sort_column):
            if val['curSort'] is True:
                if val['id'] == 'pid':
                    return doc.pid
                elif val['id'] == 'process':
                    return doc.comm.lower()
                elif val['id'] == 'rate':
                    return doc.total_func_cnt_per_intvl
                elif val['id'] == 'total':
                    return doc.total_func_cnt

    def _reverse_sort_order(self):
        """Reverse the sort order. Takes the sort_column attribute,
        look for the current sort column and reverse its order value
        (-1 or +1). Finally set the reverse_order boolean attribute used
        by the sorted function.
        """
        for idx, val in enumerate(self.sort_column):
            if val['curSort'] is True:
                val['order'] = -1 * val['order']
                if val['order'] == 1:
                    self.reverse_order = False
                elif val['order'] == -1:
                    self.reverse_order = True
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
            lst = self.sort_column
        elif shift == -1:  # shift left
            lst = reversed(self.sort_column)
        foundCurrent = False
        for i, val in enumerate(lst, 1):
            if foundCurrent is False and val['curSort'] is True:
                previous = val
                foundCurrent = True
                continue  # found the current, now set the next
            if foundCurrent is True and val['sortable'] is True:
                # We have found one; set previous to false and current to True
                previous['curSort'] = False
                val['curSort'] = True
                break
        # Order according to the saved value
        if val['order'] == 1:
            self.reverse_order = False
        elif val['order'] == -1:
            self.reverse_order = True

    def _set_dynamic_filter(self):
        """Configure a filter on comm name (process name).
        """
        self.filter_on = True
        while True:
            k = self.scr.getch()
            if k == curses.ascii.ESC:
                self.comm_filter = b''
                break  # exit filtering mode
            elif k == curses.ascii.NL:  # Enter key
                # curses.ascii.NL = 10
                break  # validate the filter
            elif k >= 20 and k < 127:
                self.comm_filter += chr(k).encode()
            elif k == 263:  # backspace
                self.comm_filter = self.comm_filter[:-1]
            else:
                continue
            self.print_body()
        self.filter_on = False
        self.print_body()

    def _reset_collection(self):
        """Zero counters of the collection. And clear the map
        from the eBPF (TODO).

        TODO need also to clear the b['map']
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

        self.scr.addstr(y, 0, line[:self.w - 1], option)
        # self.scr.clrtoeol()

    def _print_tab_header(self):
        """Create and print the top Header.
        """
        opt = curses.color_pair(3)
        opt_selected = curses.color_pair(5)

        w_index = 0
        for val in self.sort_column:
            color = opt  # set color to opt
            if val['curSort'] is True:  # This is the column used by sort
                color = opt_selected  # set color to white/red
            if w_index >= self.w:  # line will be out of the screen
                break              # and curses does an ERR in this case
            self.scr.addstr(0, w_index, val['name'], color)
            w_index += len(val['name'])

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
                             b'Filter: ' + self.comm_filter,
                             False,
                             5)
        else:
            self._print_line(self.h - 1, string, False, 4)


class TimeSpec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]


def monotonic_time():
    """Implements time.monotonic() from python3.
    Not available in python2.7.
    code is adapted from https://stackoverflow.com/a/1205762
        Returns:
            time in nano seconds
    """
    CLOCK_MONOTONIC_RAW = 4  # see <linux/time.h>

    librt = ctypes.CDLL('librt.so.1', use_errno=True)
    clock_gettime = librt.clock_gettime
    clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(TimeSpec)]

    t = TimeSpec()

    if clock_gettime(CLOCK_MONOTONIC_RAW, ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec * 1e9 + t.tv_nsec


def debug(filename, s,):
    with open(filename, 'a') as f:
        f.write('%s\n' % s)


def create_and_load_bpf(syscall_list, latency):
    """ This function read the ebpf.c file, save it into a string. A part of
    the ebp.c is generated by this function. For specific syscall list we
    append a do_enter_'syscall' and do_return_'syscall' function for every
    syscall. But in order to trace every syscall, tracepoints are used on
    sys_enter an sys_exit. In this case the #define TRACEPOINT is added.
    For latency #define LATENCY is added.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/ebpf.c', 'r') as ebpf_code:
        prog = ebpf_code.read()

    if latency:
        prog = prog.replace('ACTIVATELATENCY', '#define LATENCY', 1)
    else:
        prog = prog.replace('ACTIVATELATENCY', '#undef LATENCY', 1)

    if syscall_list[0] == 'all':
        prog = prog.replace('ACTIVATEALLSYSCALL', '#define TRACEPOINT', 1)
    else:
        prog = prog.replace('ACTIVATEALLSYSCALL', '#undef TRACEPOINT', 1)

        i = 0
        for fname in syscall_list:
            i += 1
            prog += """
            int do_enter_%s(void * ctx) {
                do_enter(ctx,"%s");
                return 0;
            }   """ % (fname, fname)
            prog += """
            #ifdef LATENCY
            int do_return_%s(void * ctx) {
                do_return(ctx,"%s");
                return 0;
            }
            #endif""" % (fname, fname)

    # if DEBUG:
    #     print(prog)
    #     exit(0)
    # load the bpf code in kernel
    b = BPF(text=prog)
    return b


def attach_syscall_to_kprobe(b, syscall_list):
    """Loop over all the syscall list and attach 2 kprobes, the first
    on the function entrance the second on the exit to get the latency.
        Args:
            syscall_list (:obj:`list` of :obj:`str`): function name or
            syscall
    """
    for fname in syscall_list:
        try:
            syscall_name = b.get_syscall_fnname(fname)
            b.attach_kprobe(event=syscall_name, fn_name='do_enter_%s' % fname)
            b.attach_kprobe(event=syscall_name, fn_name='do_return_%s' % fname)
        except KeyboardInterrupt:
            display.print_header(b'Exiting ...')
            display.reset()
            display.die = True  # will terminate the thread for keyboard
        except Exception:
            print('Failed to attach to kprobe %s' % syscall_name)


def run(display, b, pid_list, comm_list):
    """ Main loop. Sleep interval, then read the data from bpf map
    (b['map']) and add it to the collection.
        Args:
            b(BPF object). This is the main object for defining a BPF program,
            and interacting with its output.
            pid_list (:obj:`list` of :obj:`str`) : list of pids you
            want to trace.
            comm_list (:obj:`list` of :obj:`str`) : list of process
            name you want to trace.
    """
    # clear to start collecting everything at the same time
    b['map'].clear()

    while display.die is False:
        try:
            sleep(display.refresh_intvl)
            # reset the rate for each doc in the collection
            display.collection.reset_info()
            now = monotonic_time()
            for k, v in b['map'].items():
                # map.clear() or item.__delitem__() are not thread safe !!
                # Unfortunatly we need to delete items in the map, it saves
                # entries in map.
                # delete items that are not active for more than 1 sec
                # by assuming old entries won't create consistency issues
                zeroed = False
                if v.startTime < int(now - INACT_THRSLD):
                    b['map'].__delitem__(k)
                    zeroed = True
                if ((k.pid != 0)
                    and
                        (str(k.pid) in pid_list or '-1' in pid_list)
                    and
                        (k.comm.decode() in comm_list or 'all' in comm_list)):

                    if not k.fname:  # in case of a syscall fname is empty
                        k.fname = syscall_name(k.sysid)  # get fname
                    sc = ctStats(k.fname, v.counter, v.cumLat)
                    # lookup the doc in the collection. If it does not exists
                    # then create it.
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
    global DEBUG
    display = None
    try:
        parser = argparse.ArgumentParser(
            description="""display realtime view of the Linux syscalls.
            It uses eBPF to do the tracing""")
        parser.add_argument('-e', '--syscall',
                            help='the list of syscalls to trace '
                            '-e read,write,sendto',
                            default='all'
                            )
        parser.add_argument('-i', '--interval',
                            help='set the interval in sec',
                            default='1'
                            )
        parser.add_argument('-p', '--pid',
                            help='filter on pids'
                            'eg --pid 10001,10002,10003',
                            default='-1'
                            )
        parser.add_argument('-c', '--comm',
                            help='''filter on comm alias process name
                            --comm nginx,memcache,redis''',
                            default='all'
                            )
        parser.add_argument('-d', '--debug', help='print eBPF code',
                            action='store_true')

        parser.add_argument('-l', '--latency', help='display latency of func',
                            action='store_true')

        parser.add_argument('-b', '--batch', help='print output in batch mode',
                            action='store_true',
                            default=False)

        args = parser.parse_args()

        # get syscalls list
        syscall_list = args.syscall.split(',')

        # get pid list
        pid_list = args.pid.split(',')

        # get comm name list
        comm_list = args.comm.split(',')

        # set the latency, DEBUG and batch
        latency = args.latency
        batch = args.batch
        DEBUG = args.debug

        b = create_and_load_bpf(syscall_list, latency)
        if syscall_list[0] != b'all':
            attach_syscall_to_kprobe(b, syscall_list)

        st_coll = CtCollection()  # create a collection
        if batch is True:
            display = BatchDisplay(st_coll)  # display of the collection
        else:
            display = TopDisplay(st_coll)  # display of the collection
            # Create a thread for the keyboard short key
            t = threading.Thread(target=display.read_key)
            t.start()

        display.set_refresh_intvl(float(args.interval))
        display.print_header(b'Collecting first data ...')

        run(display, b, pid_list, comm_list)
        if batch is False:
            t.join()
        display.die = True  # will terminate the thread for keyboard
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
