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
        self.collection = {}

    def collection_update(self, newDoc):
        """Update an existing document in the collection. If the
        document does not exist in the colelction, then add it.
            Args:
                newDoc (Doc) : A document to be updated
        """
        doc = self.lookup_or_create(newDoc.pid, newDoc.comm)
        for stSysStats in newDoc.stSysStatsList:
            doc.updatestSysStats(stSysStats)

    def lookup_or_create(self, pid, comm):
        """Return the doc with the given pid and comm if it exists,
        else create and insert it.
            Args :
                pid (int) : pid of the process
                comm (str) : name of the process
            Returns :
                doc (Doc) : The doc new one or already existing
        """
        # lookup
        key = str(pid) + str(comm)
        doc = self.collection.get(key, None)
        # or create if look up failed
        if doc is None:
            doc = Doc(pid, comm)
            key = str(pid) + str(comm)
            self.collection[key] = doc

        return doc

    def drop(self):
        """Drop a collection and all its documents. It drops also
        all the stats in docs.
        """
        for k, doc in self.collection.items():
            del doc
            del self.collection[k]

    def writeOutput(self):
        strOut = "|"+"=" * 77 + "|\n"
        strOut += "|%6s" % " pid "
        strOut += "|%16s" % "process name"
        strOut += "|%21s" % "function"
        strOut += "|%15s" % "Rate/s"
        strOut += "|%15s|\n" % "Total"
        strOut += "|"+"=" * 77 + "|\n"
        for doc in self.collection:
            strOut += doc.writeOutput()

        return strOut

    def resetInfo(self):
        for doc in self.collection.values():
            doc.sysTotalCntPerIntvl = 0
            doc.resetInfo()


class Doc:
    """This class define the document of a collection. A doc is made
    up of a pid and a process name (comm). pid and comm identify a
    process (and not only pid). The document conatins also a list of
    stats of system calls or functions. A document is also made up
    of a 2 global counters that are the sum of each system call /
    function counters during the interval of from the begining.

        Attributes:
            pid (int) : The pid
            comm (str) : The process name
            sysTotalCnt (int) : The sum of each counters in this doc
            sysTotalCntPerIntvl (int) : The sum of each function call
            counters in this doc during the interval.
            stSysStatsList (:obj:`list` of :obj:`stSysStatsList`) : The
            list of stat for each functions/syscall
    """
    def __init__(self, pid, comm):
        self.pid = pid
        self.comm = comm
        self.sysTotalCnt = 0  # the sum of each statSysCall count in this doc
        self.sysTotalCntPerIntvl = 0  # the sum of each statSysCall rates
        self.stSysStatsList = []
        # we want to keep the reference counter and cumulated Latency.
        # when a stat for a function is reset keep the reference in counterRef
        # and cumLatRef.
        # This is a dict where key = func name and value the counter
        self.counterRef = {}
        # This is a dict where key = func name and value the cumulated Latency
        self.cumLatRef = {}

    def __delitem__(self):
        del (self.stSysStatsList)

    def updatestSysStats(self, stSysStats):
        """Update the stat of the doc with this new stat.
        If it does not yet exists, add it to the doc.
        """
        for syscall in self.stSysStatsList:
            if syscall.name == stSysStats.name:
                syscall.updateStats(stSysStats,
                                    self.counterRef[syscall.name],
                                    self.cumLatRef[syscall.name])
                self.sysTotalCnt += stSysStats.cntPerIntvl
                self.sysTotalCntPerIntvl += stSysStats.cntPerIntvl
                return
        # not already there so add it
        self.counterRef[stSysStats.name] = 0
        self.cumLatRef[stSysStats.name] = 0
        self.stSysStatsList.append(stSysStats)
        self.sysTotalCnt += stSysStats.cntPerIntvl
        self.sysTotalCntPerIntvl += stSysStats.cntPerIntvl

    def keep_previous_count(self, stSysStats):
        """The stats has been deleted. Preciseley counters and cumLat has been
        clear/delitem from the eBPF map. In order to keep consistent infos, we
        need to save the previous values : the references.
            Args:
                stSysStats : (stSysStats) The stat that has been reset
        """
        self.counterRef[stSysStats.name] += stSysStats.total
        self.cumLatRef[stSysStats.name] += stSysStats.cumLat

    def writeOutput(self):
        strOut = ""
        first = True
        for stSysStats in self.stSysStatsList:
            if first:
                strOut += "|%6s" % self.pid,
                strOut += "|%16s" % self.comm,
                strOut += "| %20s" % stSysStats.name,
                strOut += "|%15d" % stSysStats.avgLat,
                strOut += "|%15d" % stSysStats.cntPerIntvl,
                strOut += "|%15d|\n" % stSysStats.total

                first = False
            else:
                strOut += "|%6s" % " ",
                strOut += "|%16s" % " ",
                strOut += "|%21s" % stSysStats.name,
                strOut += "|%15d" % stSysStats.avgLat,
                strOut += "|%15d" % stSysStats.cntPerIntvl,
                strOut += "|%15d|\n" % stSysStats.total

        strOut += "|"+"=" * 77 + "|\n"
        return strOut

    def resetInfo(self):
        for stSysStats in self.stSysStatsList:
            stSysStats.resetInfo()


class stSysStats:
    """stSysStats is used to get latency or call counters for a given
    function call.

    Attributes:
        name (str): Name of the function traced
        cntPerIntvl (int): nb of call to function during the interval
        cumLatPerIntvl (int): cumulated time spent in func during the interval
        total (int): nb of call to function from the begining
        cumLat (int): cumulated time (ns) spent in the func from the begining
        avgLat (float): cumulated time (ns) spent in the func during the interval
        nbSample (int): nb of sample
    """
    def __init__(self, name, cumCount, cumLat):
        self.name = name
        self.cntPerIntvl = cumCount  # count during the interval
        self.cumLatPerIntvl = cumLat  # sum of lat during interval
        self.total = cumCount  # total over time (keep increasing)
        self.cumLat = cumLat
        self.avgLat = float(cumLat / cumCount)  # avg latency during intvl.
        self.nbSample = 1  # first sample

    def updateStats(self, sysStat, counterRef, cumLatRef):
        """Update the information of a stSysStats. It mainly manage the case
        where the counter and cumLat from the eBPF has been cleared. In this
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
            sysStat (stSysStats): Update the current stats with value from
            sysStat args.
            counterRef (int): Use this value as the previous reference
            for counter before clear
            cumLatRef (int):  Use this value as the previous reference
            for cumulated latency before clear
        """
        # BUG : when this stats has been zeroed and
        # if self.total == sysStat.total ( old value is == new value)
        # then nothing will be added. And in that specific case it should
        # should not happen so often, but need to fixe it.
        if int(self.total) == int(sysStat.total):
            return  # counter have not been updated

        # count per interval = new count - old  count
        self.cntPerIntvl = sysStat.total - self.total + counterRef

        # time spent per interval
        self.cumLatPerIntvl = sysStat.cumLat - self.cumLat + cumLatRef

        # update the Total with the one give by eBPF counter
        self.total = counterRef + sysStat.total

        # update the cumulated Latency
        self.cumLat = cumLatRef + sysStat.cumLat

        # compute the avg latency
        if self.cntPerIntvl == 0:
            self.avgLat = 0
        else:
            self.avgLat = float(self.cumLatPerIntvl / self.cntPerIntvl)

        # increment sample count
        self.nbSample += 1

    def writeOutput(self):
        strOut += "[%16s]" % self.name,
        strOut += "latInt=%8.2f" % self.avgLat,
        strOut += "cntInt=%8d" % self.cntPerIntvl,
        strOut += "Total=%8d" % self.total,
        strOut += "sample=%8d" % self.nbSample
        return strOut

    def resetInfo(self):
        """
        set count to 0
        """
        self.cntPerIntvl = 0


def debug(filename, s,):
    with open(filename, 'a') as f:
        f.write("%s\n" % s)


class TopDisplay:

    def __init__(self, stCollection):
        self.h = 0
        self.w = 0
        self.scr = None
        self.topLineIdx = 0
        self.bottomLineIdx = 0
        self._initDisplay()
        self.collection = stCollection
        self.die = False
        self.refreshIntvl = 1
        # {columnName, id, current Sort, sortable, sortOrder}
        self.sortColumn = [{"name": "%6s" % "PID", "id": "pid",
                            "curSort": False, "sortable": True, "order": 1},
                           {"name": "%17s" % "PROCESS NAME", "id": "process",
                            "curSort": False, "sortable": True, "order": 1},
                           {"name": "%21s" % "FUNC NAME", "id": "fname",
                            "curSort": False, "sortable": False, "order": 1},
                           {"name": "%16s" % "latency(us)", "id": "rate",
                            "curSort": False, "sortable": False, "order": -1},
                           {"name": "%16s" % "call/s", "id": "rate",
                            "curSort": False, "sortable": True, "order": -1},
                           {"name": "%16s" % "TOTAL", "id": "total",
                            "curSort": True, "sortable": True, "order": -1}
                           ]
        self.reverseOrder = True

    def _getDisplaySize(self):
        """return getmaxyx from curses.

            Returns:
                width, height (int,int): width and height of the terminal.
        """
        return self.scr.getmaxyx()

    def setRefreshIntvl(self, rate):
        """Set refreshIntvl.

            Args:
                rate(int) : the rate.
        """
        self.refreshIntvl = rate

    def _updateRefreshIntvl(self, direction):
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
            if self.refreshIntvl == 1 and direction == 1:
                self.refreshIntvl = 2
            elif self.refreshIntvl > 1:
                self.refreshIntvl = int(self.refreshIntvl) + 1 * direction
            else:
                self.refreshIntvl += 1 * direction * 0.1

            self.refreshIntvl = max(self.refreshIntvl, 0.1)

    def _initDisplay(self):
        """Init of the curses display. Prepare also 4 pairs of
        colors : text colors, background colors.
        """
        self.scr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.scr.keypad(True)
        self.scr.clear()
        self.w, self.h = self._getDisplaySize()
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

    def printBody(self):
        """Print the data in a top like manner. Loops over all the
        collection and print stats related to pid/process/funcname.
        """
        self.h, self.w = self._getDisplaySize()
        self.scr.clear()
        self._printTabHeader()
        y_index = -1
        doc_id = 0
        for doc in sorted(self.collection.collection.values(),
                          key=self._sortKey,
                          reverse=self.reverseOrder):
            first = True
            doc_id += 1
            for stSysStats in doc.stSysStatsList:
                y_index += 1
                if ((y_index < self.topLineIdx) or
                        (y_index - self.topLineIdx > self.h - 2)):
                    continue
                rps = stSysStats.cntPerIntvl / self.refreshIntvl
                latency = "%.2f" % float(stSysStats.avgLat / 1000)

                if first:
                    pid = doc.pid
                    comm = doc.comm
                    first = False
                else:
                    pid = comm = ""

                line = "%6s " % pid
                line += "%16s " % comm
                line += "%20s " % stSysStats.name
                line += "%15s " % str(latency)
                line += "%15d " % rps
                line += "%15d" % stSysStats.total

                color = doc_id % 2 + 1  # alternate color from pair 1 and 2
                self._printLine(y_index + 1 - self.topLineIdx,
                                line, False, color)
        self.bottomLineIdx = y_index
        self.printFooter("z: reset| >/<: sort| +/-: incr/decr sampling rate"
                         "| UP/Down (%d/%d)  [refresh=%1.1fs]"
                         % (self.topLineIdx,
                            self.bottomLineIdx,
                            self.refreshIntvl))
        self.scr.refresh()

    def readKey(self):
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
                self.scr.timeout(250)
                key = self.scr.getch()
                if key == curses.KEY_UP:
                    self._move(-1)
                elif key == 115:  # s
                    self._move(0, "a")  # go back to first line
                elif key == 101:  # s
                    self._move(1e12, "a")  # go back to last line
                elif key == curses.KEY_DOWN:
                    self._move(1)
                elif key == curses.KEY_PPAGE:
                    self._move(1 - self.h)
                elif key == curses.KEY_NPAGE:
                    self._move(self.h - 1)
                elif key == 122:  # z key
                    self._resetCollection()
                elif key == 60 or key == 260:  # < or left key
                    self._changeSortColumn(-1)
                elif key == 62 or key == 261:  # > or right key
                    self._changeSortColumn(1)
                elif key == 113:  # q key
                    self.die = True
                    break
                elif key == 114:  # r key
                    self._reverseSortOrder()  # reverse sort
                elif key == 43:  # + key
                    self._updateRefreshIntvl(+1)
                elif key == 45:  # - key
                    self._updateRefreshIntvl(-1)
            except KeyboardInterrupt:
                break

    def _move(self, y, mode="r"):
        """Scroll the page up or down.

            Args:
                y (int): if mode is relative, y is the nb of line to
                scroll up (y<0) or down (y>0). if mode is absolute, y
                will the first line of the screen.
                mode (string) : "r" or "a" : relative or absolute scroll.
        """

        if mode == "r":
            self.topLineIdx = max(self.topLineIdx + y, 0)
            self.topLineIdx = min(self.topLineIdx, self.bottomLineIdx)
        elif mode == "a":
            self.topLineIdx = max(y, 0)
            self.topLineIdx = min(y, self.bottomLineIdx)
        else:
            return

        self.scr.erase()
        self.printBody()

    def _sortKey(self, doc):
        """Customize the sort order for 'sorted' python function.

            Args:
                doc (:obj:`doc`): the element used to do the sort

            Returns:
                The value on wich to make the sort order
        """
        for idx, val in enumerate(self.sortColumn):
            if val['curSort'] is True:
                if val['id'] == "pid":
                    return doc.pid
                elif val['id'] == "process":
                    return doc.comm.lower()
                elif val['id'] == "rate":
                    return doc.sysTotalCntPerIntvl
                elif val['id'] == "total":
                    return doc.sysTotalCnt

    def _reverseSortOrder(self):
        """Reverse the sort order. Takes the sortColumn attribute,
        look for the current sort column and reverse its order value
        (-1 or +1). Finally set the reverseOrder boolean attribute used
        by the sorted function.
        """
        for idx, val in enumerate(self.sortColumn):
            if val['curSort'] is True:
                val['order'] = -1 * val['order']
                if val['order'] == 1:
                    self.reverseOrder = False
                elif val['order'] == -1:
                    self.reverseOrder = True
                break

    def _changeSortColumn(self, shift):
        """Change the column on wich we do the sort. Used to
        set the current column on wich we do the sort. Set also
        the reverseOrder attribute accordingly.

            Args :
                shift (int): 1 means we use the next right column
                to do the sort. -1 means it is the left one.
        """
        if shift == 1:  # shift right
            lst = self.sortColumn
        elif shift == -1:  # shift left
            lst = reversed(self.sortColumn)
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
            self.reverseOrder = False
        elif val['order'] == -1:
            self.reverseOrder = True

    def _resetCollection(self):
        """Zero counters of the collection. And clear the map
        from the eBPF (TODO).

        TODO need also to clear the b["map"]
        """
        self.collection.drop()
        self.topLineIdx = 0
        self.printBody()

    def reset(self):
        """Reset the curses screen.
        """
        curses.nocbreak()
        self.scr.keypad(False)
        curses.echo()
        curses.endwin()

    def _printLine(self, y, line, highlight, colorpair):
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

    def _printTabHeader(self):
        """Create and print the top Header.
        """
        opt = curses.color_pair(3)
        opt_selected = curses.color_pair(5)

        w_index = 0
        for val in self.sortColumn:
            color = opt  # set color to opt
            if val['curSort'] is True:  # This is the column used by sort
                color = opt_selected  # set color to white/red
            if w_index >= self.w:  # line will be out of the screen
                break              # and curses does an ERR in this case
            self.scr.addstr(0, w_index, val['name'], color)
            w_index += len(val['name'])

    def printHeader(self, string):
        """Prints string in the header. header's height = 1 row.

            Args:
                string (str): the string to prints.
        """
        self._printLine(0, string, False, 3)

    def printFooter(self, string):
        """Prints string in the footer. footer's height = 1 row

            Args:
                string (str): the string to prints.
        """
        self._printLine(self.h - 1, string, False, 4)


class timespec(ctypes.Structure):
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
    clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

    t = timespec()

    if clock_gettime(CLOCK_MONOTONIC_RAW, ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec * 1e9 + t.tv_nsec


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
        prog = prog.replace("ACTIVATELATENCY", "#define LATENCY", 1)
    else:
        prog = prog.replace("ACTIVATELATENCY", "#undef LATENCY", 1)

    if syscall_list[0] == "all":
        prog = prog.replace("ACTIVATEALLSYSCALL", "#define TRACEPOINT", 1)
    else:
        prog = prog.replace("ACTIVATEALLSYSCALL", "#undef TRACEPOINT", 1)

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
            b.attach_kprobe(event=syscall_name, fn_name="do_enter_%s" % fname)
            b.attach_kprobe(event=syscall_name, fn_name="do_return_%s" % fname)
        except KeyboardInterrupt:
            display.printHeader("Exiting ...")
            display.reset()
            display.die = True  # will terminate the thread for keyboard
        except Exception:
            print("Failed to attach to kprobe %s" % syscall_name)


def run(display, b, pid_list, comm_list):
    """ Main loop. Sleep interval, then read the data from bpf map
    (b["map"]) and add it to the collection.
        Args:
            b(BPF object). This is the main object for defining a BPF program,
            and interacting with its output.
            pid_list (:obj:`list` of :obj:`str`) : list of pids you
            want to trace.
            comm_list (:obj:`list` of :obj:`str`) : list of process
            name you want to trace.
    """
    # clear to start collecting everything at the same time
    b["map"].clear()

    while display.die is False:
        try:
            sleep(display.refreshIntvl)
            now = monotonic_time()
            for k, v in b["map"].items():
                # map.clear() or item.__delitem__() are not thread safe !!
                # Unfortunatly we need to delete items in the map, it saves
                # entries in map.
                # delete items that are not active for more than 1 sec
                # by assuming old entries won't create consistency issues
                zeroed = False
                if v.startTime < int(now - INACT_THRSLD):
                    b["map"].__delitem__(k)
                    zeroed = True
                if ((k.pid != 0)
                    and (k.pid in pid_list
                         or -1 in pid_list)
                    and (k.comm in comm_list
                         or "all" in comm_list)):
                    if not k.fname:  # in case of a syscall fname is empty
                        k.fname = syscall_name(k.sysid)  # get fname
                    sc = stSysStats(k.fname, v.counter, v.cumLat)
                    # lookup the doc in the collection. If it does not exists
                    # then create it.
                    doc = display.collection.lookup_or_create(k.pid, k.comm)
                    # update the stats for this doc
                    doc.updatestSysStats(sc)
                    if zeroed is True:
                        doc.keep_previous_count(sc)

            display.printBody()
            # reset the rate for each doc in the collection
            display.collection.resetInfo()
        except KeyboardInterrupt:
            break

    display.printHeader("Exiting ...")
    display.reset()
    display.die = True  # will terminate the thread for keyboard


def main(display):
    """Main function.
        Args:
            display (TopDisplay) : object use to print in a 'top' like manner
    """
    global DEBUG
    parser = argparse.ArgumentParser(
        description="""display realtime view of the Linux syscalls.
         It uses eBPF to do the tracing""")
    parser.add_argument("-e", "--syscall",
                        help="the list of syscalls to trace "
                        "-e read,write,sendto",
                        default="all"
                        )
    parser.add_argument("-i", "--interval",
                        help="set the interval in sec",
                        default="1"
                        )
    parser.add_argument("-p", "--pid",
                        help="filter on pids"
                        "eg --pid 10001,10002,10003",
                        default="-1"
                        )
    parser.add_argument("-c", "--comm",
                        help="""filter on comm alias process name
                        --comm nginx,memcache,redis""",
                        default="all"
                        )
    parser.add_argument("-d", "--debug", help="print eBPF code",
                        action="store_true")

    parser.add_argument("-l", "--latency", help="display latency of func",
                        action="store_true")

    args = parser.parse_args()

    # get syscalls list
    syscall_list = args.syscall.split(",")

    # get pid list
    pid_list = args.pid.split(",")
    # turn list of string into list of int
    pid_list = map(int, pid_list)

    # get comm name list
    comm_list = args.comm.split(",")

    # set the latency
    latency = args.latency
    # set the debug global var
    DEBUG = args.debug
    display.setRefreshIntvl(float(args.interval))
    b = create_and_load_bpf(syscall_list, latency)

    if syscall_list[0] != "all":
        attach_syscall_to_kprobe(b, syscall_list)

    display.printHeader("Collecting first data ...")

    # Create a thread for the keyboard short key
    t = threading.Thread(target=display.readKey)
    t.start()
    run(display, b, pid_list, comm_list)
    t.join()


if __name__ == "__main__":
    try:
        st_coll = CtCollection()  # create a collection
        display = TopDisplay(st_coll)  # create the display of the collection
        main(display)
        display.die = True  # will terminate the thread for keyboard
    except Exception:
        display.printHeader("Exiting...")
        display.reset()
        display.die = True  # will terminate the thread for keyboard
        traceback.print_exc()
