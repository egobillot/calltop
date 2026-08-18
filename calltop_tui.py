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
"""Textual user interface of calltop.

This module holds the whole *top like* interface. It does not import
bcc, so it can be imported (and tested) on any platform. Everything
that talks to eBPF is provided by the backend object given to
:class:`CallTopApp`. The backend only has to expose:

    sample(interval)  : read the eBPF maps and feed the collection
    attach_probe(pid) : attach USDT probes to a pid, returns (ok, msg)
    traced_pids       : the list of pids currently probed with USDT
"""

import threading

from rich.markup import escape
from rich.text import Text

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import (DataTable, Footer, Header, Input, Label,
                             Sparkline, Static)
from textual.worker import get_current_worker

# Glyphs used in the table header to show which column drives the sort.
# A filled triangle is the process (collection) sort, a hollow one is
# the function (stats) sort.
DOC_SORT_MARK = {True: '▼', False: '▲'}     # v / ^
STAT_SORT_MARK = {True: '▽', False: '△'}    # hollow v / ^

# Latency thresholds (in us) above which the latency cell gets colored.
LAT_WARN_US = 1000
LAT_ALERT_US = 10000


class Column:
    """Describe a column of the main table.

        Attributes:
            id (str): internal name, also used as the DataTable column key
            label (str): the text printed in the table header
            width (int): fixed width, None means auto sized
            justify (str): 'left' or 'right'
            doc_sortable (bool): the processes can be sorted on it
            stat_sortable (bool): the functions can be sorted on it
            desc (bool): default sort order, True means descending
            latency (bool): the column only makes sense when latency is on
    """

    def __init__(self, id, label, width=None, justify='right',
                 doc_sortable=False, stat_sortable=False, desc=True,
                 latency=False):
        self.id = id
        self.label = label
        self.width = width
        self.justify = justify
        self.doc_sortable = doc_sortable
        self.stat_sortable = stat_sortable
        self.desc = desc
        self.latency = latency


# The widths leave room for the sort markers appended to the labels : a
# column can carry both of them, ie 'Call/s ▼▽'.
COLUMNS = [
    Column('pid', 'Pid', width=7, doc_sortable=True, desc=False),
    Column('fname', 'Function', width=30, justify='left',
           stat_sortable=True, desc=False),
    Column('latency', 'Latency(us)', width=14,
           stat_sortable=True, latency=True),
    Column('total_lat', 'Intv.Lat(ms)', width=15,
           stat_sortable=True, latency=True),
    Column('rate', 'Call/s', width=12, doc_sortable=True, stat_sortable=True),
    Column('total', 'Total', width=13, doc_sortable=True, stat_sortable=True),
    Column('totaltime', 'Tot.Time(ms)', width=15, doc_sortable=True,
           stat_sortable=True, latency=True),
    Column('process', 'Process name', width=None, justify='left',
           doc_sortable=True, desc=False),
]

COLUMN_WIDTH = dict((c.id, c.width) for c in COLUMNS)


class CtFilter:
    """The dynamic filter of the display.

    It understands a comma separated list of 'key:value' where key is
    one of comm, pid, sys or fn. A bare value is understood as a comm
    filter. ie : 'sys:read,comm:nginx' or 'pid:1234,fn:my_func'.
    """

    def __init__(self):
        self.text = ''
        self.comm = b''
        self.sys = b''
        self.fn = b''
        self.pid = None
        self.error = ''

    def parse(self, text):
        """Build the filter out of the user input.

            Args:
                text (str): the raw filter typed by the user.
            Returns:
                error (str): empty when the filter could be parsed.
        """
        self.text = text
        self.comm = self.sys = self.fn = b''
        self.pid = None
        self.error = ''

        for item in text.split(','):
            item = item.strip()
            if not item:
                continue
            if item.startswith('sys:'):
                self.sys = item[len('sys:'):].encode()
            elif item.startswith('fn:'):
                self.fn = item[len('fn:'):].encode()
            elif item.startswith('comm:'):
                self.comm = item[len('comm:'):].encode()
            elif item.startswith('pid:'):
                raw = item[len('pid:'):]
                if not raw:
                    continue
                try:
                    self.pid = int(raw)
                except ValueError:
                    self.error = "'%s' is not a pid" % raw
            else:
                self.comm = item.encode()

        return self.error

    @property
    def is_active(self):
        return bool(self.comm or self.sys or self.fn or self.pid is not None)

    def match_doc(self, doc):
        """Tells whether a process has to be displayed."""
        if self.pid is not None and doc.pid != self.pid:
            return False
        if self.comm and (self.comm not in doc.comm and
                          self.comm not in doc.cmdline):
            return False
        return True

    def match_stat(self, stat):
        """Tells whether a syscall/function has to be displayed.

        Syscalls are named '[name]' and traced functions '{name}'. So
        'sys:' only matches syscalls and 'fn:' only matches functions.
        When both are given, the stat matches either of them.
        """
        if not self.sys and not self.fn:
            return True
        name = stat.name
        if self.sys and name.startswith(b'[') and self.sys in name:
            return True
        if self.fn and name.startswith(b'{') and self.fn in name:
            return True
        return False


def _decode(raw):
    """bytes coming from eBPF are not always valid utf-8."""
    if isinstance(raw, bytes):
        return raw.decode('utf-8', 'replace')
    return str(raw)


def _trunc(text, width):
    """Shorten a string, keeping the beginning."""
    if width and len(text) > width:
        return text[:width - 1] + '…'
    return text


def _fmt_us(value):
    """Format a duration expressed in us."""
    if value >= 100000:
        return '%.0f' % value
    if value >= 1000:
        return '%.1f' % value
    return '%.2f' % value


def _fmt_compact(value):
    """Shorten a number that does not fit in its column, so that it is
    never silently truncated.
    """
    for unit, factor in (('G', 1e9), ('M', 1e6), ('k', 1e3)):
        if abs(value) >= factor:
            return '%.1f%s' % (value / factor, unit)
    return '%.0f' % value


def _fit(text, value, width):
    return text if width is None or len(text) <= width \
        else _fmt_compact(value)


def _fmt_rate(value, width=None):
    if value and abs(value) < 10:
        return _fit('%.1f' % value, value, width)
    return _fit('{:,.0f}'.format(value), value, width)


def _fmt_count(value, width=None):
    return _fit('{:,d}'.format(int(value)), value, width)


def _fmt_ms(value, width=None):
    return _fit('{:,.0f}'.format(value), value, width)


class HelpScreen(ModalScreen):
    """The modal displayed when hitting '?'."""

    BINDINGS = [
        Binding('escape,q,question_mark,space,enter', 'dismiss',
                'Close', show=True),
    ]

    HELP = """[b]calltop[/b] - eBPF powered tracing tool

[b $accent]Moving around[/]
  [b]up/down[/]          move one line
  [b]pgup/pgdn[/]        move one page
  [b]home/end[/]         jump to the first / last line
  [b]enter[/]            show the details of the selected line
[b $accent]Sorting[/]
  [b]left/right[/]       sort the [b]processes[/] on the prev/next column ({doc})
  [b]< / >[/]            sort the [b]functions[/] on the prev/next column ({stat})
  [b]shift+left/right[/] scroll the table sideways
  [b]r / R[/]            reverse the process / function sort order
  [b]click[/]            sort on a column header, click it again to reverse
[b $accent]Tracing[/]
  [b]f[/]                filter, it is applied while you type, esc puts back
                   the previous one. ie [i]comm:nginx[/i], [i]pid:1234[/i],
                   [i]sys:read,comm:nginx[/i], [i]fn:my_func,pid:1234[/i]
  [b]t[/]                attach USDT probes to a pid (python/java/php/ruby).
                   The pid of the selected line is proposed by default.
  [b]z[/]                reset every counter
[b $accent]Display[/]
  [b]c[/]                toggle process name / full command line
  [b]d[/]                toggle the details panel
  [b]space[/]            pause / resume the sampling
  [b]+ / -[/]            increase / decrease the sampling interval
  [b]ctrl+p[/]           command palette (theme, ...)
  [b]q[/]                quit
"""

    def compose(self):
        doc = ' '.join(DOC_SORT_MARK.values())
        stat = ' '.join(STAT_SORT_MARK.values())
        box = VerticalScroll(id='help-box')
        box.can_focus = True
        box.border_subtitle = ' esc / q / ? to close '
        with box:
            yield Static(self.HELP.format(doc=doc, stat=stat), id='help-text')

    def on_mount(self):
        self.query_one('#help-box').focus()


class DetailPanel(Vertical):
    """Bottom panel with the details of the selected function."""

    # below that width the call rate graph is dropped, and the numbers
    # are printed in a single column.
    NARROW = 104

    def compose(self):
        yield Label('', id='detail-title')
        with Horizontal(id='detail-body'):
            yield Static('', id='detail-stats')
            with Vertical(id='detail-graph'):
                yield Label('call/s history', id='detail-graph-title')
                yield Sparkline([0], summary_function=max, id='detail-spark')

    def on_resize(self, event):
        self.set_class(event.size.width < self.NARROW, 'narrow')

    def update(self, doc, stat, interval):
        """Refresh the panel with the given process / function."""
        narrow = self.size.width < self.NARROW
        title = self.query_one('#detail-title', Label)
        stats = self.query_one('#detail-stats', Static)
        spark = self.query_one('#detail-spark', Sparkline)

        if doc is None or stat is None:
            title.update('no selection')
            stats.update('')
            spark.data = [0]
            return

        name = _decode(stat.name)
        title.update(Text.assemble(
            (name, 'bold'),
            ('  in  ', 'dim'),
            ('%s[%d]' % (_decode(doc.comm), doc.pid), 'bold')))

        # a Text is built rather than markup, the command line of a
        # process could contain square brackets.
        rate = _fmt_rate(stat.rps)
        latency = '%s us' % _fmt_us(stat.avg_lat / 1000)
        intvl_calls = _fmt_count(stat.cnt_per_intvl)
        intvl_time = '%.2f ms' % (stat.cum_lat_per_intvl / 1000000)
        total_calls = _fmt_count(stat.total)
        total_time = '{:,.1f} ms'.format(stat.cum_lat / 1000000)

        if narrow:      # no room for a second column, keep the essentials
            lines = [('call/s', rate, None, None),
                     ('latency', latency, None, None),
                     ('total calls', total_calls, None, None),
                     ('total time', total_time, None, None)]
        else:
            lines = [('call/s', rate, 'latency', latency),
                     ('calls/intvl', intvl_calls, 'time/intvl', intvl_time),
                     ('total calls', total_calls, 'total time', total_time),
                     ('samples', '%d' % stat.nb_sample,
                      'sampling', '%.1f s' % interval)]

        body = Text(no_wrap=True, overflow='ellipsis')
        body.append('cmdline'.ljust(13), style='dim')
        body.append(_trunc(_decode(doc.cmdline).strip(),
                           max(20, self.size.width - 15)) + '\n\n')
        for label, value, label2, value2 in lines:
            body.append(label.ljust(13), style='dim')
            body.append(value.rjust(13))
            if label2 is not None:
                body.append('     ')
                body.append(label2.ljust(13), style='dim')
                body.append(value2.rjust(13))
            body.append('\n')
        stats.update(body)

        history = list(stat.rate_history)
        spark.data = history if history else [0]


class CallTopApp(App):
    """The top like view of the collected syscalls / functions."""

    TITLE = 'calltop'
    SUB_TITLE = 'eBPF syscall and function tracing'

    CSS = """
    Screen {
        background: $surface;
    }
    #status {
        height: 1;
        background: $panel;
        color: $text;
        padding: 0 1;
    }
    #calls {
        height: 1fr;
        width: 100%;
    }
    #details {
        display: none;
        height: 10;
        border-top: solid $primary;
        padding: 0 1 1 1;
    }
    #details.visible {
        display: block;
    }
    #detail-title {
        height: 1;
        color: $accent;
    }
    #detail-body {
        height: 1fr;
    }
    #detail-stats {
        width: 1fr;
        height: 1fr;
    }
    #detail-graph {
        width: 40;
        height: 1fr;
        padding-left: 1;
    }
    #details.narrow #detail-graph {
        display: none;
    }
    #detail-graph-title {
        height: 1;
        color: $text-muted;
    }
    #detail-spark {
        height: 1fr;
    }
    #promptbar {
        display: none;
        height: 1;
        width: 100%;
        background: $panel;
    }
    #promptbar.visible {
        display: block;
    }
    #prompt-label {
        width: auto;
        padding: 0 1;
        color: $text;
        background: $accent;
    }
    #prompt {
        border: none;
        height: 1;
        width: 1fr;
        padding: 0 1;
        background: $panel;
    }
    #prompt-error {
        width: auto;
        padding: 0 1;
        color: $error;
    }
    HelpScreen {
        align: center middle;
        background: $background 60%;
    }
    #help-box {
        width: 86;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    #help-text {
        height: auto;
    }
    """

    BINDINGS = [
        Binding('q', 'quit', 'Quit'),
        Binding('f', 'filter', 'Filter'),
        Binding('t', 'trace', 'Trace pid'),
        Binding('z', 'reset', 'Reset'),
        Binding('c', 'toggle_cmdline', 'Cmdline'),
        Binding('d', 'toggle_details', 'Details'),
        Binding('space', 'toggle_pause', 'Pause'),
        Binding('question_mark', 'help', 'Help', key_display='?'),
        Binding('left', 'sort_doc(-1)', 'sort proc', show=False),
        Binding('right', 'sort_doc(1)', 'sort proc', show=False),
        Binding('less_than_sign', 'sort_stat(-1)', 'sort func', show=False),
        Binding('greater_than_sign', 'sort_stat(1)', 'sort func', show=False),
        Binding('r', 'reverse_doc', 'reverse proc sort', show=False),
        Binding('R', 'reverse_stat', 'reverse func sort', show=False),
        Binding('plus', 'interval(1)', 'slower', show=False),
        Binding('minus', 'interval(-1)', 'faster', show=False),
        Binding('shift+left', 'scroll_table(-1)', 'scroll left', show=False),
        Binding('shift+right', 'scroll_table(1)', 'scroll right', show=False),
        Binding('escape', 'cancel_prompt', 'cancel', show=False),
    ]

    def __init__(self, collection, backend, refresh_intvl=1.0, latency=True):
        """
            Args:
                collection (CtCollection): where the stats are stored
                backend: the object doing the eBPF work. See module doc.
                refresh_intvl (float): sampling interval in seconds
                latency (bool): False when started with --no-latency
        """
        super().__init__()
        self.collection = collection
        self.backend = backend
        self.refresh_intvl = refresh_intvl
        self.latency = latency

        self.columns = [c for c in COLUMNS if latency or not c.latency]
        self.doc_sort_id = 'total'
        self.stat_sort_id = 'fname'
        self.doc_order = dict((c.id, c.desc) for c in COLUMNS)
        self.stat_order = dict((c.id, c.desc) for c in COLUMNS)

        self.ct_filter = CtFilter()
        self.cmdline_mode = False
        self.paused = False
        self.details_on = False

        self._prompt_mode = None      # None, 'filter' or 'trace'
        self._filter_backup = ''
        self._column_keys = {}        # column id -> DataTable ColumnKey
        self._rows = {}               # row key -> (doc, stat)
        self._displayed_rate = 0.0
        self._displayed_procs = 0

        self._stop = threading.Event()
        self._wake = threading.Event()

    # ------------------------------------------------------------------
    # layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static('', id='status')
        yield DataTable(id='calls', zebra_stripes=True, cursor_type='row')
        yield DetailPanel(id='details')
        with Horizontal(id='promptbar'):
            yield Label('Filter:', id='prompt-label')
            yield Input(id='prompt')
            yield Label('', id='prompt-error')
        yield Footer()

    def on_mount(self):
        table = self.query_one('#calls', DataTable)
        for column in self.columns:
            self._column_keys[column.id] = table.add_column(
                Text(column.label, justify=column.justify),
                width=column.width, key=column.id)
        self._update_headers()
        table.focus()
        self._update_status('collecting first data …')
        self._sampler()

    def on_unmount(self):
        self._stop.set()
        self._wake.set()

    # ------------------------------------------------------------------
    # sampling
    # ------------------------------------------------------------------
    @work(thread=True, exclusive=True, group='sampler')
    def _sampler(self):
        """Read the eBPF maps every refresh_intvl, in a background thread."""
        worker = get_current_worker()
        while self._wait_next_sample(worker):
            if self.paused:
                continue
            try:
                self.backend.sample(self.refresh_intvl)
            except Exception as exc:      # keep the ui alive on map errors
                if not self._from_thread(worker, self.notify, str(exc),
                                         title='sampling error',
                                         severity='error'):
                    break
                continue
            # sorting and formatting is the expensive part, it is done
            # here so that the ui thread only has to fill the table.
            rows = self._build_rows()
            if not self._from_thread(worker, self.refresh_view, rows):
                break

    def _wait_next_sample(self, worker):
        """Sleep until the next sampling.

        The wait is sliced so that quitting is never delayed by a long
        sampling interval, and it restarts from scratch when the user
        changes the interval.

            Returns:
                False when the application is going away.
        """
        remaining = self.refresh_intvl
        while True:
            if worker.is_cancelled or self._stop.is_set():
                return False
            if remaining <= 0:
                return True
            if self._wake.wait(min(0.1, remaining)):
                self._wake.clear()
                remaining = self.refresh_intvl   # the interval has changed
            else:
                remaining -= 0.1

    def _from_thread(self, worker, callback, *args, **kwargs):
        """Run a callback in the ui thread. Returns False when the ui is
        not there anymore, which is the signal to stop sampling.
        """
        if worker.is_cancelled or self._stop.is_set():
            return False
        try:
            self.call_from_thread(callback, *args, **kwargs)
        except Exception:
            return False
        return True

    def refresh_view(self, rows=None):
        """Rebuild the table. Runs in the ui thread.

            Args:
                rows (list): the result of _build_rows(). When None the
                rows are built here, which is what the key handlers do
                when they change the sort or the filter.
        """
        try:
            table = self.query_one('#calls', DataTable)
        except NoMatches:       # the application is shutting down
            return
        previous_key = self._cursor_key(table)
        scroll_y = table.scroll_offset.y

        if rows is None:
            rows = self._build_rows()

        table.clear()
        self._rows = {}
        for key, cells, item in rows:
            self._rows[key] = item
            table.add_row(*cells, key=key)

        if previous_key is not None and previous_key in table.rows:
            index = table.get_row_index(previous_key)
            table.move_cursor(row=index, animate=False)
            page = max(1, table.size.height - 1)
            if not scroll_y <= index < scroll_y + page:
                scroll_y = max(0, index - page // 2)
        table.scroll_to(y=scroll_y, animate=False, force=True)

        self._update_status()
        if self.details_on:
            self._update_details()

    def _build_rows(self):
        """Sort and format everything that has to be displayed. It only
        reads the collection, so it can be called from the sampling
        thread as well as from the ui one.

            Returns:
                a list of (row key, cells, (doc, stat))
        """
        rows = []
        rate = 0.0
        procs = 0
        docs = sorted(filter(self.ct_filter.match_doc,
                             list(self.collection.doctionary.values())),
                      key=self._doc_sort_key,
                      reverse=self.doc_order[self.doc_sort_id])

        for doc in docs:
            stats = sorted(filter(self.ct_filter.match_stat,
                                  list(doc.ct_stat_list)),
                           key=self._stat_sort_key,
                           reverse=self.stat_order[self.stat_sort_id])
            if not stats:
                continue
            procs += 1
            first = True
            for stat in stats:
                rate += stat.rps
                rows.append((
                    # repr of the bytes, so that two different names
                    # can never end up with the same row key
                    '%d|%r|%r' % (doc.pid, doc.comm, stat.name),
                    self._format_row(doc, stat, first),
                    (doc, stat)))
                first = False

        self._displayed_rate = rate
        self._displayed_procs = procs
        return rows

    def _format_row(self, doc, stat, first):
        """Build the cells of one line. pid and process name are only
        printed on the first line of a process, so that the functions of
        a process are visually grouped.
        """
        name = _decode(stat.name)
        if name.startswith('{'):        # a traced function, not a syscall
            fname = Text(_trunc(name, COLUMN_WIDTH['fname']), style='cyan')
        else:
            fname = Text(_trunc(name, COLUMN_WIDTH['fname']))

        if first:
            pid = Text('%d' % doc.pid, style='bold', justify='right')
            comm = _decode(doc.cmdline if self.cmdline_mode else doc.comm)
            process = Text(_trunc(comm.strip(), 120), style='bold')
        else:
            pid = Text('')
            process = Text('')

        latency_us = stat.avg_lat / 1000
        if latency_us >= LAT_ALERT_US:
            lat_style = 'bold red'
        elif latency_us >= LAT_WARN_US:
            lat_style = 'yellow'
        else:
            lat_style = ''

        values = {
            'pid': pid,
            'fname': fname,
            'latency': Text(_fit(_fmt_us(latency_us), latency_us,
                                 COLUMN_WIDTH['latency']),
                            style=lat_style, justify='right'),
            'total_lat': Text(_fit('%.2f' % (stat.cum_lat_per_intvl / 1e6),
                                   stat.cum_lat_per_intvl / 1e6,
                                   COLUMN_WIDTH['total_lat']),
                              justify='right'),
            'rate': Text(_fmt_rate(stat.rps, COLUMN_WIDTH['rate']),
                         justify='right'),
            'total': Text(_fmt_count(stat.total, COLUMN_WIDTH['total']),
                          justify='right'),
            'totaltime': Text(_fmt_ms(stat.cum_lat / 1e6,
                                      COLUMN_WIDTH['totaltime']),
                              justify='right'),
            'process': process,
        }
        return [values[column.id] for column in self.columns]

    # ------------------------------------------------------------------
    # sorting
    # ------------------------------------------------------------------
    def _doc_sort_key(self, doc):
        sort_id = self.doc_sort_id
        if sort_id == 'pid':
            return doc.pid
        if sort_id == 'process':
            return doc.comm.lower()
        if sort_id == 'rate':
            return doc.total_func_cnt_per_intvl
        if sort_id == 'totaltime':
            return doc.total_func_time
        return doc.total_func_cnt

    def _stat_sort_key(self, stat):
        sort_id = self.stat_sort_id
        if sort_id == 'rate':
            return stat.rps
        if sort_id == 'total':
            return stat.total
        if sort_id == 'latency':
            return stat.avg_lat
        if sort_id == 'total_lat':
            return stat.cum_lat_per_intvl
        if sort_id == 'totaltime':
            return stat.cum_lat
        return stat.name.lower()

    def _shift_sort(self, sort_id, shift, attr):
        """Return the id of the next sortable column, in the direction
        given by shift (+1 right, -1 left).
        """
        sortable = [c for c in self.columns if getattr(c, attr)]
        if not sortable:
            return sort_id
        ids = [c.id for c in sortable]
        try:
            index = ids.index(sort_id)
        except ValueError:
            return ids[0]
        return ids[(index + shift) % len(ids)]

    def action_sort_doc(self, shift):
        self.doc_sort_id = self._shift_sort(self.doc_sort_id, shift,
                                            'doc_sortable')
        self._update_headers()
        self.refresh_view()

    def action_sort_stat(self, shift):
        self.stat_sort_id = self._shift_sort(self.stat_sort_id, shift,
                                             'stat_sortable')
        self._update_headers()
        self.refresh_view()

    def action_scroll_table(self, direction):
        """Scroll the table sideways, the left and right keys are used
        to change the sort column.
        """
        table = self.query_one('#calls', DataTable)
        table.scroll_relative(x=direction * 12, animate=False)

    def action_reverse_doc(self):
        self.doc_order[self.doc_sort_id] = not self.doc_order[self.doc_sort_id]
        self._update_headers()
        self.refresh_view()

    def action_reverse_stat(self):
        order = self.stat_order
        order[self.stat_sort_id] = not order[self.stat_sort_id]
        self._update_headers()
        self.refresh_view()

    def on_data_table_header_selected(self, event):
        """Sort when a column header is clicked. Clicking the column
        already used for the sort reverses the order.
        """
        column_id = event.column_key.value
        column = self._column(column_id)
        if column is None:
            return
        changed = False
        if column.doc_sortable:
            if self.doc_sort_id == column_id:
                self.doc_order[column_id] = not self.doc_order[column_id]
            else:
                self.doc_sort_id = column_id
            changed = True
        if column.stat_sortable:
            if self.stat_sort_id == column_id:
                self.stat_order[column_id] = not self.stat_order[column_id]
            else:
                self.stat_sort_id = column_id
            changed = True
        if changed:
            self._update_headers()
            self.refresh_view()

    def _column(self, column_id):
        for column in self.columns:
            if column.id == column_id:
                return column
        return None

    def _update_headers(self):
        """Print the sort markers in the table header."""
        table = self.query_one('#calls', DataTable)
        for column in self.columns:
            marks = ''
            if column.id == self.doc_sort_id:
                marks += DOC_SORT_MARK[self.doc_order[column.id]]
            if column.id == self.stat_sort_id:
                marks += STAT_SORT_MARK[self.stat_order[column.id]]
            label = Text(column.label, justify=column.justify)
            if marks:
                label.append(' ' + marks, style='bold')
            table.columns[self._column_keys[column.id]].label = label
        table.refresh()

    # ------------------------------------------------------------------
    # status bar
    # ------------------------------------------------------------------
    def _update_status(self, message=None):
        try:
            status = self.query_one('#status', Static)
        except NoMatches:       # the application is shutting down
            return
        if message is not None:
            status.update(message)
            return

        traced = len(self.backend.traced_pids)
        parts = [
            '[b]%.1fs[/]' % self.refresh_intvl,
            '[dim]proc[/] [b]%d[/]' % self._displayed_procs,
            '[dim]lines[/] [b]%d[/]' % len(self._rows),
            '[dim]call/s[/] [b]%s[/]' % _fmt_rate(self._displayed_rate),
        ]
        if traced:
            parts.append('[dim]usdt[/] [b]%d[/]' % traced)
        if self.ct_filter.is_active:
            parts.append('[dim]filter[/] [b $accent]%s[/]'
                         % escape(self.ct_filter.text))
        if self.cmdline_mode:
            parts.append('[dim]cmdline[/]')
        if self.paused:
            parts.append('[b $warning]PAUSED[/]')
        parts.append('[dim]sort[/] %s [b]%s[/] %s [b]%s[/]' % (
            DOC_SORT_MARK[self.doc_order[self.doc_sort_id]],
            self._column(self.doc_sort_id).label,
            STAT_SORT_MARK[self.stat_order[self.stat_sort_id]],
            self._column(self.stat_sort_id).label))
        status.update('  '.join(parts))

    # ------------------------------------------------------------------
    # details panel
    # ------------------------------------------------------------------
    def _cursor_key(self, table):
        """The key of the row under the cursor, None when the table is
        empty.
        """
        try:
            cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
        except Exception:
            return None
        return cell_key.row_key.value

    def _update_details(self):
        table = self.query_one('#calls', DataTable)
        doc, stat = self._rows.get(self._cursor_key(table), (None, None))
        self.query_one('#details', DetailPanel).update(doc, stat,
                                                       self.refresh_intvl)

    def on_data_table_row_highlighted(self, event):
        if self.details_on:
            self._update_details()

    def on_data_table_row_selected(self, event):
        if not self.details_on:
            self.action_toggle_details()

    def action_toggle_details(self):
        self.details_on = not self.details_on
        self.query_one('#details', DetailPanel).set_class(self.details_on,
                                                          'visible')
        if self.details_on:
            self._update_details()

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def action_help(self):
        self.push_screen(HelpScreen())

    def action_toggle_cmdline(self):
        self.cmdline_mode = not self.cmdline_mode
        self.refresh_view()

    def action_toggle_pause(self):
        self.paused = not self.paused
        self._update_status()

    def action_reset(self):
        """Zero the counters of the collection.

        TODO the eBPF maps are not cleared, so the counters that are
        still in them come back at the next sampling. Clearing a map is
        not atomic, hence the entries are only removed once they have
        been idle for a while, see CtBackend.sample().
        """
        self.collection.drop()
        self._rows = {}
        table = self.query_one('#calls', DataTable)
        table.clear()
        self._update_status()
        self.notify('counters have been reset', timeout=2)

    def action_interval(self, direction):
        """Increase or decrease the sampling interval. Below 1s the step
        is 0.1s, above it is 1s.
        """
        intvl = self.refresh_intvl
        if intvl >= 1 and direction > 0:
            intvl = int(intvl) + 1
        elif intvl > 1:
            intvl = int(intvl) - 1
        else:
            intvl = round(intvl + direction * 0.1, 1)
        self.refresh_intvl = max(intvl, 0.1)
        self._wake.set()          # restart the wait with the new interval
        self._update_status()

    # ------------------------------------------------------------------
    # filter and usdt prompt
    # ------------------------------------------------------------------
    def _open_prompt(self, mode, label, value, placeholder, restrict=None,
                     select_all=False):
        """Show the input line at the bottom of the screen.

            Args:
                mode (str): 'filter' or 'trace'
                label (str): what is printed on the left of the input
                value (str): the value the input starts with
                placeholder (str): the hint shown on an empty input
                restrict (str): a regexp limiting what can be typed
                select_all (bool): select the proposed value, so that
                typing replaces it instead of appending to it.
        """
        self._prompt_mode = mode
        prompt = self.query_one('#prompt', Input)
        prompt.restrict = restrict
        prompt.placeholder = placeholder
        prompt.select_on_focus = select_all
        self.query_one('#prompt-label', Label).update(label)
        self.query_one('#prompt-error', Label).update('')
        self.query_one('#promptbar').add_class('visible')
        self.query_one(Footer).display = False
        prompt.value = value
        prompt.focus()
        if not select_all:
            try:
                prompt.cursor_position = len(value)
            except AttributeError:
                pass

    def _close_prompt(self):
        self._prompt_mode = None
        self.query_one('#promptbar').remove_class('visible')
        self.query_one(Footer).display = True
        self.query_one('#calls', DataTable).focus()

    def action_filter(self):
        self._filter_backup = self.ct_filter.text
        self._open_prompt(
            'filter', 'Filter:', self.ct_filter.text,
            'comm:nginx,sys:read,fn:my_func,pid:1234 - '
            'enter to apply, esc to cancel')

    def action_trace(self):
        table = self.query_one('#calls', DataTable)
        doc, _ = self._rows.get(self._cursor_key(table), (None, None))
        self._open_prompt(
            'trace', 'Trace pid:', '%d' % doc.pid if doc else '',
            'pid of a python/java/php/ruby process - '
            'enter to attach, esc to cancel',
            restrict=r'[0-9]*', select_all=True)

    def action_cancel_prompt(self):
        if self._prompt_mode is None:
            return
        if self._prompt_mode == 'filter':
            # the filter is applied while typing, so put back the old one
            self.ct_filter.parse(self._filter_backup)
            self.refresh_view()
        self._close_prompt()

    def on_input_changed(self, event):
        """The filter is applied while it is typed."""
        if self._prompt_mode != 'filter':
            return
        error = self.ct_filter.parse(event.value)
        self.query_one('#prompt-error', Label).update(error)
        self.refresh_view()

    def on_input_submitted(self, event):
        mode = self._prompt_mode
        value = event.value.strip()
        self._close_prompt()
        if mode == 'filter':
            error = self.ct_filter.parse(value)
            if error:
                self.notify(error, title='filter', severity='warning')
            self.refresh_view()
        elif mode == 'trace' and value:
            self.notify('attaching probes to pid %s …' % value,
                        timeout=3)
            self._attach_probe(int(value))

    @work(thread=True)
    def _attach_probe(self, pid):
        """Attaching USDT probes compiles a bpf program, it takes a
        while, so do it out of the ui thread.
        """
        try:
            ok, message = self.backend.attach_probe(pid)
        except Exception as exc:
            ok, message = False, str(exc)
        self.call_from_thread(
            self.notify, message, title='pid %d' % pid,
            severity='information' if ok else 'warning')
        self.call_from_thread(self._update_status)
