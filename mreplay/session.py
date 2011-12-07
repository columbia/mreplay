import scribe
import unistd
import itertools

class Event(object):
    def __init__(self, scribe_event, proc=None):
        self._scribe_event = scribe_event
        self.proc = proc
        self.owners = dict()

    def __repr__(self):
        return repr(self._scribe_event)

    def __str__(self):
        return str(self._scribe_event)

    def next_event(self):
        if self.proc is None:
            return None
        try:
            return self.proc.events.after(self).next()
        except StopIteration:
            return None

    @property
    def children(self):
        # The children list is generated on the fly.
        # Only a syscall event gets to have some fun
        if self.proc is None:
            raise AttributeError
        if not self.is_a(scribe.EventSyscallExtra):
            return []
        return itertools.takewhile(
                lambda e: not e.is_a(scribe.EventSyscallEnd),
                self.proc.events.after(self))

    @property
    def syscall(self):
        return self._syscall
    @syscall.setter
    def syscall(self, value):
        self._syscall = value

    @property
    def syscall_index(self):
        if self.proc is None:
            raise AttributeError
        try:
            index = self.proc.syscalls.index(self)
        except ValueError:
            raise AttributeError
        return index

    @property
    def index(self):
        if self.proc is None:
            raise AttributeError
        try:
            index = self.proc.events.index(self)
        except ValueError:
            raise AttributeError
        return index

    @property
    def resource(self):
        return self._resource
    @resource.setter
    def resource(self, value):
        self._resource = value

    # Proxying attributes getters to the scribe event instance
    def __getattr__(self, name):
        return getattr(self._scribe_event, name)
    def is_a(self, klass):
        return isinstance(self._scribe_event, klass)

class EventList:
    def __init__(self):
        self._events = list()

    def __iter__(self):
        return iter(self._events)

    def __len__(self):
        return len(self._events)

    def __getitem__(self, index):
        return self._events[index]

    def append(self, e):
        e.owners[self] = len(self._events)
        self._events.append(e)

    def extend(self, el):
        for e in el:
            self.append(e)

    def index(self, e):
        try:
            return e.owners[self]
        except KeyError:
            raise ValueError('event not in list')

    def after(self, e):
        i = self.index(e)
        return (self[j] for j in xrange(i + 1, len(self)))

    def before(self, e):
        i = self.index(e)
        return (self[j] for j in xrange(i - 1, -1, -1))

    def sort(self, key):
        self._events.sort(key=key)
        self._indices_have_changed()

    def _indices_have_changed(self):
        # Called when the event list has been re-ordered, and the indices
        # need to be reset
        for i in xrange(0, len(self._events)):
            self._events[i].owners[self] = i

class Process:
    def __init__(self, pid, name=None):
        self.pid = pid
        self.name = name
        self.events = EventList()
        self.syscalls = EventList()

        # State for add_event()
        self.current_syscall = None

    def add_event(self, e):
        self.events.append(e)
        e.proc = self

        def check_execve(syscall):
            if syscall.nr != unistd.NR_execve:
                return
            if syscall.ret < 0:
                return
            for e in syscall.children:
                if not e.is_a(scribe.EventDataExtra):
                    continue
                if e.data_type != scribe.SCRIBE_DATA_INPUT | \
                                  scribe.SCRIBE_DATA_STRING:
                    continue
                self.name = e.data
                break

        if e.is_a(scribe.EventSyscallExtra):
            self.syscalls.append(e)
            self.current_syscall = e

        if self.current_syscall is not None:
            e.syscall = self.current_syscall

        if e.is_a(scribe.EventSyscallEnd):
            check_execve(self.current_syscall)
            self.current_syscall = None

    def __str__(self):
        return "pid=%d (%s)" % (self.pid, self.name if self.name else "??")

    def __repr__(self):
        return "<Process pid=%d name='%s' events=%d>" % \
                   (self.pid,
                    self.name if self.name else "??",
                    len(self.events))

class Session:
    def __init__(self, events):
        self.processes = dict()
        self.resources = dict()
        self.events = list()
        self._current_proc = None # State for add_event()

        self._add_events(events)

    def _add_events(self, events):
        for e in events:
            if isinstance(e, Event):
                self._add_event(e)
            else:
                assert isinstance(e, scribe.Event)
                self._add_event(Event(e))

    def _add_event(self, e):
        # the add_event() method is made private because we need to do extra
        # processing after an event is added (resource sorting, ...)

        self.events.append(e)

        if e.is_a(scribe.EventPid):
            if e.pid not in self.processes:
                self.processes[e.pid] = Process(pid=e.pid)

            self._current_proc = self.processes[e.pid]
            return

        if self._current_proc:
            self._current_proc.add_event(e)

    @property
    def init_proc(self):
        return self.processes[1]
