from nose.tools import *
from mreplay.session import *
from mreplay.unistd import *

def test_event_str():
    e = Event(scribe.EventRegs())
    assert_equal(repr(e), repr(scribe.EventRegs()))
    assert_equal(str(e), str(scribe.EventRegs()))

def test_event_encode():
    e = Event(scribe.EventRegs())
    assert_equal(e.encode(), scribe.EventRegs().encode())

def test_event_attr():
    e = Event(scribe.EventSyscallExtra(nr = 3))
    assert_equal(e.nr, 3)
    e = Event(scribe.EventResourceLockExtra(id = 3))
    assert_equal(e.id, 3)

def test_event_is():
    e = Event(scribe.EventSyscallExtra(nr = 3))
    assert_true(e.is_a(scribe.EventSyscallExtra))
    assert_false(e.is_a(scribe.EventResourceLockExtra))

def test_event_list():
    e1 = Event(scribe.EventRegs())
    e2 = Event(scribe.EventRegs())
    e3 = Event(scribe.EventRegs())

    el1 = EventList()
    el1.append(e1)
    el1.append(e2)
    el1.append(e3)

    el2 = EventList()
    el2.append(e2)
    el2.append(e3)

    el3 = EventList()
    el3.append(e2)

    assert_equal(list(el1), [e1, e2, e3])
    assert_equal(list(el2), [e2, e3])
    assert_equal(list(el3), [e2])

    assert_equal(list(el1.after(e1)), [e2, e3])
    assert_equal(list(el3.after(e2)), [])

    assert_equal(list(el1.before(e2)), [e1])
    assert_equal(list(el1.before(e3)), [e2, e1])
    assert_equal(list(el2.before(e2)), [])

    assert_equal(el1.index(e2), 1)
    assert_equal(el2.index(e2), 0)
    assert_equal(el3.index(e2), 0)
    assert_raises(ValueError, el3.index, e3)

    assert_equal(el1[0], e1)
    assert_equal(el1[-1], e3)

    assert_raises(ValueError, el3.after, e1)

    el1.extend(el2)
    assert_equal(list(el1), [e1, e2, e3, e2, e3])


def test_event_doesnt_belong_to_proc_by_default():
    e = Event(scribe.EventRegs())
    assert_equal(e.proc, None)

def test_event_can_belong_to_a_proc_on_creation():
    e = Event(scribe.EventRegs(), "proc")
    assert_equal(e.proc, "proc")

def test_add_proc_events_sets_event_proc():
    proc = Process(pid=1)
    e = Event(scribe.EventRegs())
    proc.add_event(e)
    assert_equal(e.proc, proc)

def test_event_no_proc():
    e = Event(scribe.EventSyscallExtra(1))
    def get_children(e):
        return e.children
    assert_raises(AttributeError, get_children, e)

def test_process_syscall():
    events = [ scribe.EventFence(),             # 0
               scribe.EventSyscallExtra(1),     # 1
               scribe.EventRegs(),              # 2
               scribe.EventSyscallEnd(),        # 3
               scribe.EventRdtsc(),             # 4
               scribe.EventSyscallExtra(2),     # 5
               scribe.EventData('hello'),       # 6
               scribe.EventData('world'),       # 7
               scribe.EventSyscallEnd(),        # 8
               scribe.EventSyscallExtra(3),     # 9
               scribe.EventSyscallEnd() ]       # 10
    events = map(lambda se: Event(se), events)

    proc = Process(pid=1)
    for event in events:
        proc.add_event(event)

    proc_events = list(proc.events)
    assert_equal(len(proc_events), 11)

    assert_equal(list(proc_events[1].children), [events[2]])
    assert_equal(list(proc_events[5].children), [events[6], events[7]])
    assert_equal(list(proc_events[9].children), [])

    assert_equal(list(proc_events[6].children), [])

    def get_syscall(e):
        return e.syscall
    assert_raises(AttributeError, get_syscall, events[0])
    assert_raises(AttributeError, get_syscall, events[4])

    assert_equal(events[1].syscall, events[1])
    assert_equal(events[2].syscall, events[1])
    assert_equal(events[6].syscall, events[5])
    assert_equal(events[7].syscall, events[5])

    def get_syscall_index(e):
        return e.syscall_index
    assert_raises(AttributeError, get_syscall_index, events[0])
    assert_raises(AttributeError, get_syscall_index, events[6])

    assert_equal(events[1].syscall_index, 0)
    assert_equal(events[5].syscall_index, 1)
    assert_equal(events[9].syscall_index, 2)

    assert_equal(list(proc.syscalls), [events[1], events[5], events[9]])


def test_process_name():
    events = [ scribe.EventSyscallExtra(nr=unistd.NR_execve, ret=0),
               scribe.EventFence(),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT,
                                     data = 'bad'),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'cmd1'),
               scribe.EventFence(),
               scribe.EventSyscallEnd(),

               scribe.EventSyscallExtra(nr=unistd.NR_execve, ret=0),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'cmd2'),
               scribe.EventFence(),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'bad'),
               scribe.EventFence(),
               scribe.EventSyscallEnd() ]

    proc = Process(pid=1)
    assert_equal(proc.name, None)

    for event in events:
        proc.add_event(Event(event))
    assert_equal(proc.name, 'cmd2')

    events[6].ret = -1 # if execve() < 0, it should not process the name
    proc = Process(pid=1)
    for event in events:
        proc.add_event(Event(event))
    assert_equal(proc.name, 'cmd1')

def test_process_str():
    proc = Process(pid=1, name='cmd')
    assert_equal(str(proc), 'pid=1 (cmd)')

    proc = Process(pid=1)
    assert_equal(str(proc), 'pid=1 (??)')

def test_process_repr():
    proc = Process(pid=1, name='cmd')
    proc.add_event(Event(scribe.EventFence()))
    proc.add_event(Event(scribe.EventSyscallExtra()))

    assert_equal(repr(proc), "<Process pid=1 name='cmd' events=2>")

def test_session_events():
    events = [ scribe.EventFence(), scribe.EventRegs() ]

    session = Session(events)
    assert_equal(len(session.events), 2)
    assert_true(isinstance(session.events[0], Event))

    session = Session(map(lambda se: Event(se), events))
    assert_equal(len(session.events), 2)
    assert_true(isinstance(session.events[0], Event))

def test_process_pid():
    events = [ scribe.EventFence(),             # 0
               scribe.EventPid(pid=1),          # 1
               scribe.EventRdtsc(),             # 2
               scribe.EventSyscallExtra(2),     # 3
               scribe.EventPid(pid=2),          # 4
               scribe.EventRdtsc(),             # 5
               scribe.EventPid(pid=1),          # 6
               scribe.EventPid(pid=2),          # 7
               scribe.EventPid(pid=1),          # 8
               scribe.EventData('hello'),       # 9
               scribe.EventSyscallEnd() ]       # 10

    session = Session(events)
    events = list(session.events)

    assert_equal(len(events), 11)
    assert_equal(len(session.processes), 2)
    assert_equal(session.processes[1].pid, 1)
    assert_equal(session.processes[2].pid, 2)
    assert_equal(list(session.processes[1].events), [events[2], events[3],
                                                     events[9], events[10]])
    assert_equal(list(session.processes[2].events), [events[5]])

    assert_equal(session.processes[1], session.init_proc)
