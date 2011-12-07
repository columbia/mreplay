from nose.tools import *
from mreplay.mutator import *
from mreplay.session import *
from mreplay.location import *
from mreplay.unistd import *
from mreplay.mutator.location_matcher import *

class ToStr(Mutator):
    def process_events(self, events):
        for event in events:
            yield str(event)

class RemoveEventPid(Mutator):
    def process_events(self, events):
        for event in events:
            if not event.is_a(scribe.EventPid):
                yield event

def test_base_class():
    out = ToStr().process_events([1,2,3])
    assert_equal(list(out), ['1','2','3'])

def test_replace():
    out = Replace({1:5, 3:8}).process_events([1,2,3])
    assert_equal(list(out), [5,2,8])

def test_pipe():
    out = [1,2,3] | Replace({1:3}) | Replace({3:5}) | ToStr()
    assert_equal(list(out), ['5','2','5'])

def test_adjust_resources():
    # The tests were written at some point. Where are they ?
    pass

def test_insert_pid_events():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventPid(pid=2),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]
    out = Session(events).events | InsertPidEvents() | ToRawEvents()
    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]

    assert_equal(list(out), should_be)

def test_insert_eoq_events():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]
    out = Session(events).events | InsertEoqEvents() | \
                                   InsertPidEvents() | ToRawEvents()
    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
               scribe.EventPid(pid=1),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventQueueEof(),
             ]

    assert_equal(list(out), should_be)

def test_cat_session():
    events = [
               scribe.EventInit(),                            # 0
               scribe.EventPid(pid=1),                        # 1
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 2
               scribe.EventSyscallExtra(nr=NR_wait4, ret=2),  # 3
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 4
               scribe.EventPid(pid=2),                        # 5
               scribe.EventSyscallExtra(nr=NR_read,  ret=0),  # 6
               scribe.EventFence(),                           # 7
               scribe.EventSyscallEnd(),                      # 8
               scribe.EventFence(),                           # 9
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 10
               scribe.EventPid(pid=1),                        # 11
               scribe.EventFence(),                           # 12
             ]

    s = Session(events)
    e = list(s.events)

    out = CatSession(s)

    should_be = [
                  e[0],
                  e[2],
                  e[3],
                  e[4],
                  e[12],
                  e[6],
                  e[7],
                  e[8],
                  e[9],
                  e[10],
               ]

    assert_equal(list(out), should_be)

    out = s | Nop() # Piping a graph directly should work too
    assert_equal(list(out), should_be)


def test_location_matcher():
    events = [
               scribe.EventPid(pid=1),     # 0
               scribe.EventFence(),        # 1
               scribe.EventSyscallExtra(), # 2
               scribe.EventFence(),        # 3
               scribe.EventSyscallEnd(),   # 4
               scribe.EventSyscallExtra(), # 5
               scribe.EventSyscallEnd(),   # 6
               scribe.EventFence(),        # 7
             ]
    s = Session(events)
    e = list(s.events)
    p = s.processes

    def match(l1, e2):
        return LocationMatcher(Location(l1[0], l1[1])).match(e2)

    #assert_equal(match((e[1], 'before'), e[1]), 'before')
    #assert_equal(match((e[1], 'after'),  e[2]), 'after')

    #assert_equal(match((e[2], 'before'), e[2]), 'before')
    #assert_equal(match((e[2], 'after'),  e[3]), None)
    #assert_equal(match((e[2], 'after'),  e[5]), 'after')


    assert_equal(match((Event(Start(), p[1]), 'after'), e[1]), 'after')
    #assert_equal(match((e[7],               'after'), p[1].last_anchor), 'after')
    #assert_equal(match((Event(End(), p[1]),   'after'), p[1].last_anchor), 'after')


def test_truncate_queue():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
               scribe.EventPid(pid=3),   # 5
               scribe.EventFence(),      # 6
               scribe.EventFence(),      # 7
               scribe.EventPid(pid=1),   # 8
               scribe.EventFence(),      # 9
               scribe.EventFence(),      # 10
               scribe.EventPid(pid=2),   # 11
               scribe.EventFence(),      # 12
             ]
    s = Session(events)
    e = list(s.events)
    out = e | TruncateQueue([ Location(e[1], 'after'),
                              Location(e[2], 'after'),
                              Location(e[12], 'before') ]) \
            | RemoveEventPid() \
            | ToRawEvents()

    assert_equal(list(out), list([e[1], e[4], e[6], e[7]] | ToRawEvents()))


def test_truncate_queue_atom():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
             ]

    s = Session(events)
    e = list(s.events)
    out = e | TruncateQueue( Location(e[1], 'after') ) \
            | RemoveEventPid() \
            | ToRawEvents()

    assert_equal(list(out), list([e[1], e[4]] | ToRawEvents()))

def test_bookmark_ids():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
               scribe.EventBookmark(id=0, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL), # 5
             ]

    s = Session(events)
    e = list(s.events)

    out = e | Bookmark([Location(e[1], 'after')]) \
            | Bookmark([Location(e[4], 'before')]) \
            | InsertPidEvents() \
            | ToRawEvents()

    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventBookmark(id=0, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventBookmark(id=1, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_PRE_SYSCALL),
               scribe.EventFence(),
                ]

    assert_equal(list(out), should_be)

def test_bookmark_npr():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
             ]

    s = Session(events)
    e = list(s.events)
    p = s.processes

    p[1].first_anchor = p[1].last_anchor = None
    p[2].first_anchor = p[2].last_anchor = None

    out = e | Bookmark([Location(e[1], 'after'),
                        Location(e[4], 'before')]) \
            | InsertPidEvents() \
            | ToRawEvents()

    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventBookmark(id=0, npr=2,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventBookmark(id=0, npr=2,
                      type=scribe.SCRIBE_BOOKMARK_PRE_SYSCALL),
               scribe.EventFence(),
                ]

    assert_equal(list(out), should_be)

def test_bookmark_same_location():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
             ]

    s = Session(events)
    e = list(s.events)
    p = s.processes

    p[1].first_anchor = p[1].last_anchor = None
    p[2].first_anchor = p[2].last_anchor = None

    out = e | Bookmark([Location(e[1], 'after')]) \
            | Bookmark([Location(e[1], 'after')]) \
            | Bookmark([Location(e[2], 'before')]) \
            | Bookmark([Location(e[2], 'before')]) \
            | InsertPidEvents() \
            | ToRawEvents()

    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventBookmark(id=0, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL),
               scribe.EventBookmark(id=1, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL),
               scribe.EventBookmark(id=2, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_PRE_SYSCALL),
               scribe.EventBookmark(id=3, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_PRE_SYSCALL),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
                ]

    assert_equal(list(out), should_be)


def test_to_raw_events():
    events = [
               scribe.EventInit(),                            # 0
               scribe.EventPid(pid=1),                        # 1
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 2
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 3
               scribe.EventPid(pid=2),                        # 4
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 5
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 6
             ]


    s = Session(events)
    out = s | InsertPidEvents() | ToRawEvents()
    assert_equal(list(out), events)

def test_bookmark_and_truncate():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
             ]

    s = Session(events)
    e = list(s.events)
    p = s.processes

    out = e | Bookmark([Location(Event(Start(), p[1]), 'after')]) \
            | TruncateQueue([Location(Event(Start(), p[1]), 'after')]) \
            | InsertPidEvents() \
            | ToRawEvents()

    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventBookmark(id=0, npr=1,
                      type=scribe.SCRIBE_BOOKMARK_POST_SYSCALL),
                ]

    assert_equal(list(out), should_be)
