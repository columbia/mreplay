import itertools
from location import Location
from mreplay.session import Event
import scribe
import struct
import mutator
from mreplay.explorer import Execution, ExecutionStates

# TODO: move to utils?
def head(seq, n=1):
    iterator = iter(seq)
    for i in xrange(n):
        yield iterator.next()


def is_data(event):
    return event.is_a(scribe.EventDataExtra) or \
           event.is_a(scribe.EventData)

def is_data_extra(event):
    return event.is_a(scribe.EventDataExtra)

def is_string_data(event):
    if not is_data_extra(event):
        return False
    return event.data_type == scribe.SCRIBE_DATA_INPUT | \
                              scribe.SCRIBE_DATA_STRING

class DivergeHandler:
    def __init__(self, execution, diverge_event, mutations):
        self.execution = execution
        self.explorer = execution.explorer
        self.diverge_event = diverge_event
        self.mutations = list(mutations)
        self.status = "unknown"

        self.extract_culprit()

    def extract_culprit(self):
        num = self.diverge_event.num_ev_consumed - 1
        if not self.diverge_event.fatal:
            if isinstance(self.diverge_event, scribe.EventDivergeSyscall):
                num += 1
            if isinstance(self.diverge_event, scribe.EventDivergeMemOwned):
                num += 1
        if isinstance(self.diverge_event, scribe.EventDivergeDataContent):
            num += 1

        self.pid = self.diverge_event.pid
        self.execution.update_progress(self.pid, num)
        self.execution.state = ExecutionStates.FAILED
        self.proc = self.execution.running_session.processes[self.pid]
        self.culprit = self.proc.events[num]
        self.mutations = map(lambda e: Event(e, self.proc), self.mutations)

        assert self.culprit.index == num

        try:
            self.syscall = self.culprit.syscall
        except AttributeError:
            self.syscall = None

    def get_diverge_str(self):
        if self.diverge_event.fatal:
            diverge_str = "diverged (%s)" % (self.diverge_event)
        else:
            diverge_str = "mutating (%s)" % (self.diverge_event)

        diverge_str = "pid=%d \033[1;33m%s at %s\033[m" % (self.pid, diverge_str, self.culprit)

        if self.syscall is not None and self.syscall != self.culprit:
            diverge_str = "%s in %s" % (diverge_str, self.syscall)

        return diverge_str

    def is_allowed_event(self, event_str):
        pattern = self.execution.get_user_pattern()
        return pattern is None or pattern == event_str

    def add_event(self, event, add_event, add_location=None, fly_state=None):
        if not self.is_allowed_event('+'):
            return

        if not add_location:
            add_location = Location(event, 'before')

        add_events = [Event(add_event, event.proc)]
        if self.diverge_event.fatal or fly_state == ExecutionStates.TODO or \
                self.execution.depth_otf > self.explorer.max_otf:
            add_events.append(Event(scribe.EventNop(scribe.EventSyscallEnd().encode()), event.proc))
            self.explorer.add_execution(self.execution,
                Execution(self.execution,
                mutator.InsertEvent(add_location, add_events),
                mutation_index=event.index+len(add_events), fly_offset_delta=0,
                mutation_pid=self.diverge_event.pid))
        else:
            if fly_state is None:
                fly_state = ExecutionStates.RUNNING
            add_events.extend([Event(scribe.EventNop(e.encode()), event.proc)
                                for e in self.mutations[1:]])
            self.explorer.add_execution(self.execution,
                Execution(self.execution,
                mutator.InsertEvent(add_location, add_events),
                state=fly_state, running_session=self.execution.running_session,
                mutation_index=event.index, fly_offset_delta=len(add_events),
                mutation_pid=self.diverge_event.pid))

    def replace_event(self, original, new):
        if not self.is_allowed_event('r'):
            return

        new = Event(new, self.proc)
        if self.diverge_event.fatal or self.execution.depth_otf > self.explorer.max_otf:
            print("Replacing: (%s) with (%s)" % (str(original), str(new)))
            self.explorer.add_execution(self.execution,
                    Execution(self.execution,
                mutator.Replace({original: new}),
                mutation_index=original.index, fly_offset_delta=0,
                mutation_pid=self.pid))
        else:
            self.explorer.add_execution(self.execution,
                Execution(self.execution, mutator.Replace({original: new}),
                state=ExecutionStates.RUNNING, running_session=self.execution.running_session,
                mutation_index=original.index, fly_offset_delta=0,
                mutation_pid=self.pid))

    def delete_event(self, events):
        if not self.is_allowed_event('-'):
            return

        if events is None:
            return

        self.explorer.add_execution(self.execution,
            Execution(self.execution,
            mutator.DeleteEvent(events),
            mutation_index=events[0].index, fly_offset_delta=0,
            mutation_pid=self.diverge_event.pid))

    def handle_mem_owned(self):
        address = self.diverge_event.address
        if self.diverge_event.write_access:
            self.add_event(self.culprit, scribe.EventMemOwnedWriteExtra(serial=0, address=address))
        else:
            self.add_event(self.culprit, scribe.EventMemOwnedReadExtra(serial=0, address=address))
        self.delete_event(self.take_until_match(self.culprit, self.culprit))

        self.status = "memory access"

    def handle_rdtsc(self):
        self.add_event(self.culprit, scribe.EventRdtsc())
        self.delete_event([self.culprit])
        self.status = "RDTSC"

    def handle_type(self):
        self.delete_event([self.culprit])
        self.status = "deleting internal event"

    def handle_syscall(self):
        add_location = None

        if len(self.mutations) > 0:
            new_syscall = self.mutations[0]
        else:
            new_syscall = scribe.EventSyscallExtra(nr=self.diverge_event.nr, ret=0,
                           args=self.diverge_event.args[:struct.calcsize('L')*self.diverge_event.num_args])

        # Because of how signals are handled, we need to put the ignore
        # syscall event before the signals...
        if self.syscall is not None:
            try:
                first_signal = itertools.takewhile(lambda e: e.is_a(scribe.EventSignal),
                                            self.syscall.proc.events.before(self.syscall)).next()
                add_location = Location(first_signal, 'before')
            except StopIteration:
                # no signal found
                pass

        add_event = scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL, new_syscall.encode())

        self.add_event(self.culprit, add_event, add_location=add_location)
        self.delete_event(self.take_until_match(self.culprit, new_syscall))
        self.status = "syscall: %s" % add_event

    def get_add_state(self):
        add_state = ExecutionStates.TODO
        if not self.is_allowed_event('r') and not self.diverge_event.fatal:
            add_state = ExecutionStates.RUNNING
        return add_state

    def handle_syscall_ret(self):
        new_syscall = scribe.EventSyscallExtra(nr=self.syscall.nr, ret=0, args=self.syscall.args)

        add_state = self.get_add_state()

        self.add_event(self.syscall, scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL, new_syscall.encode()), fly_state=add_state)
        self.replace_event(self.syscall, scribe.EventSyscallExtra(nr=self.syscall.nr, ret=self.diverge_event.ret, args=self.syscall.args))
        self.delete_event(self.take_until_match(self.syscall, new_syscall))
        self.status = "ret value mismatch"

    def handle_data_content(self):
        new_syscall = None
        if self.syscall is not None:
            new_syscall = scribe.EventSyscallExtra(nr=self.syscall.nr, ret=0, args = self.syscall.args)

            self.mutations = [None,
                Event(scribe.EventDataExtra(data_type=scribe.SCRIBE_DATA_INPUT | scribe.SCRIBE_DATA_STRING,
                    data=self.diverge_event.data[:self.diverge_event.size]), self.proc),
                Event(scribe.EventSyscallEnd(), self.proc)]
            add_state = self.get_add_state()

            self.add_event(self.syscall, scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL, new_syscall.encode()), fly_state=add_state)
            # not replacing inline data events, it's messed up with resource
            # and all.
            #self.replace_event(self.culprit, scribe.EventData(data=self.diverge_event.data[:self.diverge_event.size]))

        start = self.syscall or self.culprit
        end = new_syscall or self.culprit
        self.delete_event(self.take_until_match(start, end))
        self.status = "diverge data content"

    def handle_default(self):
        new_syscall = None
        if self.syscall is not None:
            new_syscall = scribe.EventSyscallExtra(nr=self.syscall.nr, ret=0, args = self.syscall.args)
            self.mutations = [None, Event(scribe.EventSyscallEnd(), self.proc)]
            self.add_event(self.syscall, scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL, new_syscall.encode()))

        start = self.syscall or self.culprit
        end = new_syscall or self.culprit
        self.delete_event(self.take_until_match(start, end))
        self.status = "unhandled case: %s" % self.diverge_event.__class__

    def handle(self):
        if isinstance(self.diverge_event, scribe.EventDivergeMemOwned):
            self.handle_mem_owned()
        elif isinstance(self.diverge_event, scribe.EventDivergeEventType) and \
                self.diverge_event.type == scribe.EventRdtsc.native_type:
            self.handle_rdtsc()
        elif isinstance(self.diverge_event, scribe.EventDivergeEventType):
            self.handle_type()
        elif isinstance(self.diverge_event, scribe.EventDivergeSyscall):
            self.handle_syscall()
        elif isinstance(self.diverge_event, scribe.EventDivergeSyscallRet):
            self.handle_syscall_ret()
        elif isinstance(self.diverge_event, scribe.EventDivergeDataContent):
            self.handle_data_content()
        else:
            self.handle_default()

        self.execution.info("%s %s" % (self.get_diverge_str(), self.status))

    def take_until_match(self, start, end):
        events = []

        def is_memory(e):
            return e is not None and isinstance(e, Event) and (e.is_a(scribe.EventMemOwnedWriteExtra) or
                   e.is_a(scribe.EventMemOwnedReadExtra))

        if is_memory(start) and is_memory(end) and not start.has_syscall():
            events = list(itertools.takewhile(
                    lambda e: not is_memory(e) or (not self.mem_match(e, end) and not e.has_syscall()),
                    head(start.proc.events.after(start),
                        self.explorer.max_delete)))
            if len(events) > 0 and not self.mem_match(events[-1].next_event(), end):
                return None

        if end is not None and start.has_syscall():
            events = list(itertools.takewhile(
                    lambda e: not self.sys_match(e, end),
                    head(start.proc.syscalls.after(start.syscall),
                        self.explorer.max_delete)))
            if len(events) > 0 and not self.sys_match(events[-1].next_syscall(), end):
                return None

        events.insert(0, start)
        return events

    def mem_match(self, m1, m2):
        if m1 is None or m2 is None:
            return False

        return m1.address == m2.address

    def sys_match(self, s1, s2):
        if s1 is None or s2 is None:
            return False

        if s1.nr != s2.nr:
            return False

        def get_args(s):
            return struct.unpack("L" * (len(s.args)/4), s.args)

        def is_addr(val):
            return (val & 0xff800000) != 0

        for (a1, a2) in zip(get_args(s1), get_args(s2)):
            if a1 == a2:
                continue
            if is_addr(a1) and is_addr(a2):
                continue
            return False

        body1 = list(s1.children)
        body2 = self.mutations[1:-1]

        if len(body2) == 0:
            return True

        # paths1 actually contains more than path, but I guess that fine
        paths1 = filter(is_data, body1)
        paths2 = filter(is_string_data, body2)

        if len(paths1) < len(paths2):
            return

        paths1_iter = iter(paths1)

        for path2 in paths2:
            try:
                while paths1_iter.next().data != path2.data:
                    pass
            except StopIteration:
                return False
        return True
