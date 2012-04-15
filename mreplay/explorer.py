import scribe
import mutator
import mmap
import shutil
import os
import logging
import signal
import errno
import subprocess
import unistd
import execute
import itertools
import struct
from session import Session
from location import Location
from mreplay.session import Event
import datetime
import math

MREPLAY_DIR = ".mreplay"

TODO = 0
SUCCESS = 1
FAILED = 2
RUNNING = 3

def head(seq, n=1):
    iterator = iter(seq)
    for i in xrange(n):
        yield iterator.next()


def sys_match(s1, s2):
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

    return True


def is_verbose():
    return logging.getLogger().getEffectiveLevel() == logging.DEBUG

def load_session(logfile_path):
    with open(logfile_path, 'r') as logfile:
        logfile_map = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        return Session(scribe.EventsFromBuffer(logfile_map))

class Execution:
    def __init__(self, parent, mutation, state=TODO,
                 running_session=None, mutation_index=0, mutation_pid=0):
        self.explorer = parent.explorer
        self.parent = parent
        self.score = parent.score
        self.depth = parent.depth + 1

        self.mutation = mutation
        self.children = []
        self.state = state
        self._session = None
        self._running_session = running_session
        self.name = None

        self.mutation_indices = dict(parent.mutation_indices)
        self.mutation_indices[mutation_pid] = mutation_index

        self.id = self.explorer.get_new_id()

        self.sig_list = list(parent.sig_list)
        self.sig = parent.sig

        if isinstance(mutation, mutator.InsertEvent):
            self.score += self.explorer.add_constant
            self.sig = self.sig + "+"
        elif isinstance(mutation, mutator.DeleteEvent):
            try:
                if mutation.events[-1].syscall.nr in unistd.SYS_exit:
                    self.score -= 10000
            except AttributeError:
                pass
            self.score += self.explorer.del_constant * len(mutation.events)
            self.sig = self.sig + "-"
        elif isinstance(mutation, mutator.Nop):
            pass
        elif isinstance(mutation, mutator.SetFlagsInit):
            pass
        elif isinstance(mutation, mutator.Replace):
            self.sig = self.sig + "+-"
        else:
            raise RuntimeError("Mutator type: %s" % mutation.__class__)

    def __str__(self):
        if self.name is None:
            self.name = "%s_%s" % (self.parent, self.mutation)
        return self.name

    def __eq__(self, other):
        a = map(lambda s: sorted(s), self.signature())
        b = map(lambda s: sorted(s), other.signature())
        return a == b

    @property
    def logfile_path(self):
        return MREPLAY_DIR + "/" + str(self.id)

    def generate_log(self):
        if os.path.exists(self.logfile_path):
            return

        events  = self.mutated_session
        events |= mutator.AdjustResources()
        events |= mutator.InsertPidEvents()
        events |= mutator.ToRawEvents()

        with open(self.logfile_path, 'w') as logfile:
            for event in events:
                logfile.write(event.encode())

    @property
    def session(self):
        if self._session is None:
            self.generate_log()
            self._session = load_session(self.logfile_path)
        return self._session

    @property
    def running_session(self):
        if self._running_session is None:
            return self.session
        return self._running_session

    @property
    def mutated_session(self):
        if self._session is not None:
            return self._session

        if self.depth > 180:
            path = []
            current = self.parent
            while current.depth > 10 and current._session is None:
                path.append(current)
                current = current.parent
            path.reverse()

            i = 0
            for p in path:
                i += 1
                if i % 200 == 0:
                    p.session

        return self.parent.mutated_session | self.mutation

    def print_diff(self):
        self.generate_log()
        def human_log_file(path):
            return "<(profiler %s | sed 's/serial = [0-9]\+, //g' 2> /dev/null)" % path

        cmd = "colordiff -U1 %s %s | tail -n +4" % \
                  (human_log_file(self.explorer.root.logfile_path),
                          human_log_file(self.logfile_path))
        subprocess.call(['/bin/bash', '-c', cmd])

    def info(self, msg):
        logging.info("[%d] %s" % (self.id, msg))

    def deadlocked(self):
        self.state = FAILED
        self.info("\033[1;31mDeadlocked\033[m")
        if is_verbose():
            self.print_diff()

    def signature(self):
        return self.sig_list + [self.sig]

    def update_progress(self, pid, index):
        old_score = self.score

        segment_length = index - self.mutation_indices.get(pid, 0)

        if segment_length > 0:
            self.sig_list.append(self.sig)
            self.sig = ""

        self.info("pid %d mutation_indices: %d, diverged on: %d" %
                (pid, self.mutation_indices.get(pid, 0), index))

        if self.explorer.linear:
            self.score += segment_length * self.explorer.match_constant
        else:
            self.score = math.sqrt(self.score**2 + segment_length**2 * self.explorer.match_constant)

        self.info("adjusting score %d -> %d" %(old_score, self.score))

    def get_user_pattern(self):
        pattern = self.explorer.pattern
        if pattern is not None and self.depth < len(pattern):
            user_pattern = pattern[self.depth]
            if user_pattern == '.':
                return None
            return user_pattern
        return None

    def diverged(self, diverge_event):
        if diverge_event is None:
            self.info("\033[1;31m FATAL ERROR -- FIXME\033[m")
        pid = diverge_event.pid
        num = diverge_event.num_ev_consumed - 1
        if not diverge_event.fatal:
            if isinstance(diverge_event, scribe.EventDivergeSyscall):
                num += 1

        self.update_progress(pid, num)
        self.state = FAILED
        event = self.running_session.processes[pid].events[num]

        syscall = None
        try:
            syscall = event.syscall
        except AttributeError:
            # no syscall found
            if not diverge_event.fatal:
                self.info("\033[1;31m FATAL ERROR -- FIXME\033[m")

        if diverge_event.fatal:
            diverge_str = "diverged (%s)" % (diverge_event)
        else:
            diverge_str = "mutating (%s)" % (diverge_event)

        diverge_str = "pid=%d \033[1;33m%s at %s\033[m" % (pid, diverge_str, event)


        if syscall is not None and syscall != event:
            diverge_str = "%s in %s" % (diverge_str, syscall)

        new_syscall = None
        add_location = None
        add_event = None
        replace_event = None

        if isinstance(diverge_event, scribe.EventDivergeMemOwned):
            address = diverge_event.address
            if diverge_event.write_access:
                add_event = scribe.EventMemOwnedWriteExtra(serial=0, address=address)
            else:
                add_event = scribe.EventMemOwnedReadExtra(serial=0, address=address)
            self.info("%s memory access" % diverge_str)

        elif isinstance(diverge_event, scribe.EventDivergeEventType) and \
                diverge_event.type == scribe.EventRdtsc.native_type:
            add_event = scribe.EventRdtsc()
            self.info("%s RDTSC" % diverge_str)

        elif isinstance(diverge_event, scribe.EventDivergeEventType):
            self.info("%s deleting internal event" % diverge_str)

        elif isinstance(diverge_event, scribe.EventDivergeSyscall):
            new_syscall = scribe.EventSyscallExtra(nr=diverge_event.nr, ret=0,
                           args=diverge_event.args[:struct.calcsize('L')*diverge_event.num_args])
            add_event = scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL,
                                             new_syscall.encode())
            self.info("%s syscall: %s" % (diverge_str, add_event))

            # Because of how signals are handled, we need to put the ignore
            # syscall event before the signals...
            if syscall is not None:
                try:
                    first_signal = itertools.takewhile(lambda e: e.is_a(scribe.EventSignal),
                                                syscall.proc.events.before(syscall)).next()
                    add_location = Location(first_signal, 'before')
                except StopIteration:
                    # no signal found
                    pass

        elif isinstance(diverge_event, scribe.EventDivergeSyscallRet):
            event = syscall
            new_syscall = scribe.EventSyscallExtra(nr=syscall.nr, ret=0, args=syscall.args)
            add_event = scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL,
                                             new_syscall.encode())
            replace_event = scribe.EventSyscallExtra(nr=syscall.nr, ret=diverge_event.ret,
                                                     args=syscall.args)
            self.info("%s ret value mismatch" % diverge_str)

        else:
            if syscall is not None:
                event = syscall
                new_syscall = scribe.EventSyscallExtra(nr=syscall.nr, ret=0, args = syscall.args)
                add_event = scribe.EventSetFlags(0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL,
                                                 new_syscall.encode())
            self.info("%s unhandled case" % (diverge_str))


        user_pattern = self.get_user_pattern()

        if (user_pattern is None or user_pattern == 'r') and replace_event:
            replace_event = Event(replace_event, event.proc)
            if diverge_event.fatal:
                self.explorer.add_execution(self, Execution(self,
                    mutator.Replace({event: replace_event}),
                    mutation_index=event.index, mutation_pid=pid))
            else:
                self.explorer.add_execution(self, Execution(self,
                    mutator.Replace({event: replace_event}),
                    state=RUNNING, running_session=self.running_session,
                    mutation_index=event.index, mutation_pid=pid))

        if (user_pattern is None or user_pattern == '+') and add_event:
            if add_location is None:
                add_location = Location(event, 'before')

            add_event = Event(add_event, event.proc)
            if diverge_event.fatal:
                self.explorer.add_execution(self, Execution(self,
                    mutator.InsertEvent(add_location, add_event),
                    mutation_index=event.index+1, mutation_pid=pid))
            elif replace_event is None:
                self.explorer.add_execution(self, Execution(self,
                    mutator.InsertEvent(add_location, add_event),
                    state=RUNNING, running_session=self.running_session,
                    mutation_index=event.index, mutation_pid=pid))

        if user_pattern is None or user_pattern == '-':
            events = []
            if new_syscall is not None:
                try:
                    events = list(itertools.takewhile(
                            lambda e: not sys_match(e, new_syscall),
                            head(event.proc.syscalls.after(event.syscall),
                                self.explorer.max_delete)))
                except AttributeError:
                    pass
            events.insert(0, event)

            self.explorer.add_execution(self, Execution(self,
                mutator.DeleteEvent(events),
                mutation_index=event.index+1, mutation_pid=pid))

        if is_verbose() and diverge_event.fatal:
            self.print_diff()

    def success(self):
        self.state = SUCCESS
        self.info("\033[1;32mSuccess\033[m")
        self.print_diff()

class RootExecution(Execution):
    def __init__(self, explorer, on_the_fly, var_io):
        class DummyParent:
            pass
        parent = DummyParent()
        parent.depth = -1
        parent.score = 0
        parent.explorer = explorer
        parent.mutated_session = load_session(explorer.logfile_path)
        parent.mutation_indices = dict()
        parent.sig = ""
        parent.sig_list = []

        neg_flags = 0
        if on_the_fly:
            neg_flags |= scribe.SCRIBE_PS_STRICT_REPLAY
        if var_io:
            neg_flags |= scribe.SCRIBE_PS_FIXED_IO

        if neg_flags != 0:
            m = mutator.SetFlagsInit(parent.mutated_session,
                                     scribe.SCRIBE_PS_ENABLE_ALL & ~neg_flags)
        else:
            m = mutator.Nop()
        Execution.__init__(self, parent, m)

    def __str__(self):
        return "0"

# An execution is not the same as a replay:
# A Replay can mutate and thus represent different executions
class Replayer:
    def __init__(self, execution):
        self.execution = execution
        self.explorer = execution.explorer
        self.context = None

    def stop(self):
        self.context.close()

    def run(self, exe):
        if is_verbose():
            self.execution.info("Running %s (%d)" % (self.execution, self.execution.score))
        def _on_mutation(diverge_event):
            if self.execution is None:
                return
            self.execution.diverged(diverge_event)
            old_execution = self.execution
            try:
                self.execution = [e for e in self.explorer.executions
                                  if e.state == RUNNING][0]
            except IndexError:
                # user pattern aborted the replay, must abort.
                self.execution = None
                ps.kill()
                return
            if is_verbose():
                self.execution.info("Continue Running %s" % self.execution)
            self.execution.num_run = old_execution.num_run
            self.execution.num_success = old_execution.num_success

        class ReplayContext(scribe.Context):
            def __init__(self, logfile, **kargs):
                scribe.Context.__init__(self, logfile, **kargs)
                self.start = datetime.datetime.now()
                self.last = self.start

            def on_mutation(self, event):
                _on_mutation(event)

            def on_bookmark(self, id, npr):
                now = datetime.datetime.now()
                dstart = now - self.start
                dlast = now - self.last
                self.last = now
                print("Reached bmark %d at %d.%ds, +%d.%ds" %
                        (id, dstart.seconds, dstart.microseconds,
                            dlast.seconds, dlast.microseconds))
                self.resume()

        self.execution.generate_log()
        with open(self.execution.logfile_path, 'r') as logfile:
            self.context = ReplayContext(logfile, backtrace_len = 0)
            self.context.add_init_loader(lambda argv, envp: exe.prepare())
            ps = scribe.Popen(self.context, replay = True)

        def do_check_deadlock(signum, stack):
            try:
                self.context.check_deadlock()
            except OSError as e:
                if e.errno != errno.EPERM:
                    logging.error("Cannot check for deadlock (%s)" % str(e))
        signal.signal(signal.SIGALRM, do_check_deadlock)
        signal.setitimer(signal.ITIMER_REAL, 1, 1)

        try:
            self.context.wait()
            if self.execution is not None:
                self.execution.success()
        except scribe.DeadlockError:
            if self.execution is not None:
                self.execution.deadlocked()
        except scribe.DivergeError as diverge:
            if self.execution is not None:
                self.execution.diverged(diverge.event)
        except scribe.ContextClosedError:
            pass
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

        ps.wait()
        self.context.close()

class Explorer:
    def __init__(self, logfile_path, on_the_fly, var_io,
                 num_success_to_stop, isolate, linear, pattern,
                 add_constant, del_constant, match_constant,
                 max_delete):
        self.add_constant = add_constant
        self.del_constant = del_constant
        self.match_constant = match_constant
        self.max_delete = max_delete
        self.logfile_path = logfile_path
        self.num_success_to_stop = num_success_to_stop
        self.isolate = isolate
        self.linear = linear
        if pattern is not None:
            pattern = pattern.replace('*','-+')
        self.pattern = pattern
        self.executions = []
        self.make_mreplay_dir()
        self._next_id = 0
        self.root = RootExecution(self, on_the_fly, var_io)

    def get_new_id(self):
        self._next_id += 1
        return self._next_id

    def make_mreplay_dir(self):
        if os.path.exists(MREPLAY_DIR):
            shutil.rmtree(MREPLAY_DIR)
        os.makedirs(MREPLAY_DIR)

    def add_execution(self, parent, child):
        if child.state == TODO:
            if child in self.executions:
                parent.info("NOT adding [%d], score: %d (%d) %s" %
                        (child.id, child.score, child.score - parent.score,
                        child.signature()))
                return

        if parent is not None:
            parent.info("Adding [%d], score: %d (%d) %s" %
                    (child.id, child.score, child.score - parent.score,
                    child.signature()))

        self.executions.append(child)

    def num_state(self, state):
        return len(filter(lambda e: e.state == state, self.executions))

    def print_status(self):
        logging.info("-" * 80)
        logging.info("Success: %d, Failed: %d, Todo: %d" % \
                     (self.num_state(SUCCESS),
                      self.num_state(FAILED),
                      self.num_state(TODO)))
        logging.info("-" * 80)


    def run(self):
        stop_requested = [False]
        replayer = [None]
        def do_stop(signum, stack):
            logging.info("Stop Requested")
            stop_requested[0] = True
            replayer[0].stop()

        signal.signal(signal.SIGINT, do_stop)

        self.add_execution(None, self.root)

        num_run = 0
        while not stop_requested[0]:
            if self.num_state(SUCCESS) >= self.num_success_to_stop:
                break

            todos = filter(lambda e: e.state == TODO, self.executions)
            if len(todos) == 0:
                break
            self.print_status()
            execution = max(todos, key=lambda e: e.score)

            num_run += 1
            with execute.open(jailed=self.isolate) as exe:
                execution.num_run = num_run
                execution.num_success = len(list([e for e in self.executions if e.state == SUCCESS]))

                replayer[0] = Replayer(execution)
                replayer[0].run(exe)

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        print("Number of Replays: %d" % num_run)

        if self.num_success_to_stop != 1:
            print("")
            self.print_status()
            print("Summary of good executions:")
            self.executions.sort(key=lambda e: e.score)
            for execution in self.executions:
                if execution.state == SUCCESS:
                    print("%d %d %d %s:" % (execution.score, execution.num_run, execution.num_success+1, execution))
                    execution.print_diff()
                    print("")
