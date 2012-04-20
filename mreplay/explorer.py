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
from session import Session, Event
import datetime
import math

MREPLAY_DIR = ".mreplay"

def is_verbose():
    return logging.getLogger().getEffectiveLevel() == logging.DEBUG

def load_session(logfile_path):
    with open(logfile_path, 'r') as logfile:
        logfile_map = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        return Session(scribe.EventsFromBuffer(logfile_map))

class ExecutionStates:
    TODO = 0
    SUCCESS = 1
    FAILED = 2
    RUNNING = 3

class Execution:
    def __init__(self, parent, mutation, state=ExecutionStates.TODO,
                 running_session=None, mutation_index=0, fly_offset_delta=0, mutation_pid=0):

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

        self.fly_offsets = dict(parent.fly_offsets)
        self.fly_offsets[mutation_pid] = self.fly_offsets.get(mutation_pid, 0) + fly_offset_delta

        self.mutation_indices = dict(parent.mutation_indices)
        self.mutation_indices[mutation_pid] = mutation_index

        if self._running_session is None:
            for (pid, offset) in self.fly_offsets.items():
                self.mutation_indices[pid] += offset
            self.fly_offsets = {}

        self.id = self.explorer.get_new_id()

        self.sig_list = list(parent.sig_list)
        self.sig = parent.sig


        def penalize_sacred_events(events):
            for e in events:
                if e.is_a(scribe.EventSetFlags) or e.is_a(scribe.EventNop):
                    if len(e.extra) > 0:
                        e = Event(scribe.Event.from_bytes(e.extra), e.proc)

                syscall = None
                if e.is_a(scribe.EventSyscallExtra):
                    syscall = e
                elif e.has_syscall():
                    syscall = e.syscall
                else:
                    continue
                if syscall.nr in unistd.SYS_exit:
                    self.score -= 100000000000000000000000000

        if isinstance(mutation, mutator.InsertEvent):
            penalize_sacred_events(mutation.events)
            self.score += self.explorer.add_constant
            self.sig = self.sig + "+"
        elif isinstance(mutation, mutator.DeleteEvent):
            penalize_sacred_events(mutation.events)
            self.score += self.explorer.del_constant * len(mutation.events)
            self.score += self.explorer.match_constant
            self.sig = self.sig + "-" * len(mutation.events)
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
        a = map(lambda s: ''.join(sorted(s)), self.signature())
        b = map(lambda s: ''.join(sorted(s)), other.signature())
        return a == b

    def __hash__(self):
        a = map(lambda s: ''.join(sorted(s)), self.signature())
        return hash(','.join(a))

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

        cmd = "colordiff -U3 %s %s | tail -n +4" % \
                  (human_log_file(self.explorer.root.logfile_path),
                          human_log_file(self.logfile_path))
        subprocess.call(['/bin/bash', '-c', cmd])

    def info(self, msg):
        logging.info("[%d] %s" % (self.id, msg))

    def deadlocked(self):
        self.state = ExecutionStates.FAILED
        self.info("\033[1;31mDeadlocked\033[m")

    def signature(self):
        return self.sig_list + [self.sig]

    def update_progress(self, pid, index):
        old_score = self.score

        base = self.mutation_indices.get(pid, 0)

        if self._running_session is None:
            print("Using disk indices")
        else:
            print("Using fly indices")

        #print("Awarded for: %s" % map(lambda e: str(e), list(self.running_session.processes[pid].events)[base:index]))

        segment_length = index - base

        if segment_length > 0:
            self.sig_list.append(self.sig)
            self.sig = ""

        self.info("pid %d mutation_indices: %d, diverged on: %d" %
                (pid, base, index))

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

    def diverged(self, diverge_event, mutations):
        from diverge_handler import DivergeHandler
        DivergeHandler(self, diverge_event, mutations).handle()

    def success(self):
        self.state = ExecutionStates.SUCCESS
        self.info("\033[1;32mSuccess\033[m")
        if is_verbose():
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
        parent.fly_offsets = dict()
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
            self.execution.print_diff()

        def _on_mutation(diverge_event, mutations):
            if self.execution is None:
                return

            self.execution.diverged(diverge_event, mutations)
            old_execution = self.execution
            try:
                self.execution = [e for e in self.explorer.executions
                                  if e.state == ExecutionStates.RUNNING][0]
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

            def on_mutation(self, diverge_event, mutations):
                _on_mutation(diverge_event, mutations)

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
                self.execution.diverged(diverge.event, [])
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
        self.execution_set = set()
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
        if child in self.execution_set:
            parent.info("NOT adding [%d], score: %d (%d) %s" %
                    (child.id, child.score, child.score - parent.score,
                    child.signature()))
            return

        if parent is not None:
            parent.info("Adding [%d], score: %d (%d) %s" %
                    (child.id, child.score, child.score - parent.score,
                    child.signature()))

        self.executions.append(child)
        self.execution_set.add(child)

    def num_state(self, state):
        return len(filter(lambda e: e.state == state, self.executions))

    def print_status(self, num_run):
        logging.info("-" * 80)
        logging.info("Replays: %d, Success: %d, Failed: %d, Todo: %d" % \
                     (num_run,
                      self.num_state(ExecutionStates.SUCCESS),
                      self.num_state(ExecutionStates.FAILED),
                      self.num_state(ExecutionStates.TODO)))
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
            if self.num_state(ExecutionStates.SUCCESS) >= self.num_success_to_stop:
                break

            todos = filter(lambda e: e.state == ExecutionStates.TODO, self.executions)
            if len(todos) == 0:
                break
            self.print_status(num_run)
            execution = max(todos, key=lambda e: e.score)

            num_run += 1
            with execute.open(jailed=self.isolate) as exe:
                execution.num_run = num_run
                execution.num_success = len(list([e for e in self.executions if e.state == ExecutionStates.SUCCESS]))

                replayer[0] = Replayer(execution)
                replayer[0].run(exe)

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        print("Number of Replays: %d" % num_run)

        if self.num_success_to_stop != 1:
            print("")
            self.print_status(num_run)
            print("Summary of good executions:")
            self.executions.sort(key=lambda e: e.score)
            for execution in self.executions:
                if execution.state == ExecutionStates.SUCCESS:
                    print("%d %d %d %s:" % (execution.score, execution.num_run, execution.num_success+1, execution))
                    execution.print_diff()
                    print("")
