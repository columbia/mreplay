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
from session import Session
from location import Location

MREPLAY_DIR = ".mreplay"

TODO = 0
SUCCESS = 1
FAILED = 2
RUNNING = 3

def is_verbose():
    return logging.getLogger().getEffectiveLevel() == logging.DEBUG

def load_session(logfile_path):
    with open(logfile_path, 'r') as logfile:
        logfile_map = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        return Session(scribe.EventsFromBuffer(logfile_map))

class Execution:
    def __init__(self, parent, mutation, state=TODO,
                 running_session=None, mutation_index=0):
        self.explorer = parent.explorer
        self.parent = parent
        self.score = parent.score

        self.mutation = mutation
        self.children = []
        self.state = state
        self._session = None
        self._running_session = running_session
        self.name = None
        self.mutation_index = mutation_index
        self.id = self.explorer.get_new_id()

    def __str__(self):
        if self.name is None:
            self.name = "%s_%s" % (self.parent, self.mutation)
        return self.name

    @property
    def logfile_path(self):
        return MREPLAY_DIR + "/" + str(self.id)

    def generate_log(self):
        if os.path.exists(self.logfile_path):
            return

        events  = self.mutated_session
        events |= mutator.AdjustResources()
        events |= mutator.InsertEoqEvents()
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
        if self._session is not None and self._running_session is None:
            return self._session
        return self.parent.mutated_session | self.mutation

    def print_diff(self):
        self.generate_log()
        cmd = "diff -U1 <(profiler %s 2> /dev/null) <(profiler %s 2> /dev/null) | tail -n +4" % \
                  (self.explorer.root.logfile_path, self.logfile_path)
        subprocess.call(['/bin/bash', '-c', cmd])

    def info(self, msg):
        logging.info("[%d] %s" % (self.id, msg))

    def deadlocked(self):
        self.state = FAILED
        self.info("\033[1;31mDeadlocked\033[m")
        if is_verbose():
            self.print_diff()

    def adjust_score(self, index):
        segment_length = index - self.mutation_index
        if self.explorer.linear:
            self.score += segment_length
        else:
            self.score += segment_length**2

    def diverged(self, diverge_event):
        if diverge_event is None:
            self.info("\033[1;31m FATAL ERROR -- FIXME\033[m")
        pid = diverge_event.pid
        num = diverge_event.num_ev_consumed
        if diverge_event.fatal:
            num -= 1

        self.adjust_score(num)

        if diverge_event.fatal:
            diverge_str = "diverged (%s)" % diverge_event
        else:
            diverge_str = "mutating (%s)" % diverge_event

        self.state = FAILED
        event = self.running_session.processes[pid].events[num]

        try:
            syscall = event.syscall
        except AttributeError:
            if not diverge_event.fatal:
                self.info("\033[1;31m FATAL ERROR -- FIXME\033[m")
            self.info("pid=%d \033[1;31m%s\033[m at n=%d: %s (no syscall)" %
                       (pid, diverge_str, num, event))
            self.print_diff()
            return

        if is_verbose():
            self.print_diff()

        if event != syscall:
            self.info("pid=%d \033[1;33m%s\033[m at n=%d: %s in %s" %
                      (pid, diverge_str, num, event, syscall))
        else:
            self.info("pid=%d \033[1;33m%s\033[m at n=%d: %s" %
                       (pid, diverge_str, num, syscall))

        # Because of how signals are handled, we need to put the ignore
        # syscall event before the signals...
        try:
            first_signal = itertools.takewhile(lambda e: e.is_a(scribe.EventSignal),
                                        syscall.proc.events.before(syscall)).next()
            add_location = Location(first_signal, 'before')
        except StopIteration:
            add_location = Location(syscall, 'before')

        if diverge_event.fatal:
            self.explorer.add_execution(Execution(self,
                mutator.IgnoreNextSyscall(add_location),
                mutation_index=syscall.index+1))
        else:
            self.explorer.add_execution(Execution(self,
                mutator.IgnoreNextSyscall(add_location),
                state=RUNNING, running_session=self.running_session,
                mutation_index=syscall.index))


        if syscall.nr != unistd.NR_exit_group:
            self.explorer.add_execution(Execution(self,
                mutator.DeleteSyscall(syscall),
                mutation_index=syscall.index+1))

    def success(self):
        self.state = SUCCESS
        self.info("\033[1;32mSuccess\033[m")
        self.adjust_score(len(self.running_session.events))
        self.print_diff()

class RootExecution(Execution):
    def __init__(self, explorer, on_the_fly):
        class DummyParent:
            pass
        parent = DummyParent()
        parent.score = 0
        parent.explorer = explorer
        parent.mutated_session = load_session(explorer.logfile_path)

        if on_the_fly:
            m = mutator.MutateOnTheFly(parent.mutated_session)
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

    def run(self, exe):
        if is_verbose():
            self.execution.info("Running %s" % self.execution)
        def _on_mutation(diverge_event):
            self.execution.diverged(diverge_event)
            self.execution = [e for e in self.explorer.executions
                              if e.state == RUNNING][0]
            if is_verbose():
                self.execution.info("Running %s" % self.execution)

        class ReplayContext(scribe.Context):
            def on_mutation(self, event):
                _on_mutation(event)

        self.execution.generate_log()
        with open(self.execution.logfile_path, 'r') as logfile:
            context = ReplayContext(logfile, backtrace_len = 0)
            context.add_init_loader(lambda argv, envp: exe.prepare())
            ps = scribe.Popen(context, replay = True)

        def do_check_deadlock(signum, stack):
            try:
                context.check_deadlock()
            except OSError as e:
                if e.errno != errno.EPERM:
                    logging.error("Cannot check for deadlock (%s)" % str(e))
        signal.signal(signal.SIGALRM, do_check_deadlock)
        signal.setitimer(signal.ITIMER_REAL, 1, 1)

        try:
            context.wait()
            self.execution.success()
        except scribe.DeadlockError:
            self.execution.deadlocked()
        except scribe.DivergeError as diverge:
            self.execution.diverged(diverge.event)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

        ps.wait()

class Explorer:
    def __init__(self, logfile_path, on_the_fly, try_all, isolate):
        self.logfile_path = logfile_path
        self.num_success_to_stop = 99999 if try_all else 1
        self.isolate = isolate
        self.linear = linear
        self.executions = []
        self.make_mreplay_dir()
        self._next_id = 0
        self.root = RootExecution(self, on_the_fly)

    def get_new_id(self):
        self._next_id += 1
        return self._next_id

    def make_mreplay_dir(self):
        if os.path.exists(MREPLAY_DIR):
            shutil.rmtree(MREPLAY_DIR)
        os.makedirs(MREPLAY_DIR)

    def add_execution(self, execution):
        if execution.state == TODO:
            # We need to check if it's not a duplicate right here
            pass

        self.executions.append(execution)

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
        def do_stop(signum, stack):
            logging.info("Stop Requested")
            stop_requested[0] = True

        signal.signal(signal.SIGINT, do_stop)

        self.add_execution(self.root)

        while not stop_requested[0]:
            if self.num_state(SUCCESS) >= self.num_success_to_stop:
                break

            todos = filter(lambda e: e.state == TODO, self.executions)
            if len(todos) == 0:
                break
            self.print_status()
            execution = max(todos, key=lambda e: e.score)

            with execute.open(jailed=self.isolate) as exe:
                Replayer(execution).run(exe)

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        if self.num_success_to_stop != 1:
            print("")
            self.print_status()
            print("Summary of good executions:")
            for execution in self.executions:
                if execution.state == SUCCESS:
                    print("%s:" % execution)
                    execution.print_diff()
                    print("")
