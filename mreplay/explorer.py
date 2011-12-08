import scribe
import mutator
import mmap
import shutil
import os
import logging
import signal
import errno
import subprocess
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
    def __init__(self, parent, mutation, state=TODO, replay_offset=0):
        self.explorer = parent.explorer
        self.parent = parent
        self.score = parent.score + 1
        if isinstance(mutation, mutator.DeleteSyscall):
            self.score += 1

        self.mutation = mutation
        self.children = []
        self.state = state
        self._session = None
        self.replay_offset = replay_offset
        self.name = None

    def __str__(self):
        if self.name is None:
            self.name = "%s_%s" % (self.parent, self.mutation)
        return self.name

    @property
    def logfile_path(self):
        return MREPLAY_DIR + "/" + str(self)

    def generate_log(self):
        if os.path.exists(self.logfile_path):
            return

        events  = self.parent.session
        events |= self.mutation
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

    def print_diff(self):
        self.generate_log()
        cmd = "diff -U1 <(profiler %s 2> /dev/null) <(profiler %s 2> /dev/null) | tail -n +4" % \
                  (self.explorer.root.logfile_path, self.logfile_path)
        subprocess.call(['/bin/bash', '-c', cmd])

    def info(self, msg):
        logging.info("[%s] %s" % (self, msg))

    def deadlocked(self):
        self.state = FAILED
        self.info("\033[1;31mDeadlocked\033[m")
        if is_verbose():
            self.print_diff()

    def diverged(self, diverge_event):
        pid = diverge_event.pid
        num = diverge_event.num_ev_consumed
        if diverge_event.fatal:
            num -= 1
        num += self.replay_offset

        if diverge_event.fatal:
            diverge_str = "diverged (%s)" % diverge_event
        else:
            diverge_str = "mutating (%s)" % diverge_event

        self.state = FAILED
        event = self.session.processes[pid].events[num]
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

        if diverge_event.fatal:
            self.explorer.add_execution(Execution(self,
                mutator.IgnoreNextSyscall(Location(syscall, 'before'))))
        else:
            self.explorer.add_execution(Execution(self,
                mutator.IgnoreNextSyscall(Location(syscall, 'before')),
                state = RUNNING, replay_offset=self.replay_offset+1))

        self.explorer.add_execution(Execution(self, mutator.DeleteSyscall(syscall)))

    def success(self):
        self.state = SUCCESS
        self.info("\033[1;32mSuccess\033[m")
        self.print_diff()

class RootExecution(Execution):
    def __init__(self, explorer, on_the_fly):
        class DummyParent:
            pass
        parent = DummyParent()
        parent.score = 0
        parent.explorer = explorer
        parent.session = load_session(explorer.logfile_path)
        if on_the_fly:
            Execution.__init__(self, parent, mutator.MutateOnTheFly(parent.session))
        else:
            Execution.__init__(self, parent, mutator.Nop())

    def __str__(self):
        return "0"

# An execution is not the same as a replay:
# A Replay can mutate and thus represent different executions
class Replayer:
    def __init__(self, execution):
        self.execution = execution
        self.explorer = execution.explorer

    def run(self):
        self.execution.info("Running")

        def _on_mutation(diverge_event):
            self.execution.diverged(diverge_event)
            self.execution = [e for e in self.explorer.executions
                              if e.state == RUNNING][0]
            self.execution.info("Running Mutation")

        class ReplayContext(scribe.Context):
            def on_mutation(self, event):
                _on_mutation(event)

        self.execution.generate_log()
        with open(self.execution.logfile_path, 'r') as logfile:
            context = ReplayContext(logfile, backtrace_len = 0)
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
    def __init__(self, logfile_path, on_the_fly, try_all):
        self.logfile_path = logfile_path
        self.try_all = try_all
        self.executions = []
        self.make_mreplay_dir()
        self.root = RootExecution(self, on_the_fly)

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
            if not self.try_all and self.num_state(SUCCESS) > 0:
                break

            todos = filter(lambda e: e.state == TODO, self.executions)
            if len(todos) == 0:
                break
            self.print_status()
            execution = min(todos, key=lambda e: e.score)
            Replayer(execution).run()

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        print("")
        self.print_status()
        print("Summary of good executions:")
        for execution in self.executions:
            if execution.state == SUCCESS:
                print("%s:" % execution)
                execution.print_diff()
                print("")
