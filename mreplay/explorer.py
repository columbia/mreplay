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

SUCCESS = 1
FAILED = 2

def load_session(logfile_path):
    with open(logfile_path, 'r') as logfile:
        logfile_map = mmap.mmap(logfile.fileno(), 0, prot=mmap.PROT_READ)
        return Session(scribe.EventsFromBuffer(logfile_map))

class Failure:
    pass

class Success:
    pass

class Diverge(Failure):
    def __init__(self, syscall):
        self.syscall = syscall

class Execution:
    def __init__(self, parent, mutation):
        self.explorer = parent.explorer
        self.parent = parent
        self.mutation = mutation
        self.children = []
        self.state = None
        self._session = None
        self.name = None

    def __str__(self):
        if self.name is None:
            self.name = "%s_%s" % (self.parent, self.mutation)
        return self.name

    def add_execution(self, execution):
        self.children.append(execution)
        self.explorer.add_execution(execution)

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
            self._session = load_session(self.logfile_path)
        return self._session

    def print_diff(self):
        cmd = "diff -U1 <(profiler %s 2> /dev/null) <(profiler %s 2> /dev/null) | tail -n +4" % \
                  (self.explorer.root.logfile_path, self.logfile_path)
        subprocess.call(['/bin/bash', '-c', cmd])

    def info(self, msg):
        logging.info("[%s] %s" % (self, msg))

    def deadlocked(self):
        self.state = FAILED
        self.info("\033[1;31mDeadlocked\033[m")
        self.print_diff()

    def diverged(self, diverge_event):
        if diverge_event is None:
            self.info("\033[1;31mFATAL ERROR -- FIXME\033[m")
            return

        pid = diverge_event.pid
        num = diverge_event.num_ev_consumed - 1

        diverge_str = "diverged (%s)" % diverge_event

        self.state = FAILED
        event = self.session.processes[pid].events[num]
        try:
            syscall = event.syscall
        except AttributeError:
            self.info("pid=%d \033[1;31m%s\033[m at n=%d: %s (no syscall)" %
                       (pid, diverge_str, num, event))
            self.print_diff()
            return

        if event != syscall:
            self.info("pid=%d \033[1;33m%s\033[m at n=%d: %s in %s" %
                      (pid, diverge_str, num, event, syscall))
        else:
            self.info("pid=%d \033[1;33m%s\033[m at n=%d: %s" %
                       (pid, diverge_str, num, syscall))
        self.print_diff()

        # We only add the insert child only when we didn't deleted at the same
        # place. Otherwise we end up with two children like this:
        # - syscall()                   + ignore syscall
        # + ignore syscall              - syscall()
        # These two executions are equivalent

        if not (isinstance(self.mutation, mutator.DeleteSyscall) and \
            self.mutation.syscall.proc.pid == syscall.proc.pid and \
            self.mutation.syscall.index == syscall.index):
            self.add_execution(Execution(self,
                               mutator.IgnoreSyscall(Location(syscall, 'before'))))

        self.add_execution(Execution(self, mutator.DeleteSyscall(syscall)))

    def success(self):
        self.state = SUCCESS
        self.info("\033[1;32mSuccess\033[m")
        self.print_diff()

    def run(self):
        self.info("Running")
        self.generate_log()
        with open(self.logfile_path, 'r') as logfile:
            context = scribe.Context(logfile, backtrace_len = 1)
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
            self.success()
        except scribe.DeadlockError:
            self.deadlocked()
        except scribe.DivergeError as diverge:
            self.diverged(diverge.event)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        ps.wait()

class RootExecution(Execution):
    def __init__(self, explorer):
        class DummyParent:
            pass
        parent = DummyParent()
        parent.explorer = explorer
        parent.session = load_session(explorer.logfile_path)
        Execution.__init__(self, parent, mutator.Nop())

    def __str__(self):
        return "0"

class Explorer:
    def __init__(self, logfile_path):
        self.logfile_path = logfile_path
        self.success = []
        self.failed = []
        self.todo = []
        self.make_mreplay_dir()
        self.root = RootExecution(self)

    def make_mreplay_dir(self):
        if os.path.exists(MREPLAY_DIR):
            shutil.rmtree(MREPLAY_DIR)
        os.makedirs(MREPLAY_DIR)

    def add_execution(self, execution):
        self.todo.append(execution)

    def run(self):
        stop_requested = [False]
        def do_stop(signum, stack):
            logging.info("Stop Requested")
            stop_requested[0] = True

        signal.signal(signal.SIGINT, do_stop)

        self.add_execution(self.root)
        while len(self.todo) > 0 and not stop_requested[0]:
            logging.info("-" * 80)
            logging.info("Success: %d, Failed: %d, Todo: %d" % \
                         (len(self.success), len(self.failed), len(self.todo)))
            logging.info("-" * 80)
            execution = self.todo.pop(0)
            execution.run()
            if execution.state == SUCCESS:
                self.success.append(execution)
            else:
                self.failed.append(execution)

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        print("")
        print("-"*80)
        print("Success: %d, Failed: %d, Todo: %d" % \
               (len(self.success), len(self.failed), len(self.todo)))
        print("-"*80)
        print("Summary of good executions:")
        for execution in self.success:
            print("%s:" % execution)
            execution.print_diff()
            print("")
