from mutator import Mutator
import scribe
import mreplay.unistd

class SplitOnBookmark(Mutator):
    def __init__(self, cutoff=0, do_tail=False):
        self.cutoff = cutoff
        self.do_tail = do_tail
        self.do_head = not do_tail
        self.output_pid = 0
        self.stream_tail = False

    # Output event, adding pid if necessary
    def output(self, pid, e):
        # pid 0 only occurs once
        if self.output_pid != pid:
            yield scribe.EventPid(pid=pid)
            self.output_pid = pid
        yield e

    def output_head(self, pid, e):
        if self.do_head:
            for x in self.output(pid, e):
                yield x

    def output_tail(self, pid, e):
        if self.do_tail:
            for x in self.output(pid, e):
                yield x

    def process_events(self, events):
        pending_events = {}
        children = {}
        streaming = {}
        done = {}

        pid = 0

        bookmarks_count = 0
        npr = None

        def add_child(parent, child):
            if parent not in children:
                children[parent] = []
            children[parent].append(child)

        def add_pending(pid, event):
            if pid not in pending_events:
                pending_events[pid] = []
            pending_events[pid].append(event)

        def include_child(pid):
            for e in pending_events.get(pid, []):
                for x in self.output_head(pid, e):
                    yield x
            for c in children.get(pid, []):
                for x in include_child(c):
                    yield x
                if c not in done:
                    streaming[c] = True
            pending_events[pid] = []

        for e in events:
            if isinstance(e, scribe.EventPid):
                pid = e.pid
                continue

            if self.stream_tail:
                for x in self.output_tail(pid, e):
                    yield x
                continue

            if npr == bookmarks_count and len(streaming) == 0:
                if self.do_head:
                    return
                else:
                    add_pending(pid, e)
                    for (pid, events) in pending_events.items():
                        for e in events:
                            for x in self.output_tail(pid, e):
                                yield x
                    pending_events.clear()
                    self.stream_tail = True
                    continue

            if pid in done:
                for x in self.output_tail(pid, e):
                    yield x
                continue;

            if pid == 0:
                for x in self.output_head(pid, e):
                    yield x
                continue

            if isinstance(e, scribe.EventBookmark) and \
                    e.id == self.cutoff:
                npr = e.npr
                bookmarks_count += 1
                for x in include_child(pid):
                    yield x
                for x in self.output_head(pid, e):
                    yield x
                done[pid] = True
                if pid in streaming:
                    del streaming[pid]

                continue

            if isinstance(e, scribe.EventSyscallExtra) \
                    and e.nr in mreplay.unistd.SYS_fork \
                    and e.ret > 0:
                add_child(pid, e.ret)

            if pid in streaming:
                for x in self.output_head(pid, e):
                    yield x
            else:
                add_pending(pid, e)

            if isinstance(e, scribe.EventQueueEof):
                # Delete from streaming so that we can count streaming. This
                # won't affect correctness and is only an optimization because
                # EOF is the last event for a pid by contract.
                # Note: the event is already yielded
                done[pid] = True
                if pid in streaming:
                    del streaming[pid]

        if npr != bookmarks_count:
            for pid in pending_events:
                for e in pending_events[pid]:
                    for x in self.output_head(pid, e):
                        yield x
