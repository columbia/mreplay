from mutator import Mutator
from mreplay import session
import scribe

class InsertPidEvents(Mutator):
    def process_events(self, events):
        current = None
        for e in events:
            if e.is_a(scribe.EventPid):
                continue
            proc = e.proc
            if proc != current:
                yield session.Event(scribe.EventPid(proc.pid))
                current = proc
            yield e
