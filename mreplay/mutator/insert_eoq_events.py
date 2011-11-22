from mutator import Mutator
from mreplay import session
import scribe
import operator

class InsertEoqEvents(Mutator):
    def process_events(self, events):
        proc_eoq = dict()

        for e in events:
            proc = e.proc
            if proc is not None:
                proc_eoq[proc] = e.is_a(scribe.EventQueueEof)
            yield e

        procs = (proc for (proc, has_eoq) in proc_eoq.iteritems()
                 if not has_eoq)

        # Sorting make the test pass, it's actually not necessary
        for proc in sorted(procs, key=operator.attrgetter('pid')):
            yield session.Event(scribe.EventQueueEof(), proc)
