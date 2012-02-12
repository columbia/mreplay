from mutator import Mutator
import scribe
from mreplay.location import Location
from location_matcher import LocationMatcher

class DeleteEvent(Mutator):
    def __init__(self, event):
        self.event = event
        self.is_syscall = event.is_a(scribe.EventSyscallExtra)
        self.matcher = LocationMatcher(Location(event, 'before'))

    def __str__(self):
        return "d-%d:%d" % (self.event.proc.pid, self.event.index)

    def process_events(self, events):
        if self.event.is_a(scribe.EventSyscallExtra):
            skip_events = False
            for e in events:
                match = self.matcher.match(e)
                if match is not None:
                    if not e.is_a(scribe.EventSyscallExtra):
                        continue
                    skip_events = True

                if skip_events:
                    if e.is_a(scribe.EventSyscallEnd):
                        skip_events = False
                else:
                    yield e
        else:
            for e in events:
                match = self.matcher.match(e)
                if match is not None:
                    continue
                yield e
