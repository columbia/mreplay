from mutator import Mutator
import scribe
from mreplay.location import Location
from location_matcher import LocationMatcher

class DeleteEvent(Mutator):
    def __init__(self, events):
        if not isinstance(events, list):
            events = [events]
        self.events = list(events)
        self.matcher = LocationMatcher(map(lambda e: Location(e, 'before'), self.events))

    def __str__(self):
        return "d-%d:%s" % (self.events[0].proc.pid,
                ','.join(map(lambda e: str(e.index), self.events)))

    def process_events(self, events):
        syscall_depth = 0
        res_depth = 0
        for e in events:
            match = self.matcher.match(e)
            if match is not None or syscall_depth > 0 or res_depth > 0:
                if e.is_a(scribe.EventSyscallExtra):
                    syscall_depth += 1
                elif e.is_a(scribe.EventResourceLock):
                    res_depth += 1
                elif e.is_a(scribe.EventSyscallEnd):
                    syscall_depth -= 1
                elif e.is_a(scribe.EventResourceUnlock):
                    res_depth -= 1
            else:
                yield e
