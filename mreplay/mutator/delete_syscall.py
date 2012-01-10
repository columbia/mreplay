from mutator import Mutator
import scribe
from mreplay.location import Location
from location_matcher import LocationMatcher

class DeleteSyscall(Mutator):
    def __init__(self, syscall):
        self.syscall = syscall
        self.matcher = LocationMatcher(Location(syscall, 'before'))

    def __str__(self):
        return "d-%d:%d" % (self.syscall.proc.pid, self.syscall.index)

    def process_events(self, events):
        skip_events = False
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                if not event.is_a(scribe.EventSyscallExtra):
                    continue
                skip_events = True

            if skip_events:
                if event.is_a(scribe.EventSyscallEnd):
                    skip_events = False
            else:
                yield event
