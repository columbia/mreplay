from mutator import Mutator
from location_matcher import LocationMatcher
from mreplay.session import Event
import scribe

class IgnoreSyscall(Mutator):
    def __init__(self, where):
        self.where = where
        self.matcher = LocationMatcher(where)

    def __str__(self):
        return "i-%d:%d" % (self.where.obj.proc.pid, self.where.obj.index)

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                ignore_event = scribe.EventIgnoreSyscall()
                yield Event(ignore_event, event.proc)
            yield event
