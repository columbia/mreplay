from mutator import Mutator
from location_matcher import LocationMatcher

class InsertEvent(Mutator):
    def __init__(self, where, events):
        if not isinstance(events, list):
            events = [events]
        events = list(events)
        self.where = where
        self.events = events
        self.matcher = LocationMatcher(where)

    def __str__(self):
        return "I-%d:%d" % (self.where.obj.proc.pid, self.where.obj.index)

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                for e in self.events:
                    yield e
            yield event
