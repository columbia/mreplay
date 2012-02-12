from mutator import Mutator
from location_matcher import LocationMatcher

class InsertEvent(Mutator):
    def __init__(self, where, event):
        self.where = where
        self.event = event
        self.matcher = LocationMatcher(where)

    def __str__(self):
        return "I-%d:%d" % (self.where.obj.proc.pid, self.where.obj.index)

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                yield self.event
            yield event
