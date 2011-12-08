from mutator import Mutator
from location_matcher import LocationMatcher
from mreplay.session import Event
from mreplay.location import Location, Start
import scribe

class SetFlags(Mutator):
    def __init__(self, where, flags, duration):
        self.where = where
        self.flags = flags
        self.duration = duration
        self.matcher = LocationMatcher(where)

    def __str__(self):
        return "i-%d:%d" % (self.where.obj.proc.pid, self.where.obj.index)

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                ignore_event = scribe.EventSetFlags(self.flags, self.duration)
                yield Event(ignore_event, event.proc)
            yield event

class IgnoreNextSyscall(SetFlags):
    def __init__(self, where):
        SetFlags.__init__(self, where, 0, scribe.SCRIBE_UNTIL_NEXT_SYSCALL)

class MutateOnTheFly(SetFlags):
    def __init__(self, session):
        SetFlags.__init__(self, Location(Event(Start(), session.init_proc), 'after'),
                          scribe.SCRIBE_PS_ENABLE_ALL & ~scribe.SCRIBE_PS_ENABLE_STRICT_RPY,
                          scribe.SCRIBE_PERMANANT)
