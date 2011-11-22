from mutator import Mutator
from location_matcher import LocationMatcher
from mreplay.session import Event
import scribe

class Bookmark(Mutator):
    def __init__(self, bmarks):
        self.num_procs = len(bmarks)
        self.matcher = LocationMatcher(bmarks)

    def start(self, env):
        self.bookmark_id = env.get('next_bookmark_id', 0)
        env['next_bookmark_id'] = self.bookmark_id + 1

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                bmark_event = scribe.EventBookmark()
                if match == 'before':
                    bmark_event.type = scribe.SCRIBE_BOOKMARK_PRE_SYSCALL
                else:
                    bmark_event.type = scribe.SCRIBE_BOOKMARK_POST_SYSCALL
                bmark_event.id = self.bookmark_id
                bmark_event.npr = self.num_procs
                yield Event(bmark_event, event.proc)

            if not (event.is_a(scribe.EventBookmark) and
                    self.bookmark_id == 0):
                yield event
