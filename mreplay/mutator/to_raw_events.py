from mutator import Mutator
import scribe

class ToRawEvents(Mutator):
    def process_events(self, events):
        for event in events:
            scribe_event = event._scribe_event
            if isinstance(scribe_event, scribe.Event):
                yield scribe_event

