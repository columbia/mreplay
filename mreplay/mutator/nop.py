from mutator import Mutator

class Nop(Mutator):
    def process_events(self, events):
        for event in events:
            yield event
