from mutator import Mutator

class Replace(Mutator):
    def __init__(self, replacements):
        self.replacements = replacements

    def process_events(self, events):
        for event in events:
            if self.replacements.has_key(event):
                event = self.replacements[event]
            yield event
