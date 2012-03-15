from mutator import Mutator

class Replace(Mutator):
    def __init__(self, replacements):
        self.replacements = replacements

    def __str__(self):
        return "r-" + ",".join(map(lambda e: "%d:%d" % (e.proc.pid, e.index),
                                   self.replacements.keys()))

    def process_events(self, events):
        for event in events:
            if self.replacements.has_key(event):
                event = self.replacements[event]
            yield event
