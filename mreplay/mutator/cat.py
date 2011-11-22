from mutator import Mutator

class Cat(Mutator):
    def __init__(self, events):
        self.events = events

    def process_events(self, _):
        return self.events
