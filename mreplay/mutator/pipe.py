from mutator import Mutator

class Pipe(Mutator):
    def __init__(self, lmutator, rmutator):
        self.lmutator = lmutator
        self.rmutator = rmutator

    def start(self, env):
        self.lmutator.start(env)
        self.rmutator.start(env)

    def process_events(self, events):
        events = self.lmutator.process_events(events)
        events = self.rmutator.process_events(events)
        return events
