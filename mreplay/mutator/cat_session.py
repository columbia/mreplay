from mutator import Mutator

class CatSession(Mutator):
    def __init__(self, session):
        self.session = session

    def start(self, env):
        env['session'] = self.session

    def process_events(self, _):
        yield self.session.events[0]
        for proc in self.session.processes.values():
            for event in proc.events:
                yield event
