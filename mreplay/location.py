class Location:
    def __init__(self, obj, loc):
        self.obj = obj
        if loc == 'before':
            self.before = True
            self.after = False
        elif loc == 'after':
            self.before = False
            self.after = True
        else:
            raise ValueError

    def __eq__(self, nl):
        return self.obj == nl.obj and self.before == nl.before

    def __hash__(self):
        return hash(self.obj) ^ hash(self.before)

    def __repr__(self):
        return ('a' if self.after else 'b') + repr(self.obj)

class Start:
    def __str__(self):
        return 'start'

    @property
    def index(self):
        return 0

class End:
    def __str__(self):
        return 'end'

    @property
    def index(self):
        return -1
