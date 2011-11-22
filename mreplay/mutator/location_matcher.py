from mreplay.session import Event
from mreplay.location import Start, End
import scribe

class LocationMatcher:
    def __init__(self, matchers):
        if isinstance(matchers, list):
            matchers = dict((m, None) for m in matchers)
        if not isinstance(matchers, dict):
            matchers = {matchers: None}
        for k in matchers.keys():
            if matchers[k] is None:
                if k.before:
                    matchers[k] = 'before'
                else:
                    matchers[k] = 'after'

        self.before = dict((k.obj,v) for (k,v) in matchers.items() if k.before)
        self.after  = dict((k.obj,v) for (k,v) in matchers.items() if k.after)

        # When maching on a after syscall, we need to match only after the
        # end syscall.
        self.convert_after_to_end_syscalls()

        #######################################################################
        # XXX Because things don't work well when chaining Mutators with the
        # after matcher (events would be processed in the reverse order), we
        # convert all after matchers in before matchers.
        #######################################################################
        self.convert_after_to_before()

    def convert_after_to_end_syscalls(self):
        def after_end_sys(obj):
            if isinstance(obj, Event) and obj.is_a(scribe.EventSyscallExtra):
                for next_event in obj.proc.events.after(obj):
                    if next_event.is_a(scribe.EventSyscallEnd):
                        return next_event
            return obj

        self.after = dict(map(lambda (k,v): (after_end_sys(k), v), \
                              self.after.items()))

    def convert_after_to_before(self):
        for (obj,v) in self.after.items():
            proc = obj.proc
            if obj.is_a(Start):
                next_obj = proc.events[0]
            elif obj.is_a(End):
                next_obj = obj
            else:
                next_obj = obj.next_event()
                #next_obj = obj.proc.events.after(obj).next()
                if next_obj is None:
                    raise 'FIXME matching after the last event is problematic for now'
            if self.before.has_key(next_obj):
                raise 'FIXME before/after collapse'
            self.before[next_obj] = v

    def match(self, event):
        return self.before.get(event)
