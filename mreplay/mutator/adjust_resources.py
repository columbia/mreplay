from mutator import Mutator
import scribe
from mreplay import session

class AdjustResources(Mutator):
    """ Rewrite all serial numbers of resources.
        Sadly this is a two pass mechanism.
    """
    def process_events(self, events):
        events = list(events)

        serials = dict()
        for e in events:
            if e.is_a(scribe.EventResourceLockExtra):
                if e.id not in serials:
                    serials[e.id] = dict()
                if e.serial not in serials[e.id]:
                    serials[e.id][e.serial] = 1
                else:
                    serials[e.id][e.serial] += 1

        for id_serials in serials.values():
            last_i = None
            for i in sorted(id_serials.keys()):
                if last_i == None:
                    last_i = i
                    last_serial = id_serials[i]
                    id_serials[i] = 0
                    continue
                deficit = i - last_serial
                last_serial += id_serials[i]
                id_serials[i] = i - deficit
                last_i = i

        for e in events:
            if e.is_a(scribe.EventResourceLockExtra):
                if e.serial != serials[e.id][e.serial]:
                    ee = e.copy()
                    ee.serial = serials[e.id][e.serial]
                    e = session.Event(ee, e.proc)
            yield e
