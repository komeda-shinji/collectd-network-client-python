import re
import time
import socket
import struct
import logging
import traceback
from functools import wraps
from Queue import Queue, Empty
from collections import defaultdict
from threading import RLock, Thread, Semaphore


__all__ = ["Connection", "start_threads"]

__version_info__ = (1, 0, 2, "final", 0)
__version__ = "{0}.{1}.{2}".format(*__version_info__)

logger = logging.getLogger("collectd")

SEND_INTERVAL = 10      # seconds
MAX_PACKET_SIZE = 1024  # bytes

PLUGIN_TYPE = "gauge"

TYPE_HOST            = 0x0000
TYPE_TIME            = 0x0001
TYPE_PLUGIN          = 0x0002
TYPE_PLUGIN_INSTANCE = 0x0003
TYPE_TYPE            = 0x0004
TYPE_TYPE_INSTANCE   = 0x0005
TYPE_VALUES          = 0x0006
TYPE_INTERVAL        = 0x0007
LONG_INT_CODES = [TYPE_TIME, TYPE_INTERVAL]
STRING_CODES = [TYPE_HOST, TYPE_PLUGIN, TYPE_PLUGIN_INSTANCE, TYPE_TYPE, TYPE_TYPE_INSTANCE]

VALUE_COUNTER  = 0
VALUE_GAUGE    = 1
VALUE_DERIVE   = 2
VALUE_ABSOLUTE = 3
VALUE_CODES = {
    VALUE_COUNTER:  "!Q",
    VALUE_GAUGE:    "<d",
    VALUE_DERIVE:   "!q",
    VALUE_ABSOLUTE: "!Q"
}
DS_TYPES = {
    'COUNTER':  VALUE_COUNTER,
    'GAUGE':    VALUE_GAUGE,
    'DERIVE':   VALUE_DERIVE,
    'ABSOLUTE': VALUE_ABSOLUTE
}


def pack_numeric(type_code, number):
    return struct.pack("!HHq", type_code, 12, number)

def pack_string(type_code, string):
    return struct.pack("!HH", type_code, 5 + len(string)) + string + "\0"

def pack_value(name, value, type=VALUE_GAUGE):
    packed = []
    if isinstance(value, (list, tuple)):
        packed.append(struct.pack("!HHH", TYPE_VALUES, 6 + 9*len(value), len(value)))
        for v in value:
            packed.append(struct.pack("<B", type))
        for v in value:
            packed.append(struct.pack("<d", v))
    else:
        if name != 'value':
            packed.append(pack(TYPE_TYPE_INSTANCE, name))
        packed.append(struct.pack("!HHH", TYPE_VALUES, 15, 1))
        packed.append(struct.pack("<Bd", type, value))
    return "".join(packed)

def pack(id, value):
    if isinstance(id, basestring):
        return pack_value(id, value)
    elif id in LONG_INT_CODES:
        return pack_numeric(id, value)
    elif id in STRING_CODES:
        return pack_string(id, value)
    else:
        raise AssertionError("invalid type code " + str(id))

def message_start(when=None, host=socket.gethostname(), plugin_inst="", plugin_name="any", type_name=""):
    packed = []
    packed.append(pack(TYPE_HOST, host))
    packed.append(pack(TYPE_TIME, when or time.time()))
    packed.append(pack(TYPE_PLUGIN, plugin_name))
    if plugin_inst:
        packed.append(pack(TYPE_PLUGIN_INSTANCE, plugin_inst))
    packed.append(pack(TYPE_TYPE, type_name))
    packed.append(pack(TYPE_INTERVAL, SEND_INTERVAL))
    return "".join(packed)

def messages(counts, when=None, host=socket.gethostname(), plugin_inst="", plugin_name="any", type_name="", value_type=None):
    packets = []
    start = message_start(when, host, plugin_inst, plugin_name, type_name)

    if isinstance(counts, dict):
        parts = []
        for name,count in counts.items():
            if isinstance(count, (list, tuple)):
                if value_type is None:
                    if Counter._counters.has_key(name) and Counter._counters[name].types.has_key(name):
                        value_type = Counter._counters[name].types[name]
                    else:
                        value_type = VALUE_GAUGE
                parts.append(pack(TYPE_TYPE, name))
                parts.append(pack_value('values', count, value_type))
            else:
                if isinstance(name, tuple):
                    parts.append(pack(TYPE_TYPE, name[0]))
                    if len(name) == 2:
                        parts.append(pack(name[1], count))
                    elif len(name) == 3:
                        parts.append(pack('%s-%s' % name[1:], count))
                else:
                    parts.append(pack(name, count))
    elif isinstance(counts, list):
        if type_name and Counter._counters.has_key(type_name):
            if Counter._counters[name].types.has_key(type_name):
                value_type = Counter._counters[name].types[type_name]
        parts = [pack_value('values', counts, value_type)]
    else:
        parts = [pack('value', counts)]
    parts = [p for p in parts if len(start) + len(p) <= MAX_PACKET_SIZE]
    if parts:
        curr, curr_len = [start], len(start)
        for part in parts:
            if curr_len + len(part) > MAX_PACKET_SIZE:
                packets.append("".join(curr))
                curr, curr_len = [start], len(start)
            curr.append(part)
            curr_len += len(part)
        packets.append("".join(curr))
    return packets



def sanitize(s):
    return re.sub(r"[^a-zA-Z0-9]+", "_", s).strip("_")

def swallow_errors(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            try:
                logger.error("unexpected error", exc_info = True)
            except:
                pass
    return wrapped

def synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped

class Counter(object):
    _counters = {}

    def __init__(self, category):
        self.category = category
        self._lock = RLock()
        self.counts = defaultdict(lambda: defaultdict(float))
        self.types = defaultdict(lambda: VALUE_GAUGE)
        self.__class__._counters[category] = self
    
    @swallow_errors
    @synchronized
    def record(self, *args, **kwargs):
        for specific in list(args) + [""]:
            assert isinstance(specific, basestring)
            for stat, value in kwargs.items():
                if isinstance(value, (list, tuple)):
                    self.is_list = True
                    for i, v in enumerate(value):
                        assert isinstance(v, (int, float))
                        self.counts[str(specific)][i] += v
                else:
                    assert isinstance(value, (int, float))
                    self.counts[str(specific)][str(stat)] += value
    
    @swallow_errors
    @synchronized
    def set_type(self, **kwargs):
        for stat, type in kwargs.items():
            assert type in DS_TYPES.keys()
            self.types[str(stat)] = DS_TYPES[type]
    
    @swallow_errors
    @synchronized
    def get_type(self, stat):
        if self.types.has_key(str(stat)):
            return self.types[str(stat)]
    
    @swallow_errors
    @synchronized
    def set_exact(self, **kwargs):
        for stat, value in kwargs.items():
            if isinstance(value, (list, tuple)):
                self.is_list = True
                for i, v in enumerate(value):
                    assert isinstance(v, (int, float))
                    self.counts[""][i] = v
            else:
                assert isinstance(value, (int, float))
                self.counts[""][str(stat)] = value
    
    @synchronized
    def get_exact(self, *args):
        if args:
            counts = {}
            for stat in args:
                if self.counts[""].has_key(stat):
                    counts[stat] = self.counts[""][stat]
            return counts
        else:
            return dict([(self.category, [v for i, v in sorted(self.counts[""].items())])])

    @synchronized
    def snapshot(self, extend=False):
        if hasattr(self, 'is_list'):
            return dict([(self.category, [v for i, v in sorted(self.counts[""].items())])])
        totals = {}
        for specific,counts in self.counts.items():
            for stat in counts:
                name_parts = map(sanitize, [self.category, specific, stat])
                if extend:
                    if specific:
                        name = tuple(name_parts[0:2])
                    else:
                        name = (name_parts[0], name_parts[2])
                else:
                    name = "-".join(name_parts).replace("--", "-")
                totals[name] = counts[stat]
                counts[stat] = 0.0
        return totals

class Connection(object):
    _lock = RLock() # class-level lock, only used for __new__
    instances = {}
    
    @synchronized
    def __new__(cls, hostname = socket.gethostname(),
                     collectd_host = "localhost", collectd_port = 25826,
                     plugin_inst = "", plugin_name = "any"):
        id = (hostname, collectd_host, collectd_port, plugin_inst, plugin_name)
        if id in cls.instances:
            return cls.instances[id]
        else:
            inst = object.__new__(cls)
            cls.instances[id] = inst
            return inst
    
    def __init__(self, hostname = socket.gethostname(),
                       collectd_host = "localhost", collectd_port = 25826,
                       plugin_inst = "", plugin_name = "any"):
        if "_counters" not in self.__dict__:
            self._lock = RLock()
            self._counters = {}
            self._plugin_inst = plugin_inst
            self._plugin_name = plugin_name
            self._hostname = hostname
            self._collectd_addr = (collectd_host, collectd_port)
    
    @synchronized
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError("{0} object has no attribute {1!r}".format(self.__class__.__name__, name))
        
        if name not in self._counters:
            self._counters[name] = Counter(name)
        return self._counters[name]
    
    @synchronized
    def _snapshot(self, extend=False):
        return [c.snapshot(extend) for c in self._counters.values() if c.counts]



snaps = Queue()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def take_snapshots():
    for conn in Connection.instances.values():
        snapshots = conn._snapshot()
        if snapshots:
            stats = {}
            for snapshot in snapshots:
                stats.update(snapshot)
            snaps.put([int(time.time()), stats, conn])

def send_stats(raise_on_empty = False):
    try:
        when, stats, conn = snaps.get(timeout = 0.1)
        for message in messages(stats, when, conn._hostname, conn._plugin_inst, conn._plugin_name):
            sock.sendto(message, conn._collectd_addr)
    except Empty:
        if raise_on_empty:
            raise

def daemonize(func, sleep_for = 0):
    @wraps(func)
    def wrapped():
        while True:
            try:
                func()
            except:
                try:
                    logger.error("unexpected error", exc_info = True)
                except:
                    traceback.print_exc()
            time.sleep(sleep_for)
    
    t = Thread(target = wrapped)
    t.daemon = True
    t.start()

single_start = Semaphore()
def start_threads():
    assert single_start.acquire(blocking = False)
    daemonize(take_snapshots, sleep_for = SEND_INTERVAL)
    daemonize(send_stats)
