import socket
import errno
import os
import ipaddress
from ctypes import cdll, c_int, c_char_p

global _lib_load_err, _lib
_lib_load_err = None
_lib = None

class MulticastException(Exception):
    pass

def _pull_error_msgs():
    global _lib_load_err, _lib
    if _lib_load_err is not None:
        raise _lib_load_err
    assert(_lib)
    errcount = _lib.errmsg_count()
    msgs = []
    for i in range(errcount):
        msgs.append(str(_lib.errmsg(i)))
    done_errcount = _lib.errmsg_count()
    if errcount != done_errcount:
        msgs.append('error: libpymcast error count changed (%d to %d) while enumerating' % (errcount, done_errcount))
        if done_errcount > errcount:
            for i in range(errcount, done_errcount):
                msgs.append(str(_lib.errmsg(i)))
    _lib.clear_errors()
    return msgs

def join_ssm(sock, source, group, if_idx):
    global _lib_load_err, _lib
    if _lib_load_err is not None:
        raise _lib_load_err
    assert(_lib)

    src_ip = ipaddress.ip_address(source)
    grp_ip = ipaddress.ip_address(group)

    if src_ip.version != grp_ip.version:
        raise MulticastException('Join(S=%s,G=%s) mismatched IP addresses' %
                (src_ip, grp_ip))

    if not grp_ip.is_multicast:
        raise MulticastException('Join(S=%s,G=%s) non-multicast group' %
                (src_ip, grp_ip))

    result = _lib.join_ssm(sock.fileno(), if_idx, src_ip.version,
            src_ip.packed, grp_ip.packed)

    if result != 0:
        raise MulticastException('\n'.join(_pull_error_msgs()))

def join_asm(sock, source, group, ifname):
    raise MulticastException("join_asm: unsupported")
    pass

def _on_load():
    global _lib_load_err, _lib
    tapspath = os.path.abspath(os.path.dirname(__file__))
    libpath = os.path.join(tapspath, 'libpymcast.so')
    _lib_load_err = None
    try:
        _lib = cdll.LoadLibrary(libpath)
        _lib.errmsg.restype = c_char_p
        if _lib.errmsg_count() != 0:
            _lib_load_err = YangException()
    except Exception as ex:
        _lib = None
        _lib_load_err = ex

_on_load()
