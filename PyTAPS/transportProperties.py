from enum import Enum
import json


class PreferenceLevel(Enum):
    REQUIRE = 2
    PREFER = 1
    IGNORE = 0
    AVOID = -1
    PROHIBIT = -2


def get_protocols():
    protocols = []
    tcp = """{
        "name": "tcp",
        "reliability": true,
        "preserve-msg-boundaries": false,
        "per-msg-reliability": false,
        "preserve-order": true,
        "zero-rtt-msg": true,
        "multistreaming": false,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": true,
        "multipath": false,
        "direction": "Bidirectional",
        "retransmit-notify": true,
        "soft-error-notify": true
    }"""
    udp = """{
        "name": "udp",
        "reliability": false,
        "preserve-msg-boundaries": true,
        "per-msg-reliability": false,
        "preserve-order": false,
        "zero-rtt-msg": true,
        "multistreaming": false,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": false,
        "multipath": false,
        "direction": "Bidirectional",
        "retransmit-notify": false,
        "soft-error-notify": true
    }"""
    tls = """{
        "name": "tls",
        "reliability": true,
        "preserve-msg-boundaries": false,
        "per-msg-reliability": false,
        "preserve-order": true,
        "zero-rtt-msg": true,
        "multistreaming": false,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": true,
        "multipath": false,
        "direction": "Bidirectional",
        "retransmit-notify": false,
        "soft-error-notify": false
    }"""
    dtls = """{
        "name": "dtls",
        "reliability": false,
        "preserve-msg-boundaries": true,
        "per-msg-reliability": false,
        "preserve-order": false,
        "zero-rtt-msg": false,
        "multistreaming": false,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": false,
        "multipath": false,
        "direction": "Bidirectional",
        "retransmit-notify": false,
        "soft-error-notify": true
    }"""
    sctp = """{
        "name": "sctp",
        "reliability": true,
        "preserve-msg-boundaries": true,
        "per-msg-reliability": true,
        "preserve-order": true,
        "zero-rtt-msg": false,
        "multistreaming": true,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": true,
        "multipath": true,
        "direction": "Bidirectional",
        "retransmit-notify": true,
        "soft-error-notify": false
    }"""
    quic = """{
        "name": "quic",
        "reliability": true,
        "preserve-msg-boundaries": false,
        "per-msg-reliability": false,
        "preserve-order": true,
        "zero-rtt-msg": true,
        "multistreaming": true,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": true,
        "multipath": false,
        "direction": "Bidirectional",
        "retransmit-notify": false,
        "soft-error-notify": true
    }"""
    mptcp = """{
        "name": "mptcp",
        "reliability": true,
        "preserve-msg-boundaries": false,
        "per-msg-reliability": false,
        "preserve-order": true,
        "zero-rtt-msg": true,
        "multistreaming": true,
        "per-msg-checksum-len-send": false,
        "per-msg-checksum-len-recv": false,
        "congestion-control": true,
        "multipath": true,
        "direction": "Bidirectional",
        "retransmit-notify": true,
        "soft-error-notify": true
    }"""
    protocols.append(json.loads(tcp))
    protocols.append(json.loads(udp))
    # protocols.append(json.loads(tls))
    # protocols.append(json.loads(dtls))
    # protocols.append(json.loads(sctp))
    # protocols.append(json.loads(quic))
    # protocols.append(json.loads(mptcp))
    return protocols

class TransportProperties:
    """ Class to handle the TAPS transport properties

    """
    def __init__(self):
        self.properties = {
            "reliability": PreferenceLevel.REQUIRE,
            "preserve-msg-boundaries": PreferenceLevel.PREFER,
            "per-msg-reliability": PreferenceLevel.IGNORE,
            "preserve-order": PreferenceLevel.REQUIRE,
            "zero-rtt-msg": PreferenceLevel.PREFER,
            "multistreaming": PreferenceLevel.PREFER,
            "per-msg-checksum-len-send": PreferenceLevel.IGNORE,
            "per-msg-checksum-len-recv": PreferenceLevel.IGNORE,
            "congestion-control": PreferenceLevel.REQUIRE,
            "multipath": PreferenceLevel.PREFER,
            "direction": "Bidirectional",
            "retransmit-notify": PreferenceLevel.IGNORE,
            "soft-error-notify": PreferenceLevel.IGNORE
        }

    def add(self, prop, value):
        self.properties[prop] = value

    def require(self, prop):
        self.properties[prop] = PreferenceLevel.REQUIRE

    def prefer(self, prop):
        self.properties[prop] = PreferenceLevel.PREFER

    def ignore(self, prop):
        self.properties[prop] = PreferenceLevel.IGNORE

    def avoid(self, prop):
        self.properties[prop] = PreferenceLevel.AVOID

    def prohibit(self, prop):
        self.properties[prop] = PreferenceLevel.PROHIBIT

    def default(self, prop):
        defaults = {
            "reliability": PreferenceLevel.REQUIRE,
            "preserve-msg-boundaries": PreferenceLevel.PREFER,
            "per-msg-reliability": PreferenceLevel.IGNORE,
            "preserve-order": PreferenceLevel.REQUIRE,
            "zero-rtt-msg": PreferenceLevel.PREFER,
            "multistreaming": PreferenceLevel.PREFER,
            "per-msg-checksum-len-send": PreferenceLevel.IGNORE,
            "per-msg-checksum-len-recv": PreferenceLevel.IGNORE,
            "congestion-control": PreferenceLevel.REQUIRE,
            "multipath": PreferenceLevel.PREFER,
            "direction": "Bidirectional",
            "retransmit-notify": PreferenceLevel.IGNORE,
            "soft-error-notify": PreferenceLevel.IGNORE
        }
        self.properties[prop] = defaults.get(prop)