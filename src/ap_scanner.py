#!/usr/bin/env python


from scapy.all import Dot11, sniff


class Scanner(object):

    def __init__(self, iface="mon0", duration=None):
        self.ap_list = {}
        self.iface = iface
        self.duration = duration

    def flush(self):
        self.ap_list = {}

    def scan(self):
        self.flush()
        try:
            print "start scanning on %s.." % self.iface
            sniff(iface=self.iface, prn=self._packet_handler)
    #   except Exception as e:
    #       print "Error %s " % e.message_
        except KeyboardInterrupt:
            print "stop scanning.."
        return self.ap_list

    def _packet_handler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:
                if pkt.addr2 not in self.ap_list.keys():
                    self.ap_list[pkt.addr2] = pkt.info
                    print "AP MAC: %s, SSID: %s" % (pkt.addr2, pkt.info)

if __name__ == "__main__":
    scanner = Scanner("mon0")
    scanner.scan()
    inp = raw_input("Press enter to exit..\n")
