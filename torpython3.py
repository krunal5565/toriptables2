#!/usr/bin/env python3
"""
Tor Iptables script (Python 3 version)
Routes all outgoing traffic through Tor using iptables.
"""

import subprocess
import urllib.request
import urllib.error
import json
import time
import sys
import os
from argparse import ArgumentParser
from atexit import register
from os.path import isfile, basename


class TorIptables(object):
    def __init__(self):
        self.local_dnsport = "53"
        self.virtual_net = "10.0.0.0/10"
        self.local_loopback = "127.0.0.1"

        # Networks that should NOT go through Tor
        self.non_tor_net = ["192.168.0.0/16", "172.16.0.0/12"]
        self.non_tor = ["127.0.0.0/9", "127.128.0.0/10", "127.0.0.0/8"]

        # Most systems today use user "tor"
        self.tor_uid = subprocess.getoutput("id -ur tor")

        self.trans_port = "9040"
        self.tor_config_file = "/etc/tor/torrc"

        self.torrc = f"""
## Added by {basename(__file__)}
VirtualAddrNetwork {self.virtual_net}
AutomapHostsOnResolve 1
TransPort {self.trans_port}
DNSPort {self.local_dnsport}
"""

    def flush_iptables(self):
        subprocess.call(["iptables", "-F"])
        subprocess.call(["iptables", "-t", "nat", "-F"])

    def load_iptables(self):
        self.flush_iptables()
        self.non_tor.extend(self.non_tor_net)

        @register
        def restart_tor():
            try:
                subprocess.check_call(
                    ["systemctl", "restart", "tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print("\n[+] Tor restarted")
                self.get_ip()
            except subprocess.CalledProcessError as err:
                print(f"[!] Tor restart failed: {err}")

        # Drop invalid TCP packets
        subprocess.call([
            "iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d",
            self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp",
            "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP"
        ])

        subprocess.call([
            "iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d",
            self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp",
            "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP"
        ])

        # Exclude Tor user from redirection
        subprocess.call([
            "iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner",
            "--uid-owner", self.tor_uid, "-j", "RETURN"
        ])

        # Redirect DNS queries
        subprocess.call([
            "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp",
            "--dport", self.local_dnsport, "-j", "REDIRECT",
            "--to-ports", self.local_dnsport
        ])

        for net in self.non_tor:
            subprocess.call([
                "iptables", "-t", "nat", "-A", "OUTPUT",
                "-d", net, "-j", "RETURN"
            ])

        # Redirect all TCP SYN packets through Tor
        subprocess.call([
            "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp",
            "--syn", "-j", "REDIRECT", "--to-ports", self.trans_port
        ])

        # Accept established connections
        subprocess.call([
            "iptables", "-A", "OUTPUT", "-m", "state", "--state",
            "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])

        # Allow non-Tor networks normally
        for net in self.non_tor:
            subprocess.call(["iptables", "-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])

        # Allow Tor itself
        subprocess.call([
            "iptables", "-A", "OUTPUT", "-m", "owner",
            "--uid-owner", self.tor_uid, "-j", "ACCEPT"
        ])

        # Everything else must go via Tor
        subprocess.call(["iptables", "-A", "OUTPUT", "-j", "REJECT"])

    def get_ip(self):
        print("[*] Getting public IP through Tor...")

        retries = 0
        my_ip = None

        while retries < 8 and not my_ip:
            retries += 1
            try:
                response = urllib.request.urlopen("https://check.torproject.org/api/ip", timeout=10)
                data = json.load(response)
                my_ip = data.get("IP")
            except urllib.er
