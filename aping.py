#! /usr/bin/env python
# -*- coding: utf-8 -*-

# *****************************************************************************
# aping.py --> main program module                                            *
#                                                                             *
# *****************************************************************************
# Copyright (C) 2007, 2008 Kantor A. Zsolt <kantorzsolt@yahoo.com>            *
# Overtaken and maintained by Emmanuel Arias <emmanuelarias30@gmail.com>      *
# *****************************************************************************
# This file is part of APing.                                                 *
#                                                                             *
# APing is free software; you can redistribute it and/or modify               *
# it under the terms of the GNU General Public License as published by        *
# the Free Software Foundation; either version 3 of the License, or           *
# (at your option) any later version.                                         *
#                                                                             *
# Aping is distributed in the hope that it will be useful,                    *
# but WITHOUT ANY WARRANTY; without even the implied warranty of              *
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               *
# GNU General Public License for more details.                                *
#                                                                             *
# You should have received a copy of the GNU General Public License           *
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       *
# *****************************************************************************


import sys
import struct
import os
import re
import random
import signal
import binascii
import getopt
import time
import socket
import array
import fcntl
import thread
import subprocess
from default import *


def calcsum(sum_data):
    """The packet checksum algorithm (the one's complement sum of 16-bit words)
    Generates a checksum of a (ICMP) packet. Based on the function found in
    ping.c on FreeBSD.
    """
    # add byte if not dividable by 2
    if len(sum_data) & 1:
        sum_data += '\0'
    # split into 16 bit word and insert into a binary array
    words = array.array('H', sum_data)
    sum = 0
    # perform ones complement arithmetic on 16-bit words
    for word in words:
        sum += (word & 0xffff)
    hi = sum >> 16
    lo = sum & 0xffff
    sum = hi + lo
    sum += (sum >> 16)
    return struct.pack('H', (~sum & 0xffff))


class ICMPprobe:
    """
    The program main class. Handles all the important stuff.
    From here are sent the ICMP packets
    """

    def __init__(self):
        """This method initiates the ICMPprobe class."""
        # the signal handler for the ctrl + c keyboard interrupt (SIGINT)
        signal.signal(signal.SIGINT, self.sighandler)
        socket.setdefaulttimeout(listen_timeout)  # Default value is 2sec
        # creates the raw socket, if the user has no root privileges then stop
        try:
            self.rawicmp = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self.rawicmp.bind((bind_addr, 0))  # bind the socket to an IP address
        except socket.error, error_msg:
            if error_msg[0] == 1:
                sys.exit("\nAPing: You must have root (superuser) privileges to run APing")
            elif error_msg[0] == 99:
                sys.exit("""\nAPing: Can't bind socket to specified address: %s
                \rThe IP address must to exist on your interface""" % bind_addr)

        # set up some socket option
        self.rawicmp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, time_to_live)
        self.rawicmp.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, ip_tos)

        # initiating some variables
        self.send_delay = send_delay
        self.pkg_sent = 0
        self.pkg_recv = 0
        self.rtt_sum = 0
        self.rtt_max = 0
        self.rtt_min = 90000
        self.code = "\0"
        self.retrans = 0
        self.addr_mask = ''
        self.tmstamp_req = ''
        self.extradata = ''

        # generate a random identifier and create a 16 bit big-endian structure
        self.ident = struct.pack('!H', random.randrange(1, 65536))

        # generates some extra bytes, if specified by the user
        self.payload = self.data_gen()

        # selecting, setting up the probe type
        if probe_type == 'p':
            self.types = "\x08"
            self.strint_type = "8(echo request)"
        elif probe_type == 'i':
            self.types = "\x0f"
            self.strint_type = "15(information request)"
        elif probe_type == 'm':
            self.types = "\x11"
            self.addr_mask = "\0\0\0\0"
            self.strint_type = "17(address mask request)"
        elif probe_type == 't':
            self.types = "\x0d"
            self.strint_type = "13(timestamp request)"
            self.tmstamp_req = "\0\0\0\0\0\0\0\0\0\0\0\0"

        # calculate the sent packets length
        self.length = 8 + extra_data + len(self.tmstamp_req + self.addr_mask)

        # check if the target address is one of the local machines IP
        # This way we know that the source and destination address could be the
        # same this means that we must flush the buffer (with recv()) to avoid
        # reception of the (just) sent packet as the response for the probe
        self.islocal = 0

        # if address is null, starts by 127 or is attached to a network iface, then we assume it
        # is an address for localhost
        a, b, c, d = ip_dst_address.split('.')
        if int(a) == int(b) == int(c) == int(d) == 0:
            self.islocal = 1
        elif int(a) == 127:
            self.islocal = 1
        else:
            for iface in self.listNetDevices():
                if ip_dst_address == self.getProtoAddrFromIface(iface):
                    self.islocal = 1
                    break
        # -------------------------- #
        # initializate the thread
        thread.start_new_thread(self.ondemandinfo, ())
        # read the time for the total elapsed time
        self.start_time = time.time()

    def listNetDevices(self):
        """
        List all the local network ifaces
        """
        if_singleMaxLen = 32  # interface max name length
        if_totalNamesLen = 2048  # assuming 64 interfaces is enough for a single host!
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if_names = array.array('B', '\0' * if_totalNamesLen)
        try:
            buff = fcntl.ioctl(
                sock.fileno(), SIOCGIFCONF, struct.pack(
                    'iL', if_totalNamesLen, if_names.buffer_info()[0]
                )
            )
        except Exception as e:  # unsupported IOCTL
            sock.close()
            return []

        sock.close()
        if_names = if_names.tostring()
        ifacesArray = []
        for i in range(0, struct.unpack('iL', buff)[0], if_singleMaxLen):
            if_label = if_names[i:i+if_singleMaxLen].split('\0', 1)[0]
            if if_label.isalnum():
                ifacesArray.append(if_label)
        return ifacesArray

    def getProtoAddrFromIface(self, iface):
        """
        return IP address attached to a given network iface
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buff = fcntl.ioctl(
                sock.fileno(), SIOCGIFADDR, struct.pack('256s', iface)
            )
            ipAddr = socket.inet_ntoa(buff[20:24])
        except Exception as e:
            ipAddr = ""
        sock.close()
        return ipAddr

    def ondemandinfo(self):
        """
        Run this thread in the background and print this info if the user
        presses the enter key
        """
        while 1:
            try:
                if raw_input() == "":
                    if self.pkg_recv:
                        rtt_aver = self.rtt_sum / self.pkg_recv
                    else:
                        rtt_aver, self.rtt_min = 0, 0
                    if ip_dst_address == dst_address:
                        print "Target: %s" % dst_address
                    else:
                        print "Target: %s (%s)" % (dst_address, ip_dst_address)
                    print """Packets sent/lost/received: %d/%d/%d
                        \rCurrent rtt min/aver/max: %.2f/%.2f/%.2f
                        \rElapsed time hours/minutes/seconds: %s\n"""\
                        % (self.pkg_sent, (self.pkg_sent - self.pkg_recv),
                           self.pkg_recv, self.rtt_min, rtt_aver,
                           self.rtt_max, time.strftime(
                               "%H:%M:%S", time.gmtime(
                                   time.time() - self.start_time)))
            except Exception as e:
                break

    def data_gen(self):
        """Generates some 0 bytes of extra data if specified by the user"""
        for i in xrange(extra_data):
            self.extradata += "\0"
        return self.extradata

    def sendpkg(self):
        """The packet transmission loop"""
        while 1:
            # if the last packet comes next set the send delay to 0
            # in the next loop if the required packets haze been sent then stop
            if probe_time == self.pkg_sent + 1:
                self.send_delay = 0
            elif probe_time < self.pkg_sent + 1:
                self.reason = "Stop after %s packet(s) sent" % (probe_time)
                self.statistics()

            # generate the sequnce nr. then pack it to a 16 bit big-endian struct 
            self.intseq = self.pkg_sent + 1
            self.seq = struct.pack('!H', self.intseq)
            # calculate the checksum
            checksum = calcsum(
                self.types + "\0" + "\0\0" + self.ident + self.seq)

            # sends a ICMP packet to the target
            try:
                self.rawicmp.sendto(self.types + self.code + checksum +
                                    self.ident + self.seq + self.addr_mask +
                                    self.tmstamp_req + self.payload,
                                    (ip_dst_address, dst_port))
            except socket.error, error_msg:
                if error_msg[0] == 101:
                    sys.exit("\nAPing: Unable to establish a connection.Verify your network connectivity !")

            # print this on every loop if the user uses the --pkg-trace option
            if pkg_trace:
                print "\nsent: %s bytes ttl=%s icmp type=%s icmp seq=%s "\
                    % (self.length, time_to_live,
                       self.strint_type, self.intseq)

            self.pkg_sent += 1

            # start counting the rtt
            rtt_starttime = time.time()

            while 1:
                try:
                    # if it's true read from the buffer only to flush the buffer
                    if self.islocal:
                        self.rawicmp.recvfrom(2048)
                    self.data, self.src_addr = self.rawicmp.recvfrom(2048)
                except socket.timeout: # The timeout value was set in the __init__ method from default or user choice
                    self.retrans += 1
                    if self.retrans >= probes_retry:
                        self.reason = "Retransmission exceeded after %s probe(s)" % (probes_retry)
                        self.statistics()
                    break

                # check if the packet is from this session, if not then drop
                if self.data[24:26] == self.ident or self.data[52:54] == self.ident:
                    signal.alarm(0)
                    self.rtt_current = (time.time() - rtt_starttime) * 1000
                    self.retrans = 0  # always reset the retrans. if a packet is received
                    self.pkg_recv += 1
                    self.data_analize()  # parse the captured packet

                    # calculate minimum rtt , maximum rtt and the rtt sums
                    self.rtt_sum += self.rtt_current
                    self.rtt_min = min(self.rtt_current, self.rtt_min)
                    self.rtt_max = max(self.rtt_current, self.rtt_max)
                    break
            time.sleep(self.send_delay)

    def data_analize(self):
        """Here are parsed the received packets,and printed to the stdout"""
        self.data = binascii.hexlify(self.data)  # converting to hex data

        # get the TTL in hex format and convert to integer
        ttl = int(self.data[16:18], 16)

        # taking from a tuple (IP, port) only the IP number because ICMP uses no
        # port numbers
        self.src_addr = self.src_addr[0]

        icmp_type = int(self.data[40:42], 16)  # getting the icmp type

        # for every type of ICMP read the sequence number converting to integer
        # and set a string expression for the message output
        if icmp_type == 0:
            icmp_msg = "echo reply"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 3:
            icmp_msg = "dest. unreachable"
            icmp_seq = int(self.data[108:112], 16)
        elif icmp_type == 4:
            icmp_msg = "source quench"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 5:
            icmp_msg = "redirect"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 8:
            icmp_msg = "echo request"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 9:
            icmp_msg = "router advertisement"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 10:
            icmp_msg = "router sollicitation"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 11:
            icmp_msg = "time exceeded"
            icmp_seq = int(self.data[108:112], 16)
        elif icmp_type == 12:
            icmp_msg = "parameter problem"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 13:
            icmp_msg = "timestamp request"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 14:
            icmp_msg = "timestamp reply"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 15:
            icmp_msg = "information request"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 16:
            icmp_msg = "information reply"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 17:
            icmp_msg = "address mask request"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 18:
            icmp_msg = "address mask reply"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 30:
            icmp_msg = "traceroute"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 31:
            icmp_msg = "conversion error"
            icmp_seq = 0  # no icmp sequence field defined for this type
        elif icmp_type == 37:
            icmp_msg = "domain name request"
            icmp_seq = int(self.data[52:56], 16)
        elif icmp_type == 38:
            icmp_msg = "domain name reply"
            icmp_seq = int(self.data[52:56], 16)
        else:
            icmp_seq = 0
            icmp_msg = "unknown"


        length = len(self.data[40:]) / 2  # calculate the returned packet length

        # if the user do not use the --time option (usual probes)
        if return_time != 1 or probe_type != 't':
            if not old:
                print "recv: %d bytes addr=%s ttl=%d icmp type=%d(%s) icmp seq=%d rtt=%.2f ms" \
                    % (length, self.src_addr, ttl,
                       icmp_type, icmp_msg, icmp_seq,
                       self.rtt_current) + sonar
            else:
                print "%d bytes from %s: icmp_seq=%d time=%d ms"\
                 % (length, self.src_addr, icmp_seq,
                    self.rtt_current) + sonar

        # if the user uses the --time option
        else:
            #  check if the returned packet is a valid timestamp reply
            if icmp_type != 14:
                sys.exit("""\nAPing: Invalid timestamp reply received
                \rSo can not use the --time option to parse the time""")
            print "recv: timestamp reply addr=%s time -> %s - UTC" \
                % (dst_address,
                   time.strftime("%H:%M:%S", time.gmtime(
                       int(self.data[72:80], 16) / 1000))) + sonar

    def sighandler(self, signum, frame):
        """The keyboard interrupt handler"""
        self.reason = "Interrupt from keyboard (SIGINT)"
        self.statistics()

    def statistics(self):
        """The statistics are printed to the stdout every time when the program
        stops for some reason (retrans. expired, interrupt from keyboard ...)
        """

        # check if APing was stopped in the listening time
        if signal.alarm(0) > 0:
        	self.last_pkg = "\n - No reply for the last sent packet because interrupted in the listening time"
        else:
            self.last_pkg = ''       
        
        # calculate the total elapsed time
        time_elapsed = time.time() - self.start_time
        # calculate the lost packets
        pkg_lost = self.pkg_sent - self.pkg_recv

        #  calcualte the average time  
        if self.pkg_recv > 0:
            aver_time = self.rtt_sum / self.pkg_recv
        else:  # if no packets are received set some variables to zero
            aver_time, self.rtt_min, self.src_addr = 0, 0, ip_dst_address

        # check if the received packet are from the target address
        if ip_dst_address in self.src_addr or self.islocal:
            from_where = ''
        else:
            from_where="\n - The received packets are not from the target address (%s)!"\
            % dst_address

        # if no error message was received
        if self.last_pkg == '' and from_where == '':
            msg = "\n - All is OK"
        else:
            msg = ''

        #  add more precision to the final time
        msec = str(time_elapsed).split('.')

        # print the last line if --pkg-trace was specified
        if pkg_trace:
                print

        # print this out every time when the program stops 
        if not old:
            print """\nHalt reason: %s
            \rStatus:%s%s%s
            \r\n++++++++++++++  statistics  ++++++++++++++
            \rPackets:
            \r   Total sent:%s | lost:%s | received:%s
            \r       | lost:%.2f%% | received:%.2f%%
            \rTiming:
            \r   rtt min:%.2f | aver:%.2f | max:%.2f ms
            \r   Total time elapsed: %s.%ss"""\
            % (self.reason, from_where, self.last_pkg, msg,
               self.pkg_sent, pkg_lost, self.pkg_recv,
               ((100.0 * pkg_lost) / self.pkg_sent),
               ((100.0 * self.pkg_recv) / self.pkg_sent),
               self.rtt_min, aver_time, self.rtt_max,
               time.strftime("%Hh: %Mm: %S", time.gmtime(time_elapsed)),
               msec[1][:3])

        else:
            print """\n\n----%s PING Statistics----
            \r%d packets transmitted, %d packets received, %d%% packet loss
            \rround-trip (ms)  min/avg/max = %d/%d/%d""" \
            % (dst_address, self.pkg_sent, self.pkg_recv,
               ((100.0 * pkg_lost) / self.pkg_sent),
               self.rtt_min, aver_time, self.rtt_max)

        self.rawicmp.close(); self.rawicmp.close(); sys.exit(0)


class Resolver:
    """The DNS resolver class.

    This class makes the resolution of the hostname or the reverse DNS resolution
    if an IPv4 is entered and the -d option used.(The class uses the system DNS 
    resolver).
    """

    def __init__(self, str_probe_type, isip):
        global ip_dst_address

        # get the full information about the target host (address record, 
        # canonical names, ip addr.), if can't then target can not be resolved
        try:
            target_addr_info = socket.gethostbyname_ex(dst_address)
        except socket.gaierror:
            sys.exit("""APing: Target hostname can not be resolved (%s)
            \rAre you specified a valid hostname ? check the characters""" %dst_address)

        nr_of_ips = len(target_addr_info[2])  # count the number of ip(s)
        target_ips = str(target_addr_info[2]).strip("[]")  # get the ip(s)

        # get the canonical names
        addr_cnames = str(target_addr_info[1]).strip("[]")
        address_record = target_addr_info[0]  # get the address record

        # select the destination ip         
        if nr_of_ips == 1:
            ip_dst_address = (target_addr_info[2])[0]
        # pick an IP if there are more (randomly)
        else:
            ip_dst_address = (target_addr_info[2])[random.randrange(0, nr_of_ips)]

        # if verbosity is 1 or 2
        if verbose > 0:
            if not isip and nr_of_ips > 1:  # a hostname with multiple ip's
                print "%s resolves to multiple IP's (%s)"\
                    % (dst_address, nr_of_ips)
                if verbose == 2:  # if verbosity is 2n
                    print "The IP's are:", target_ips
            elif not isip and nr_of_ips == 1:  # a hostname with one ip
                print dst_address, "resolves to", ip_dst_address

            if not isip and verbose == 2:  # if verbosity is 2
                if addr_cnames == '':
                    addr_cnames = None
                print "Canonical names:", addr_cnames
                print "Address record:", address_record
            print "Trying with IP:", ip_dst_address

        # if reverse DNS resolution is true & the target is in IP format
        if isip and rev_dns:
            try:
                print "Reverse DNS resolution: %s" \
                    % socket.gethostbyaddr(dst_address)[0]
            except socket.herror:
                print "Warning ! Reverse DNS resolution failed"

        if not old:
            print "Sending", str_probe_type
        else:
            print "PING %s (%s): %d data bytes"\
                % (dst_address, ip_dst_address, extra_data)

        ICMPprobe().sendpkg()


def printopt(isipv4):
    """Checks the date to adjust the time zone and if it's specified by the
    user print to the stdout all the settings witch are used for the current
    session
    """
    if probe_type == 'p':
        str_probe_type = "ICMP Echo request"
    elif probe_type == 't':
        str_probe_type = "ICMP Timestamp request"
    elif probe_type == 'm':
        str_probe_type = "ICMP Address Mask request"
    elif probe_type == 'i':
        str_probe_type = "ICMP Information request"

    # get the current time zone
    if time.localtime()[8] == 1:
        timezone = time.tzname[1]
    else:
        timezone = time.tzname[0]

    print "\n* Starting APing at: %s %s *" % (time.asctime(), timezone)

    # print this information if the option --print-options are used
    if print_opt:
        print """\nICMP probe options:
            \r-------------------
            \r Target address: . . . .%s
            \r Probe type: . . . . . .%s
            \r Packets to send: . . . %s
            \r Listening timeout: . . %s (sec)
            \r Send delay: . . . . . .%s (sec)
            \r Extra data: . . . . . .%s (bytes)
            \r Time to live: . . . . .%s
            \r Probes retry: . . . . .%s (times)
            \r Verbosity level: . . . %s
            \r Reverse DNS: . . . . . %s
            \r Packet trace: . . . . .%s
            \r Print options: . . . . %s
            \r TOS field value: . . . %s (int)
            \r Print timestamp time: .%s
            \r Bond to address: . . . %s
            \r Old style output: . . .%s
            \r Produce sonar beeps . .%s\n"""\
                % (dst_address, str_probe_type, probe_time, listen_timeout,
                   send_delay, extra_data, time_to_live, probes_retry,
                   verbose, rev_dns, pkg_trace, print_opt, ip_tos,
                   return_time, bool(bind_addr), old, bool(sonar))

    Resolver(str_probe_type, isipv4)


def help():
    """Prints this help message to the stdout if the '-h/--help' option is used"""

    sys.exit("""\nUsage: aping.py {target specification} [OPTIONS]\n
Target:
    {target specification}
        Specify the target address. The target can be a hostname like
        www.probe.com, my.example.org or any IPv4 address like 192.168.0.1
Options:
    -P, --Probe <type> 
        Specify the ICMP probe type.<type> can be p, t, m or i where
        p is for usual ping probes, t is for timestamp request m for
        address mask request and i for information request (default
        is the ICMP echo request) 
    --time
        This option is used only with the timestamp requests. If a valid
        timestamp reply is received from the target and this option is
        enabled it prints out the time in the timestamp packets
    -d, --rdns 
        Make reverse DNS resolution if you specified a IPv4 address
    --print-options
        Print out all the options configured with this session before
        sending any packets
    -t, --ttl <num>
        Set up the time to live field. <num> is an integer and it is
        between 1 and 255 (inclusive). The default value is 64
    -b, --bind <IP number>
        Use this option to bind the created socket to an IP address. The
        argument <IP number> must to be a valid IPv4 address. This option
        if useful if you have multiple public IP's or when you probe your
        local address. In this case it's a good idea to bind the socket
        to another local IP
    --pkg-trace
        If this option is specified it prints out all the packets sent to
        the target not just the received ones
    --old
        Use old style output. If you use this option the output for captured
        packets and the statistics are exactly like in the original ping
        program from 1983 by Mike Muuss
    -s, --size <byte>
        Data in packets to send. <byte> is the number of extra bytes to
        send.Default behavior for APing is to send packets with no
        extra data
    -o, --listen <time>
        Set the listening timeout before APing retransmits the packet.
        <time> is the argument in seconds. By default APing uses 2 seconds
        to listen after a sent packet.
    -c, --count <count>
        Set the number of packets to send,then stop. <count> is the number of
        packets to send. Default behaviour is to send an infinitive number of
        packets unless you stop from the keyboard, or retransmission exceeded
    -w, --send-delay <time>[s/m]
        Adjust the send delay between probes. <time> is the delay time
        in milliseconds, the default send delay is 1 second.The 's' or
        'm' options are used to choose between seconds or milliseconds,
        but argument has to be an integer.
    -r, --retry <num>
        Set the probes retry if no packet is received. <num> is the packets
        to send, the default probes retry is 3 after that APing stops
    -T, --tos <num>
        Set the TOS (Type of Service) field in the IP header. The <num>
        argument can be an integer from 0 to 255 (inclusive) or specified
        as a hexadecimal number in format 0x (default value is 0)
    -v, --verbose <level>
        Verbose output for the DNS resolver. The <level> argument is a
        integer number that can be 1 or 2 (default is 0)
    --sonar
        Produces short beeps on every received packets. You must to have
        a speaker on your mother board to hear the beeps.
        other things
    -V, --Version
        Print out the version and exit
    -h, --help
        This help message""")


# the idiom to invoking the application. All gonna start from here
if __name__ == "__main__":
    # Option parser, check for valid options
    try:
        valid_options = getopt.gnu_getopt(sys.argv[1:], "Vt:r:w:c:o:v:s:P:hdT:b:",\
            ("Probe=", "rdns", "print-options", "ttl=", "pkg-trace", "size=",\
            "count=", "retry=", "verbose=", "send-delay=", "listen=", "tos=",\
            "time", "help", "Version", "bind=", "old", "sonar"))
    except getopt.GetoptError, bad_opt:
        sys.exit("\nAPing: %s \nTry -h or --help for a list of available options"\
                 % bad_opt)


    # create an empty list and store the options string expressions for the
    # duplicated options checking loop
    lista = []

    # run through arguments and rewrite the default variables
    for opt, arg in valid_options[0]:
        # *  payload data  *
        if opt == "-s" or opt == "--size":
            try:
                extra_data = int(arg)
                if extra_data < 0:
                    sys.exit("""\nAPing: Invalid extra data specified (%s)
                    \rArgument must to be greater or equal to 0""" % arg)
            except ValueError:
                sys.exit("""\nAPing: Invalid extra data specified (%s)
                \rArgument must be an integer not string or float value"""\
                         % extra_data)
            lista.append("size")

        # *  verbose  *
        elif opt == "-v" or opt == "--verbose":
            try:
                verbose = int(arg)
                if verbose < 0 or verbose > 2:
                    sys.exit("""\nAPing: Invalid verbosity level specified (%s)
                    \rValid values range from 0 to 2 (inclusive)""" % verbose)
            except ValueError:
                sys.exit("""\nAPing: Invalid verbosity level specified (%s)
                \rArgument must to be an integer not string or float value"""\
                         % arg)
            lista.append("verbose")

        # *  Prebe type  *
        elif opt == "-P" or opt == "--Probe":
            probe_type = arg
            # assingns a string expression for the selected probe type used for the
            # printopt() function, and in the Resolver() class
            if probe_type not in ('p', 't', 'm', 'i'):
                sys.exit("""\nAPing: Unknown probe type specified (%s)
                \rValid probe types are: p for echo request
                       t for timestamp request
                       m for address mask request
                       i for information request""" % probe_type)
            lista.append("Probe")

        # *  listen time  *
        elif opt == "-o" or opt == "--listen":
            # if user chooses milliseconds
            if arg.endswith('m'):
                listen_timeout = 1 / 1000.0
                arg = arg.replace('m', '')
            # if user chooses seconds
            elif arg.endswith('s'):
                listen_timeout = 1
                arg = arg.replace('s', '')
            # if nothing specified : assuming these are seconds
            else:
                listen_timeout = 1
            try:
                listen_timeout *= int(arg)
                if listen_timeout <= 0:
                    sys.exit("""\nAping: Invalid listen timeout specified (%s)
                    \rArgument must be greater than 0""" % arg)
            except ValueError:
                sys.exit("""\nAping: Invalid listen timeout specified (%s)
                \rArgument must be an integer value not string""" % arg)
            lista.append("listen")

        # *  packets to send  *
        elif opt == "-c" or opt == "--count":
            try:
                probe_time = int(arg)
                if probe_time <= 0:
                    sys.exit("""\nAPing: Invalid number of packets to send specified (%s)
                    \rArgument must to be integer value greater than 0"""\
                             % probe_time)
            except ValueError:
                probe_time = arg
                if probe_time != "inf":
                    sys.exit("""\nAPing: Invalid number of packets to send specified (%s)
                    \rArgument must be an integer value not string or float"""\
                             % arg)
            lista.append("packet")

        # *  send delay  *
        elif opt == "-w" or opt == "--send-delay":
            send_delay = arg
            try:
                send_delay = float(send_delay)
                if send_delay < 0:
                    sys.exit("""\nAPing: Invalid send delay specified (%s)
                    \rArgument must be greater or equal to 0""" % send_delay)
            except ValueError:
                sys.exit("""\nAPing: Invalid send delay specified (%s)
                \rArgument must be a float or integer value""" % arg)
            lista.append("send-delay")

        # *  time to live  *
        elif opt == "-t" or opt == "--ttl":
            try:
                time_to_live = int(arg)
                # valid time to live value is maximum a 8 bit unsigned number
                if time_to_live < 1 or time_to_live > 255:
                    sys.exit("""\nAPing: Invalid time to live specified (%d)
                    \rValid values range from 1 to 255 (inclusive)"""\
                             % time_to_live)
            except ValueError:
                sys.exit("""\nAPing: Invalid time to live specified (%s)
                \rArgument must be an integer value"""\
                         % arg)
            lista.append("ttl")

        # *  retry  *
        elif opt == "-r" or opt == "--retry":
            try:
                probes_retry = int(arg)
                if probes_retry <= 0:
                    sys.exit("""\nAPing: Invalid probes retry specified (%s)
                    \rArgument must be greater than 0"""\
                             % probes_retry)
            except ValueError:
                sys.exit("""\nAPing: Invalid probes retry specified (%s)
                \rArgument must be an integer value"""\
                         % parg)
            lista.append("retry")

        # *  ToS value  *
        elif opt == "-T" or opt == "--tos":
            try:
                ip_tos = int(arg)  # check the ToS format (decimal or hexadecimal)
            except ValueError:
                ip_tos = arg
                if ip_tos[:2] != '0x':  # the hex format must to start with '0x'
                    sys.exit("""APing: Invalid TOS value specified (%s)
                    \rArgument must be an integer or hex value""" % arg)
                # this is a valid ToS value in hexadecimal format
                try:
                    ip_tos = int(ip_tos[2:], 16)
                except ValueError:
                    sys.exit("""\nAping: Invalid TOS hexadecimal value specified (%s)
                    \rArgument must be between 0x00 and 0xff (inclusive)"""\
                             % arg)
            # the ToS field is 8 bit (unsigned), so the maximum int value is 255
            if ip_tos > 255 or ip_tos < 0:
                sys.exit("""APing: Invalid TOS value specified (%s)
                \rArgument must be between 0 and 255 (inclusive)""" % arg)
            lista.append("tos")

        # *  Old style  *
        elif opt == "--old":
            old = True
            lista.append("old")

        # *  Print all options  *
        elif opt == "--print-options":
            print_opt = True
            lista.append("print-options")

        # *  reverse DNS *
        elif opt == "-d" or opt == "--rdns":
            rev_dns = True
            lista.append("rdns")

        # *  bind to address  *
        elif opt == "-b" or opt == "--bind":
            bind_addr = arg
            lista.append("bind")

        # *  return times from timestamp  *
        elif opt == "--time":
            return_time = True
            lista.append("time")

        # *  trace packets  *
        elif opt == "--pkg-trace":
            pkg_trace = True
            lista.append("pkg-trace")

        # * sonar *
        elif opt == "--sonar":
            sonar = "\x07"
            lista.append("sonar")

        # *  help  *
        elif opt == "-h" or opt == "--help":
            help()

        # *  version  *
        elif opt == "-V" or opt == "--Version":
            sys.exit("\nAPing version: %s (http://www.nongnu.org/aping)"\
                     % VERSION)

    # Check for double or more options of the same type
    for i in xrange(len(valid_options[0]) - 1):
        if lista.count(lista[i]) > 1:
            sys.exit("\nAPing: Duplicated options detected from a type")

    # The first non-option should be the target address, if none specified exit
    try:
        # We build a list of destinations
        dst_address = valid_options[1][0]
        # Check if the user entered more then 1 non-option
        if len(valid_options[1]) > 1:
            sys.exit("\nAPing: more than one non-option specified")
    except IndexError:
        sys.exit("""\nAPing: At least specify a target address
            \rTry -h or --help for a list of available options""")

    # Set IOCTLS values for future local IP addresses research
    platform = sys.platform
    if 'freebsd' in platform:
        SIOCGIFADDR = 0xc0206921
        SIOCGIFCONF = 0xc0086924
    elif 'linux' in platform:
        SIOCGIFADDR = 0x8915
        SIOCGIFCONF = 0x8912
    else:
        print 'APing : unsupported OS! Behavior may be unexpected!'

    def checkaddr(addresses):
        isipv4 = 0
        try:
            int(addresses.replace('.', ''))

            # check if target is specified in IP or hostname format
            a, b, c, d = addresses.split('.')
            for i in a, b, c, d:
                i = int(i)
                if i > 255 or i < 0:
                    sys.exit("""\nAPing: Invalid IP address number range specified (%s)
                    \rValid number range is between 0 and 255 (inclusive)"""\
                             % addresses)
            # Alert on broadcast pings, will be removed when Broadcasting will be implemented
            if '255' in [a, b, c, d]:
                print """\nWarning : Broadcast not implemented yet in APing
                \rBehaviour might be uncertain"""
            # ------------------ #
            isipv4 = 1
        except ValueError, error_msg:
            if "need" in str(error_msg) or "many" in str(error_msg):
                sys.exit("""\nAPing: Invalid IP address length specified (%s)
                \rThe address must to be a valid IPv4 address"""\
                         % addresses)
        return isipv4

    printopt(map(checkaddr, [bind_addr, dst_address])[1])
