# -*- coding: utf-8 -*-

#*******************************************************************************
# default.py --> contains APing predefined variables for the default options   *
#                                                                              *    
#*******************************************************************************
# Copyright (C) 2007, 2008 Kantor A. Zsolt <kantorzsolt@yahoo.com>             *   
#*******************************************************************************
# This file is part of APing.                                                  *    
#                                                                              *   
# APing is free software; you can redistribute it and/or modify                *
# it under the terms of the GNU General Public License as published by         *
# the Free Software Foundation; either version 3 of the License, or            *
# (at your option) any later version.                                          *
#                                                                              *
# Aping is distributed in the hope that it will be useful,                     *
# but WITHOUT ANY WARRANTY; without even the implied warranty of               *
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
# GNU General Public License for more details.                                 *
#                                                                              *
# You should have received a copy of the GNU General Public License            *
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        *  
#*******************************************************************************


# APing Version
VERSION = "0.1 beta 3"

# Here are defined the default options if no one is specified by the user

# default payload data to send with the ICMP packets (0 = don't send extra data)
extra_data = 56
# default verbosity level (0 = don't be verbose)
verbose = 0
# destination port 0 because ping probes doesn't need a port number but the 
# sendto() function need a destination port number
dst_port = 0
# default listening timeout in seconds
listen_timeout = 2
# default probe type (p = ICMP echo request)
probe_type = 'p'
# default packet sending (Infinitive = send packets for infinitive)
probe_time = "inf"
# default reverse DNS resolution (False = don't make reverse DNS resolution)
rev_dns = False
# default wait time between probes in seconds
send_delay = 1
# print all the probing options for this session  (False = don't display)
print_opt = False
# default time to live
time_to_live = 64
# default probe retry (packets to send),if no answer is gained
probes_retry = 3
# default packet trace (0 = don't trace the packets)
pkg_trace = False
# default TOS value
ip_tos = 0
# default value for the --time option
return_time = False
# default address to bind to. An empty string value represents your public IP 
bind_addr = ''
# default for the old output style 
old = False
# default for the sonar (the empty string means it's false) 
sonar = ''

# IO CONTROLS CONSTANTS
# used to find out local IP addresses
# Set to zero to raise an exception on unsupported OS
SIOCGIFADDR = 0x00
SIOCGIFCONF = 0x00




