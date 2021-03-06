
# TODO List

### Output:

* [ ] Better output for ICMP unreachable messages (and similars)! They're *NOT* ping replies!!
* [ ] Increase effect of verbosity levels
* [ ] XML output (*To be Discussed*)

---

### Features:   
* [ ] small DNS client to let the user choose his own DNS servers (*WIP*)
* [ ] TCP/UDP ping for non-root users
* [ ] Multiple targets specification
    * [ ] Better broadcast pings support (option)
    * [ ] Network masks (192.168.1.0/24, www.google.com/24)
    * [ ] Ranges of IP addresses (192.168.1-3.15-32)
    * [ ] ICMP type 10 (router sollicitation) (*To be discussed*)
    * [ ] IPV6 support (*To be discussed*)

---

### Code maturity:
* [ ] Reach a first stable state (*WIP*)
    * [X] Command line bug fixes
    * [ ] behaviour testing
    * [ ] special cases testing (bugged targets, stressed network...)
    * [ ] Faster (eg. signal handler) this will require non-blocking sockets and select() but were really better!!! (*Important*)

---

### KNOWN BUGS : 

* [ ] On freeBSD, signals are processed in a different way, and two ctrl+C are required to close aping.
        Description is available here: http://bugs.python.org/issue1975
* [ ] On freeBSD, there is still a pb pinging localhost, unreplied packets stay in the buffer...
* [ ] If listening timeout (-o option) is too short, Aping misses the first reply (OK) but keeps it
        and read it as a reply for next probe, this is a wrong behavior, buffer must be flushed and emptied
        between each probe!!
