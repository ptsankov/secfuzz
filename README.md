I. WHAT DOES IT DO
------------------
The purpose of the IKE fuzz tester is to evaluate IKE implementations
for vulnerabilities. The fuzz tester sends messages to the
implementation under test (IUT), which in turn is tested for low-level
vulnerabilities (e.g. memory errors) using a dynamic analysis tool.
The sequence of messages sent to the IUT is randomly mutated using one
of the fuzz operators described below.


II. FUZZ OPERATORS
------------------
The fuzz operators randomly mutate a sequence of messages, which is
the input to the IUT. A protocol execution consists of a sequence of
messages, a message consists of a list of payloads, and a payload
consits of a set of fields.

1. Fuzzing a message
   - send a random message: this operator inserts a well-formed message
     in a valid sequence of messages.
2. Fuzzing a payload
   - remove a payload: a payload from the message is removed
   - insert a payload: a random well-formed payload is inserted at a random
     position in the list of payloads
   - repeat a payload: a random payload is duplicated in the list of payloads
3. Fuzzing a field
   Fuzzing numerical fields:
   - set to 0
   - set to a random number
   Fuzzing byte fields
   - append a sequence of random bytes
   - set to empty
   - modify a random byte
   - insert a string termination at a random position
   

III. HOW DOES IT WORK
---------------------
The figure below illustrates the experimental setup for using the fuzz
tester. Openswan is a mature IPsec implementation, which is used to
generate valid IKE message sequences. 

```
    +--------+                         +--------+
    |Opponent|<------------------------|  SUT   |
    +--------+\                      ->+--------+
         |     \                    /
write to |      \                  /
         \/      --->+---------+---
   log file -------->| SecFuzz |
             read    +---------+
```

The behavior of the IUT can be monitored using a dynamic analysis
tool, e.g. memory error detector such as Valgrind's Memcheck.


IV. HOW TO USE THE FUZZ TESTER
------------------------------
The fuzz tester is a python script and can be started as follows:
$python ike_fuzzer.py [options]
 -i <ip>                 specify the IP address of the local machine
 -o <opposite ip>        specify the IP address of the IUT
 -f                      run the fuzz tester in fuzzing mode, if this
                         flag is not set, the fuzzer simply forwards
                         all Openswan messages
 -l <log file>           specify a file to log information, if not
                         file is specified, all output is send to
                         standard output
 -e <iface>              specify the name of the ethernet interface
                         used for sending messages to the IUT 
                         (e.g. eth0)
 -p <pluto log file>     set the path to Openswan's log file 

All options except -f and -l are mandatory. The fuzz tester needs 
root privileges.

When the fuzz tester is started, all messages sent by Openswan are
intercepted and forwarded to the port on which the IUT listens for IKE
messages. Openswan must be configured to output all debug information
so that the fuzz tester can find the necessary encryption information
from the log file. This can be done by setting plutodebug=all in
ipsec.conf. The ipsec_confs directory contains a number of ipsec.conf
configurations.


V. SOFTWARE DEPENDENCIES
------------------------
To use the fuzz tester you need the following software:
- Python 2.6+
- Scapy (http://www.secdev.org/projects/scapy/) - Scapy is a powerful
  interactive packet manipulation library for python.
- Openswan 2.6.37 (http://openswan.org/) - Openswan is an IPsec
  implementation for Linux. You need to configure how Openswan and the 
  IUT authenticate to each other.
- tcpdump (http://www.tcpdump.org/)


VI. IMPORTANT FILES
-------------------
- fuzzer.py - this is the fuzz tester that listens for Openswan
  messages and applies the fuzz operators
- README - this file
- ipsec_confs/ - this directory contains different Openswan
  configuration files. Openswan can be started with different
  configuration files in order to generate different message
  sequences.


VII. KNOWN PROBLEMS
-------------------
- The Scapy python library refuses to send some fuzzed messages and 
  crashes the fuzz tester.


VIII. VERSION HISTORY
---------------------
- v0.1 (November 14th, 2011)
  First public release


IX. CONTACT INFORMATION
-----------------------
For further information on how to use the IKE fuzz tester:

Petar Tsankov
Email: ptsankov@student.ethz.ch

