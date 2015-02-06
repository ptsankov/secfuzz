#! /usr/bin/env python

import fcntl
import os
import threading
import thread
import signal
import sys
import getopt
import datetime
import time
import random
from Crypto.Cipher import *
from Crypto.Hash import *
from scapy.all import *

#------------------------------------------------------------
# This class enumerates the different payload types
#------------------------------------------------------------
class PD_TYPE:
   SA = 1
   Transform = 3
   KE = 4
   ID = 5
   CERT = 6
   CR = 7
   Hash = 8
   SIG = 9
   Proposal = 10
   PD = 11
   VendorID = 13
   Header = -1

#------------------------------------------------------------
# This class holds information about the current IKE
# session
#------------------------------------------------------------
class Fuzz_session:
  fuzz = None
  enc_algo = None
  hash_algo = None
  enc_key = None
  iv = None
  init_cookie = None
  resp_cookie = None
  pkts_received = 0
  pkt_to_fuzz = 0


#------------------------------------------------------------
# Global variables
#------------------------------------------------------------
# prob_listi     - assigns a probability of applying the different
#                  fuzz categories
# fuzz_session   - keeps information about the current IKE session
# ip             - the IP of the local machine
# opp_ip         - the IP of the remote machine (under test)
# log_file       - stores fuzzing information
# iface          - the interface of the local machine (e.g. eth0)
# fuzz_mode      - boolean, specifies whether packets are fuzzed or not
# pluto_log_file - path to the pluto log file
# pluto_log_fd   - the file descriptor of the pluto log file
# running        - is the fuzzer running?
# ike_port       - the ike port (to which the packets are sent by default
# dest_port      - the ike port on which the remote machine is listening
# lock1, lock2   - semaphores used to synchronize the thread snooping 
#                  for packets (tcpdump) and the main fuzzer thread 
#                  sending the packets
#------------------------------------------------------------
prob_list = [('payload', 0.1), ('field', 0.8), ('packet', 0.1)]
fuzz_session = Fuzz_session()
ip = None
opp_ip = None
log_file = None
log_dir = None
iface = None
fuzz_mode = False
pluto_log_file= "/home/adminuser/fuzzing/pluto.log"
pluto_log_fd = None
running = True
ike_port = 500
dest_port = 501
lock1 = threading.Semaphore(0)
lock2 = threading.Semaphore(1)


#------------------------------------------------------------
# This function logs all output to a file, if no file is
# specified, it prints to standard output
#------------------------------------------------------------
def log(msg):
   log_msg = '[' + str(datetime.datetime.now()) + '] ' + msg
   if log_file is not None and msg is not None:
      log_file.write(log_msg + '\n')
      log_file.flush()
   else:
      print log_msg


#------------------------------------------------------------
# This function cleans temporary files and stop the fuzzer 
# upon Ctrl+c event
#------------------------------------------------------------
def signal_handler(signal, frame):
   running = False
   log('Cleaning up temporary pcap files')
   os.system('sudo rm -rf ' + log_dir + 'pkt*')
   log('Stopping')
   sys.exit(0)


#------------------------------------------------------------
# This function should be run in a separate thread. It
# runs tcpdump to capture packets into pcap format. It
# synchronizes with the fuzzer so that a packet is sent
# only after tcpdump is listening for the next packet.
#------------------------------------------------------------
def start_tcpdump():
   log('Tcpdump running')
   pkt_count = 1
   while running:
      # wait until the fuzzer sends the packet that was just captured
      lock2.acquire()
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      os.system('tcpdump -i ' + iface + ' dst ' + opp_ip + ' and dst port ' + str(ike_port) + ' -c 1 -w ' + pcap_file + ' &')
      if pkt_count > 1:
         # busy wait until tcpdump is up and running
         while int(os.popen('sudo ps x | grep "tcpdump -i ' + iface + '" | wc -l').read().rstrip()) < 1:
            pass
         # tcpdump is listening, safe to send the packet
         lock1.release()
      pkt_count += 1


#------------------------------------------------------------
# This function returns a random well-formed packet (that
# was captured from previous sessions of the protocol)
#------------------------------------------------------------
def get_random_pkt():
   num_pcap_pkts = int(os.popen('ls *.pcap | wc -l').read().rstrip())
   if num_pcap_pkts < 1:
      return None
   pcap_file = log_dir + 'pkt_'+str(random.randint(1,num_pcap_pkts-1))+'.pcap'
   rand_pkt = read_pcap(pcap_file)
   return rand_pkt
   

#------------------------------------------------------------
# This function reads a pcap file and returns a packet
# object.
#------------------------------------------------------------
def read_pcap(pcap_file):
   while not( os.path.isfile(pcap_file) and os.path.getsize(pcap_file) > 0 ):
      pass
   pkts=rdpcap(pcap_file)
   if len(pkts) > 0:
      return pkts[0]
   else:
      return None


#------------------------------------------------------------
# This function rewrites the packet port to the dest port and deletes
# the IP and UDP checksums, if the checksums do not match,
# the OS might (and should) ignore the packets.
#------------------------------------------------------------
def rewrite_port(pkt):
   pkt[UDP].dport = dest_port
   del pkt[IP].chksum
   del pkt[UDP].chksum


#------------------------------------------------------------
# Chooses an item from a list defined as:
# [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
# where prob_i is the probability of choosing item_i
#------------------------------------------------------------
def weighted_choice(items):
   weight_total = sum((item[1] for item in items))
   n = random.uniform(0, weight_total)
   for item, weight in items:
      if n < weight:
         return item
      n = n - weight
   return item


#------------------------------------------------------------
# When a new IKE session is detected, the fuzzer also starts
# a new session, i.e. it will fuzz a message/payload during
# that session
#------------------------------------------------------------
def init_new_session(pkt):
   global fuzz_session
   log('Starting a new session')
   fuzz_session = Fuzz_session()
   fuzz_session.fuzz = weighted_choice(prob_list) 
   # choose a random packet to fuzz
   fuzz_session.pkt_to_fuzz = random.randint(1,5)
   if fuzz_session.fuzz == 'payload':
      log('Prepare to fuzz a payload in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'field':
      log('Prepare to fuzz a field in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'packet':
      log('Prepare to insert random packet after packet ' + str(fuzz_session.pkt_to_fuzz))

   fuzz_session.init_cookie = pkt[ISAKMP].init_cookie


#------------------------------------------------------------
# This function encrypts the packet
#------------------------------------------------------------
def encrypt(pkt):
   log('Encrypting a packet')
   key = get_key()
   try:
      pkt[ISAKMP].payload = Raw(key.encrypt( str(pkt[ISAKMP].payload) + '\x00'* ( (16 - len(pkt[ISAKMP].payload)%16 )%16 ) ) )
   except ValueError:
      if fuzz_session.fuzz == 'payload':
         log('Encryption failed, probably fuzzing a payload and length is unknown..')
         encrypt(pkt)
   log('Encrypted packet:\n' + pkt.command())



#------------------------------------------------------------
# This function reads the pluto log file and returns the
# current encryption key
#------------------------------------------------------------
def get_key():
   pluto_log_reader()
   log('Creating ' + str(fuzz_session.enc_algo) + ' key with enc key ' + fuzz_session.enc_key + ' and IV ' + fuzz_session.iv)
   if fuzz_session.enc_algo == AES:
     return AES.new(fuzz_session.enc_key[:32].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:32].decode('hex'))
   elif fuzz_session.enc_algo == DES3:
     return DES3.new(fuzz_session.enc_key[:48].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:16].decode('hex'))
   else:
     log('Not supported encryption algorithm')
     sys.exit(0)


#------------------------------------------------------------
# This function decrypts the packet
#------------------------------------------------------------

   SA = 1
   Transform = 3
   KE = 4
   ID = 5
   CERT = 6
   CR = 7
   Hash = 8
   SIG = 9
   Proposal = 10
   PD = 11
   VendorID = 13

def decrypt(pkt):
   log('Decrypting a packet')
   key = get_key()
   if pkt[ISAKMP].next_payload == PD_TYPE.ID:
      pkt[ISAKMP].payload = ISAKMP_payload_ID(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.KE:
      pkt[ISAKMP].payload = ISAKMP_payload_KE(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Proposal:
      pkt[ISAKMP].payload = ISAKMP_payload_Proposal(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.SA:
      pkt[ISAKMP].payload = ISAKMP_payload_SA(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Transform:
      pkt[ISAKMP].payload = ISAKMP_payload_Transform(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.VendorID:
      pkt[ISAKMP].payload = ISAKMP_payload_VendorID(key.decrypt(pkt[ISAKMP].payload.load))
   else:
      pkt[ISAKMP].payload = ISAKMP_payload_Hash(key.decrypt(pkt[ISAKMP].payload.load))
   log('Decrypted packet:\n' + pkt.command() )
   # we assume the res field is not used and is set to 0, this allows us to check if the decryption was successful
   if pkt[ISAKMP].payload.res != 0:
      log('Decryption failed, probably the key was incorrect, this can happen if pluto has not written the latest key in its log file')
      pkt[ISAKMP].payload = ISAKMP_payload(next_payload=0)
      pkt[ISAKMP].next_payload = 6


#------------------------------------------------------------
# This function monitors the pluto.log file and captures
# when the encryption key is updated, it also keeps track
# of the current encryption scheme used, IV for CBC, etc.
#------------------------------------------------------------
def pluto_log_reader():
  global fuzz_session
  # wait to make sure that pluto saved to pluto.log
  time.sleep(0.1)

  line = pluto_log_fd.readline().rstrip()
  while line != '':
     if '! enc key:' in line:
        fuzz_session.enc_key = line[12:].replace(' ', '')
        line = pluto_log_fd.readline().rstrip()
        if '! enc key:' in line:
           fuzz_session.enc_key += line[12:].replace(' ', '')
        else:
           continue
     elif '! IV:  ' in line:
        fuzz_session.iv = line[7:].replace(' ','')
        line = pluto_log_fd.readline().rstrip()
        if '! IV:  ' in line:
           fuzz_session.iv += line[7:].replace(' ', '')
        else:
           continue
     elif '| IV:' in line:
        line = pluto_log_fd.readline().rstrip()
        fuzz_session.iv = line[4:].replace(' ','')
     elif 'OAKLEY_AES_CBC' in line:
        fuzz_session.enc_algo = AES
     elif 'OAKLEY_3DES_CBC' in line:
        fuzz_session.enc_algo = DES3
     elif 'OAKLEY_SHA1' in line:
        fuzz_session.hash_algo = SHA
     elif 'OAKLEY_MD5' in line:
        fuzz_session.hash_algo = MD5
     line = pluto_log_fd.readline().rstrip()


#------------------------------------------------------------
# This function repeats a payload in the packet
#------------------------------------------------------------
def payload_repeat(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   repeat_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,repeat_pd):
      cur_payload = cur_payload.payload
   cur_payload.payload = eval(cur_payload.command())
   cur_payload.next_payload = cur_payload.underlayer.next_payload


#------------------------------------------------------------
# This function removes a payload from the packet
#------------------------------------------------------------
def payload_remove(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   remove_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload
   cur_payload.underlayer.next_payload = cur_payload.next_payload
   if cur_payload.payload.command() == '':
     del cur_payload.underlayer.payload
   else:
     cur_payload.underlayer.payload = eval(cur_payload.payload.command())

#------------------------------------------------------------
# This function inserts a random payload in the packet
#------------------------------------------------------------
def payload_insert(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   remove_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload
   print cur_payload.command()
   r = random.choice( [ (fuzz(ISAKMP_payload()), 6), (fuzz(ISAKMP_payload_Hash()), 8), (fuzz(ISAKMP_payload_ID()), 5), 
                             (fuzz(ISAKMP_payload_KE()), 4), (fuzz(ISAKMP_payload_Nonce()), 8), (fuzz(ISAKMP_payload_Proposal()), 10), 
                             (fuzz(ISAKMP_payload_SA()), 1), (fuzz(ISAKMP_payload_Transform()), 3), (fuzz(ISAKMP_payload_VendorID()), 13) ] )
   r[0].payload = eval(cur_payload.command() )
   r[0].next_payload = cur_payload.underlayer.next_payload
   cur_payload.underlayer.next_payload = r[1]
   cur_payload.underlayer.payload = r[0]


#------------------------------------------------------------
# A map from payload fuzz type to payload fuzz function
#------------------------------------------------------------
fuzz_payload_func = {}
fuzz_payload_func['repeat'] = payload_repeat
fuzz_payload_func['remove'] = payload_remove
fuzz_payload_func['insert'] = payload_insert



#------------------------------------------------------------
# This function fuzzes a payload
#------------------------------------------------------------
def fuzz_payload(pkt):
   fuzz_type = random.choice( ['repeat', 'remove', 'insert'] )
   log('Fuzzing a payload ' + fuzz_type)

   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   fuzz_payload_func[fuzz_type](pkt)
   log('Fuzzed packet:\n'+pkt.command())
   pkt = eval(pkt.command())

   if encrypt_pkt:
      encrypt(pkt)


#------------------------------------------------------------
# This function fuzzes a field
#------------------------------------------------------------
def fuzz_field(pkt):
   log('Fuzzig a field')
   # Check if the packet is encrypted
   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   # Check what payloads are contained in the packet and
   # randomly choose one to fuzz a field in it
   cur_payload = pkt[ISAKMP]
   payloads = []
   payload_type = []
   payload_type.append(PD_TYPE.Header)
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      if cur_payload.next_payload != 0:
         payload_type.append(cur_payload.next_payload)
      cur_payload = cur_payload.payload
   if len(payloads) == 0:
      payloads.append(pkt[ISAKMP])
   pd_to_fuzz = random.randint(0,len(payloads)-1)
   fuzz_func[ payload_type[pd_to_fuzz] ](payloads[pd_to_fuzz]) 
   log('Fuzzed packet:\n'+pkt.command())

   if encrypt_pkt:
      encrypt(pkt)


#------------------------------------------------------------
# This function fuzzes a packet (sends a random packet)
#------------------------------------------------------------
def fuzz_packet(pkt):
   log('Fuzzing packet')
   rand_pkt = get_random_pkt()
   if rand_pkt != None:
      log('Sending random packet: ' + rand_pkt.command())
      rewrite_port(rand_pkt)
      send(rand_pkt[IP])


#------------------------------------------------------------
# Fuzz a packet
#------------------------------------------------------------
def fuzz_pkt(pkt):
   if fuzz_session.fuzz == 'payload':
      fuzz_payload(pkt)
   elif fuzz_session.fuzz == 'field':
      fuzz_field(pkt)
   elif fuzz_session.fuzz == 'packet':
      fuzz_packet(pkt)
   

#------------------------------------------------------------
# This function processes each new packet and decides whether
# we should fuzz it or not
#------------------------------------------------------------
def process_pkt(pkt):
   global fuzz_session
   fuzz_session.pkts_received += 1
   if fuzz_session.pkt_to_fuzz == fuzz_session.pkts_received:
      pkt = fuzz_pkt(pkt)


#------------------------------------------------------------
# The main fuzzer function
#------------------------------------------------------------
def start_fuzzer():
   global running, pluto_log_fd
   log('Initializing pluto log reader')
   pluto_log_fd = open(pluto_log_file, 'r')

   os.system('sudo rm -rf pkt*')
   thread.start_new_thread(start_tcpdump, () )
   log('Fuzzer started')
   pkt_count = 1
   while running:
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      pkt = read_pcap(pcap_file)
      if pkt is None:
         continue
      pkt_count = pkt_count + 1
      log('Received packet:\n' + pkt.command() + '\n')
      # Detect if the packets belongs to a new IKE session
      if fuzz_mode and pkt[ISAKMP].resp_cookie == '\x00\x00\x00\x00\x00\x00\x00\x00' and pkt[ISAKMP].init_cookie != fuzz_session.init_cookie:
         init_new_session(pkt)
      if fuzz_mode:
         process_pkt(pkt)
      rewrite_port(pkt)
      lock2.release()
      lock1.acquire()
      log('Sending packet\n' + pkt.command())
      send(pkt[IP])


#------------------------------------------------------------
# The main function, reads the fuzzer arguments and starts
# the fuzzer
#------------------------------------------------------------
def main():
   global ip, opp_ip, log_file, fuzz_mode, log_dir, iface, pluto_log_file, prob_list

   opts, args = getopt.getopt(sys.argv[1:], 'i:o:l:fe:p:t:')
   for o, a in opts:
      print o, a
      if o == '-i':
         ip = a
      if o == '-o':
         opp_ip = a
      if o == '-l':
         log_file = open(a, 'w')
      if o == '-f':
         fuzz_mode = True
      if o == '-e':
         iface = a
      if o == '-p':
         pluto_log_file = a
      if o == '-t':
         prob_list = [(a,1)]
         if a not in ['field', 'payload', 'packet']:
            prob_list = None

   if fuzz_mode:
      log('Running in fuzzing mode')
   else:
      log('Running in disabled fuzzing mode')

   log('Pluto file: ' + pluto_log_file)

   if log_dir is None:
      log_dir = os.getcwd()+'/'
   else:
      log_dir=os.path.abspath(fp)[:os.path.abspath(fp).rfind('/')]+'/'
          
   log('Log dir: ' + log_dir)

   if prob_list is None:
      log('Invalid fuzz type')
      sys.exit(0)
   
   if( ip is None or opp_ip is None or iface is None):
      print_usage()
      sys.exit(0)

   for item, weight in prob_list:
      log('Fuzzing ' + item + ' probability ' + str(weight))

   bind_layers(UDP, ISAKMP, sport=500)
   bind_layers(UDP, ISAKMP, dport=500)

   start_fuzzer()

def print_usage():
   print sys.argv[0], '-i <ip> -o <opposite ip> -f -l <log file> -e <eth interface> -p <pluto log file>'



#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,100))


def rand_IntEnumField():
   return random.randint(0,100)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)


def rand_IntField():
   return random.randint(0,5000)

#------------------------------------------------------------
# The functions below fuzz payloads
#------------------------------------------------------------

def fuzz_SA(payload):
   log('fuzz SA')
   pd = random.choice([ISAKMP_payload_SA, ISAKMP_payload_Proposal, ISAKMP_payload_Transform])
   length = len(payload)
   if pd == ISAKMP_payload_SA:
      field = random.choice(['next_payload', 'length', 'DOI', 'situation'])
      log('Fuzzing field: ' + field)
      if field == 'next_payload':
         payload.next_payload = rand_ByteEnumField()
      elif field == 'length':
         payload.length = rand_FieldLenField()
      elif field == 'DOI':
         payload.DOI = rand_IntEnumField()
      elif field == 'situation':
         payload.situation = rand_IntEnumField()
      else:
         log('Error')
      if field != 'length':
         payload.length += ( len(payload) - length )
   elif pd == ISAKMP_payload_Proposal:
      fuzz_Proposal(payload)
   elif pd == ISAKMP_payload_Transform:
      fuzz_Transform(payload)
   else:
      log('Error')
      sys.exit(0)

def fuzz_KE(payload):
   log('fuzz KE')
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_ID(payload):
   log('fuzz ID')
   field = weighted_choice([('next_payload', 0.1), ('length', 0.1), ('IDtype',0.1), ('ProtoID', 0.1), ('Port', 0.1), ('load',0.5)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'IDtype':
      payload.IDtype = rand_ByteEnumField()
   elif field == 'ProtoID':
      payload.ProtoID = rand_ByteEnumField()
   elif field == 'Port':
      payload.Port = rand_ShortEnumField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Hash(payload):
   log('fuzz Hash')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_VendorID(payload):
   log('fuzz VendorID')
   field = random.choice(['next_payload', 'length', 'vendorID'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'vendorID':
      payload.vendorID = rand_StrLenField(payload.vendorID)
   else:
      log('Error')
      sys.exit(0)

def fuzz_Header(payload):
   log('fuzz Header')
   field = random.choice(['init_cookie', 'resp_cookie', 'next_payload', 'exch_type', 'flags', 'id', 'length'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'init_cookie':
      payload.init_cookie = os.urandom(8)
   elif field == 'resp_cookie':
      payload.resp_cookie = os.urandom(8)
   elif field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'exch_type':
      payload.exch_type = rand_ByteEnumField()
   elif field == 'flags':
      if payload.flags == 0L:
         payload.flags = 1L
      else:
         payload.flags = 0L
   elif field == 'id':
     payload.id = rand_IntField()
   elif field == 'length':
     payload.length = rand_FieldLenField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_CERT(payload):
   log('fuzz CERT')
   fuzz_Payload(payload)


def fuzz_CR(payload):
   log('fuzz CR')
   fuzz_Payload(payload)


def fuzz_SIG(payload):
   log('fuzz SIG')
   fuzz_Payload(payload)


def fuzz_Proposal(payload):
   log(payload.command())
   log('fuzz Proposal')
   field = random.choice(['next_payload', 'length', 'proposal', 'proto', 'SPIsize', 'trans_nb'])#, 'SPI'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'proposal':
      payload.proposal = rand_ByteField()
   elif field == 'proto':
      payload.proto = rand_ByteEnumField()
   elif field == 'SPIsize':
      payload.SPIsize = rand_FieldLenField()
   elif field == 'trans_nb':
      payload.field = rand_ByteField()
   elif field == 'SPI':
      payload.SPI = rand_StrLenField(payload.SPI)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Payload(payload):
   log('fuzz Payload')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Transform(payload):
   log('fuzz Transform')
   num_transforms = 0
   cur_payload = payload
   length = len(payload)
   while cur_payload.next_payload != 0:
      num_transforms
      cur_payload = cur_payload.payload
   fuzz_transform = cur_payload
   for i in range(0,num_transforms-1):
      fuzz_transform = fuzz_transform.payload
   field = random.choice(['next_payload', 'length', 'num', 'id'])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'num':
      payload.num = rand_ByteField()
   elif field == 'id':
      payload.id = rand_ByteEnumField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )



#------------------------------------------------------------
# Map <payload id> <--> <function that fuzzes payload>
#------------------------------------------------------------
fuzz_func = {}
fuzz_func[1] = fuzz_SA
fuzz_func[4] = fuzz_KE
fuzz_func[5] = fuzz_ID
fuzz_func[6] = fuzz_CERT
fuzz_func[7] = fuzz_CR
fuzz_func[8] = fuzz_Hash
fuzz_func[9] = fuzz_SIG
fuzz_func[10] = fuzz_Proposal
fuzz_func[11] = fuzz_Payload
fuzz_func[13] = fuzz_VendorID
fuzz_func[-1] = fuzz_Header


if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)
   main()
