# Python 3 example: simple tcp server, which replays previosly dumped connection (one side of the connection)
import sys
import json
import datetime
import socket
import threading
import select

TCP_IP    = ''    # '' = ANY
TCP_PORT  = 81

g_packets = []

def read_packets(json_dump_file_path):
  with open(json_dump_file_path, "rt") as f:
   while 1:
     line = f.readline()
     if not line: break
     data = json.loads(line)
     data['data'] = bytes.fromhex(data['data_hex'])
     del data['data_hex']
     data['side'] = int(data['side'])
     data['size'] = int(data['size'])
     data['time']['abs'] = datetime.datetime.fromtimestamp(float(data['time']['abs']))
     data['time']['conn'] = float(data['time']['conn'])
     yield data

def handle_connection(s, addr):
  global g_packets
  BUFFER_SIZE = 1024 * 32
  print("Handling connection from %s:%s" % (addr[0], addr[1]))
  bin_log_file = "server-client-data-log-%s-%s.bin" % (addr[0], addr[1])
  try:
    with open(bin_log_file, "wb") as wf:
      # Receiving messages in loop
      for packet in g_packets:
        if packet is None:
          # Receiving data
          data = s.recv(BUFFER_SIZE)
          if(len(data) <= 0): break
          print("received data from %s:%s (%u):\t" % (addr[0], addr[1], len(data)), data)
          wf.write(data)
        else:
          # Sending data
          s.send(packet['data'])
  except:
    print("Exception")
  print("Closing connection from %s:%s" % (addr[0], addr[1]))
  s.close()

def start_server(port, addr = None):
  if addr is None:
    addr = '' # ANY
  
  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.bind( (addr, port) )
  server_sock.listen( 10 )

  while True:
    ready, _, _ = select.select([server_sock], [], [], 1) # Timeout set to 1 seconds
    if ready:
      s, addr = server_sock.accept()
      threading.Thread(target = handle_connection, args = (s, addr)).start()

  server_sock.close()

# ------------------------------------------------------------------------------

input_file = sys.argv[1]
print("Reading JSON packets from %s... " % input_file, end="", flush=True)
use_side = 1 if (len(sys.argv) < 3) else int(sys.argv[2])
g_packets = []
total_packets = 0
for packet in read_packets(sys.argv[1]):
  total_packets += 1
  if(use_side is None): 
    use_side = packet['side']
  if(use_side == packet['side']): 
    g_packets.append(packet)
  elif((len(g_packets) == 0) or (g_packets[-1] is not None)):
    g_packets.append(None)
print("Done (%u / %u)" % (len(g_packets), total_packets))
print("Plan: %s" % ",".join([('RECV' if (x is None) else 'SEND') for x in g_packets]))

start_server(TCP_PORT, TCP_IP)
