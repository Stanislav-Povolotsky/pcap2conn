# Python 3 example: json packets reader
import sys
import json
import datetime

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

for packet in read_packets(sys.argv[1]):
  print(packet)
