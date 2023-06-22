# This file is part of NetPlier, a tool for binary protocol reverse engineering.
# Copyright (C) 2021 Yapeng Ye

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import argparse
import sys
import os
import logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
#logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
import random
from netplier import NetPlier
from processing import Processing
from alignment import Alignment
from clustering import Clustering

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', required=True, dest='filepath_input', help='filepath of input trace')
    parser.add_argument('-t', '--type', dest='protocol_type', help='type of the protocol (for generating the ground truth): \
        dhcp, dnp3, icmp, modbus, ntp, smb, smb2, tftp, zeroaccess')
    parser.add_argument('-o', '--output_dir', dest='output_dir', default='tmp_netplier/', help='output directory')
    parser.add_argument('-l', '--layer', dest='layer', default=5, type=int, help='the layer of the protocol')
    parser.add_argument('-m', '--mafft', dest='mafft_mode', default='ginsi', help='the mode of mafft: [ginsi, linsi, einsi]')
    parser.add_argument('-mt', '--multithread', dest='multithread', default=False, action='store_true', help='run mafft with multi threads')
    parser.add_argument('-rd', '--randomdir', dest='randomdir', default=False, action='store_true', help='randomize direction')
    parser.add_argument('-sd', '--sessiondir', dest='sessiondir', default=False, action='store_true', help='use sessions for direction')
    parser.add_argument('-single', '--single', dest='single', default=False, action='store_true', help='unidirectional calculation')
    parser.add_argument('-remote', '--remote', dest='remote', default=True, action='store_false', help='unidirectional calculation')
    parser.add_argument('-getdir', '--getdir', dest='getdir', default='', help='Get directions from this file')

    args = parser.parse_args()

    dat = """
          00ffff
          00eeee
          0100000000
          0100ff0000
          01000000
          0100000000
    """.strip().split("\n")
    dat = [bytes.fromhex(d.strip()) for d in dat]



    p = Processing(filepath=args.filepath_input, protocol_type=args.protocol_type, layer=args.layer, randomdir=args.randomdir, sessiondir=args.sessiondir, getdir=args.getdir, remote=args.remote)
    # p.print_dataset_info()
    
    # We now have direction data.

    mode = args.mafft_mode
    if args.protocol_type in['dnp3']: # tftp
        mode = 'linsi'

    p.direction_list = [0 for v in p.direction_list]
    if args.getdir != '':
        def file2dirs(filename):
            f = open(filename)
            data = f.read().strip().split("\n")
            f.close()
            dirs = [int(line.split("\t")[1]) for line in data]
            return dirs
        try:
            p.direction_list = file2dirs(args.getdir)
        except:
            pass
    random.seed(0)

    # randomized direction
    p.direction_list = [random.choice([0,1]) for p in p.direction_list]
    netplier = NetPlier(messages=p.messages, direction_list=p.direction_list, output_dir=args.output_dir, mode=mode, multithread=args.multithread,single=args.single)
    
    
    fid_inferred = netplier.execute()
    if len(fid_inferred) > 0:
        print("fid_inferred",fid_inferred)
    else:
        print("fid_inferred","No Field Inferred")
    
    quit()
    # Clustering
    messages_aligned = Alignment.get_messages_aligned(netplier.messages, os.path.join(netplier.output_dir, Alignment.FILENAME_OUTPUT_ONELINE))
    messages_request, messages_response = Processing.divide_msgs_by_directionlist(netplier.messages, netplier.direction_list)
    messages_request_aligned, messages_response_aligned = Processing.divide_msgs_by_directionlist(messages_aligned, netplier.direction_list)

    clustering = Clustering(fields=netplier.fields, protocol_type=args.protocol_type)
    clustering_result_request_true = clustering.cluster_by_kw_true(messages_request)
    clustering_result_response_true = clustering.cluster_by_kw_true(messages_response)
    print("result request")
    clustering_result_request_netplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_request_aligned)
    print("results response")
    clustering_result_response_netplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_response_aligned)
    print("results both")
    clustering_result_netplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_aligned)
    clustering.evaluation([clustering_result_request_true, clustering_result_response_true], [clustering_result_request_netplier, clustering_result_response_netplier])
    
