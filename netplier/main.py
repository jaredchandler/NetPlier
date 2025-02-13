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
    parser.add_argument('-remote', '--remote', dest='remote', default=True, action='store_false', help='do remote coupling')
    parser.add_argument('-origgt', '--origgt', dest='origgt', default=False, action='store_true', help='use the original Netplier KW indexes')
    parser.add_argument('-double', '--double', dest='double', default=False, action='store_true', help='double messages and balance dirs')

    args = parser.parse_args()

    p = Processing(filepath=args.filepath_input, protocol_type=args.protocol_type, layer=args.layer, randomdir=args.randomdir, sessiondir=args.sessiondir)
    # p.print_dataset_info()
    
    if args.double:

        newmsgs =[]
        newdirs = []

        for m in p.messages:
          newmsgs.append(m)
          newdirs.append(0)
          newmsgs.append(m)
          newdirs.append(1)
        # msglen = len(p.messages)
        # newmsgs = p.messages + p.messages
        # newdirs = [1 for i in range(msglen)] + [0 for i in range(msglen)]
        

        p.messages = newmsgs
        p.direction_list = newdirs
        
    if args.randomdir:
        import random
        random.shuffle(p.direction_list)
    
    
    mode = args.mafft_mode
    if args.protocol_type in['dnp3']: # tftp
        mode = 'linsi'
    netplier = NetPlier(messages=p.messages, direction_list=p.direction_list, output_dir=args.output_dir, mode=mode, multithread=args.multithread,single=args.single,remote=args.remote)
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
    

