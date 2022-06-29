from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp

from ryu.lib import hub
import csv
import time
import math
import statistics
import keras
from sklearn import preprocessing
import joblib
#from svm import SVM

APP_TYPE = 1
#0 datacollection, 1 ddos detection

PREVENTION = 1
# ddos prevention

#TEST_TYPE is applicable only for data collection
#0  normal traffic, 1 attack traffic
TEST_TYPE = 1

#data collection time interval in seconds
INTERVAL = 2
#-------------------------------------------------------#




FLOW_SERIAL_NO = 0
iteration = 0




def get_flow_number():
    global FLOW_SERIAL_NO
    FLOW_SERIAL_NO = FLOW_SERIAL_NO + 1
    return FLOW_SERIAL_NO


def init_portcsv(dpid):
    fname = "switch_" + str(dpid) + "_data.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["time", "sfe","ssip","rfip","type"]
    writ.writerow(header)


def init_flowcountcsv(dpid):
    fname = "switch_" + str(dpid) + "_flowcount.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["time", "flowcount"]
    writ.writerow(header)

def init_resultcsv():
    fname = "result.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    header = ["packet count","byte count", "duration", "idele timeout", "hard timeout", "Label"]
    writ.writerow(header)


def update_flowcountcsv(dpid, row):
    fname = "switch_" + str(dpid) + "_flowcount.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    writ.writerow(row)


def update_portcsv(dpid, row):
    fname = "switch_" + str(dpid) + "_data.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    row.append(str(TEST_TYPE))
    writ.writerow(row)


def update_resultcsv(row):
    fname = "result.csv"
    writ = csv.writer(open(fname, 'a', buffering=1), delimiter=',')
    row.append(str(TEST_TYPE))
    writ.writerow(row)





class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_thread = hub.spawn(self._flow_monitor)
        self.datapaths = {}
        self.flow_detector = keras.models.load_model('model_ANN2.h5')
        self.arp_ip_to_port = {}
        self.attack_sources = []
        self.scaler=joblib.load('scaler.gz')


    def _flow_monitor(self):
        #inital delay
        hub.sleep(5)
        while True:
            #self.logger.info("Starts Flow monitoring")
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        #init_portcsv(datapath.id)


        flow_serial_no = get_flow_number()

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flow_serial_no)

        #init_portcsv(datapath.id)
        #init_flowcountcsv(datapath.id)
        #init_resultcsv()

    def request_flow_metrics(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)


    @set_ev_cls([ofp_event.EventOFPFlowStatsReply], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = ev.msg.body
        
        dp = ev.msg.datapath

        for stat in [flow for flow in flows if flow.priority==1]:

            #if stat.match['ipv4_src']=='172.16.1.2':
                packet_count=stat.packet_count
                byte_count=stat.byte_count
                duration=stat.duration_sec
                idle_timeout=stat.idle_timeout
                hard_timeout=stat.hard_timeout
                data_collection=[[packet_count,byte_count,duration,idle_timeout, hard_timeout]]
                data_collection=self.scaler.transform(data_collection)
                print(data_collection)

                if APP_TYPE == 1:
                    result = (self.flow_detector.predict(data_collection)>0.5).astype(int)

                    if  result==1:
                        flow_serial_no=stat.cookie
                        self.drop_packet(dp,flow_serial_no)
                        print('Attack Flow detected : {} to {}'.format(stat.match['ipv4_src'], stat.match['ipv4_dst']))
                        print('Dropped the packet from {}'.format(stat.match['ipv4_src']))

    
                    if result==0:
                        print("{} is Normal Traffic".format(stat.match['ipv4_src']))

                else:
                    t = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
                    row = [t, str(packet_count), str(byte_count), str(duration), str(idle_timeout), str(hard_timeout)]
                    self.logger.info(row)
                    update_resultcsv([str(packet_count), str(byte_count), str(duration), str(idle_timeout), str(hard_timeout)])

    def add_flow(self, datapath, priority, match, actions,serial_no, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, buffer_id=buffer_id,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, priority=priority,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def drop_packet(self, datapath, flow_serial_no, priority=1, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #match = parser.OFPMatch(ipv4_src=srcip)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=flow_serial_no, buffer_id=buffer_id, command=ofproto.OFPFC_MODIFY,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    priority=priority,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=flow_serial_no, command=ofproto.OFPFC_MODIFY,priority=priority,
                                    idle_timeout=idletime, hard_timeout=hardtime,
                                    instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:

            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        #if ARP Request packet , log the IP and MAC Address from that port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            #self.logger.info("Received ARP Packet %s %s %s ", dpid, src, dst)
            a = pkt.get_protocol(arp.arp)
            #print "arp packet ", a
            if a.opcode == arp.ARP_REQUEST or a.opcode == arp.ARP_REPLY:
                if not a.src_ip in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(a.src_ip)
                    #print "arp_ip_to_port " ,self.arp_ip_to_port


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto


                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip)

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                flow_serial_no = get_flow_number()
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no,  buffer_id=msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
