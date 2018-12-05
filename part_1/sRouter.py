from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import IPAddr
from pox.lib.packet import ethernet
from pox.lib.packet import arp, ipv4, icmp
from pox.lib.packet.icmp import TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY, TYPE_DEST_UNREACH, CODE_UNREACH_NET, CODE_UNREACH_HOST
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST

log = core.getLogger()


arpCache = {}

portsIP = {}

DST_Network = 0
NETX_HOP_IP = 1
NEXT_PORT_IP = 2
NEXTHOP_PORT = 3

pPORT = 0
PORT_IP = 1
PORT_MAC = 2

def ifReach(dstip, event, self):

    dpid = self.connection.dpid
    #search the routeTable
    for subRouteTable in self.routeTable:
        #extract the network address
        dstnetwork = subRouteTable[DST_Network]
        #if destination IP in network address in the routetable
        if dstip.inNetwork(dstnetwork):
            log.debug('------ip dst %s is in the routeTable-----' % dstip)
            
            nextPort = subRouteTable[NEXTHOP_PORT]
            log.debug('------IP dst port %s is in the routeTable-----' % nextPort)
            #if routeTable tells to send it back, do nothing and continue loop
            if nextPort == event.ofp.in_port:
                continue
       
            nextHopIp = IPAddr(subRouteTable[NETX_HOP_IP])
            nextPortIp = IPAddr(subRouteTable[NEXT_PORT_IP])
            srcMac = arpCache[dpid][nextPort][nextPortIp]


            #if router knows desIP's MAC address, forwarding the packet
            if nextHopIp in arpCache[dpid][nextPort]:
                log.debug('------I know the next dst %s mac-----' % nextHopIp)
                nextHopMac = arpCache[dpid][nextPort][nextHopIp]

                msg=of.ofp_flow_mod()
                msg.match = of.ofp_match()
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_dst = dstip

                msg.command = 0
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.buffer_id = event.ofp.buffer_id
                msg.actions.append(of.ofp_action_dl_addr.set_src(srcMac))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextHopMac))
                msg.actions.append(of.ofp_action_output(port=nextPort))
                self.connection.send(msg)
   
                log.debug('------install a flow-----')
            #else router does not knows detIP's MAC address, send ARP request.
            else:
                log.debug('------I do not know the next dst %s mac,make an arp request' % IPAddr(subRouteTable[NETX_HOP_IP]))
                ARPrequest = arp()
                ARPrequest.opcode = arp.REQUEST
                ARPrequest.protosrc = nextPortIp
                ARPrequest.hwsrc = srcMac
                ARPrequest.protodst = nextHopIp
                arpPacket = ethernet(type=ethernet.ARP_TYPE, src=ARPrequest.hwsrc, dst=ETHER_BROADCAST)
                arpPacket.set_payload(ARPrequest)
                msg = of.ofp_packet_out()
                msg.data = arpPacket.pack()
                msg.actions.append(of.ofp_action_output(port=nextPort))
                msg.in_port = event.ofp.in_port
                event.connection.send(msg)
                log.debug('------Arp request has been snet-----')
            
                nextHopMac = ETHER_BROADCAST
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                msg.buffer_id = event.ofp.buffer_id
                msg.actions.append(of.ofp_action_dl_addr.set_src(srcMac))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextHopMac))
                msg.actions.append(of.ofp_action_output(port=nextPort))
                self.connection.send(msg)

            return True
    return False

def ifEcho(ipLoad, dstip, self, event):
    packet = event.parsed
    dpid = self.connection.dpid
    for portIP in portsIP[dpid]:
        selfip = portIP[PORT_IP]
        if dstip == selfip:

            if ipLoad.protocol == ipv4.ICMP_PROTOCOL:
                log.debug('-----An icmp for router-----')
                icmpLoad = ipLoad.payload

                if icmpLoad.type == TYPE_ECHO_REQUEST:
                    selfmac = portIP[PORT_MAC]
                    
                    reply = icmpLoad
                    reply.type = TYPE_ECHO_REPLY

                    ipShell = ipv4()
                    ipShell.protocol = ipv4.ICMP_PROTOCOL
                    ipShell.srcip = selfip
                    ipShell.dstip = ipLoad.srcip
                    ipShell.payload = reply

                    etherShell = ethernet()
                    etherShell.type = ethernet.IP_TYPE
                    etherShell.src = selfmac
                    etherShell.dst = packet.src
                    etherShell.payload = ipShell

                    msg = of.ofp_packet_out()
                    msg.data = etherShell.pack()
                    msg.actions.append(of.ofp_action_output(port=event.port))
                    self.connection.send(msg)
                    return True
                else:
                    return True
            else:
                return True
        else:
            return False

def handleIP(self, event):
    dpid=self.connection.dpid
    packet = event.parsed
    ipLoad = packet.payload
    dstip = ipLoad.dstip
    log.debug('-----It is an ip packet-----'+ str(dstip))
    if ifEcho(ipLoad, dstip, self, event)!=True : #if it is not an ICMP echo to router
        if ifReach(dstip, event, self)!=True : #if dst IP is not in the Route Table
            #construct an ICMP host unreachable packet
            reply = icmp()
            reply.type = TYPE_DEST_UNREACH
            reply.code = CODE_UNREACH_NET
            payLoad = ipLoad.pack()[:ipLoad.iplen + 8]
            import struct
            payLoad = struct.pack("!I", 0) + payLoad

            reply.payload = payLoad
            ipShell = ipv4()
            ipShell.protocol = ipv4.ICMP_PROTOCOL
            for portIP in portsIP[dpid]:
                selfip = portIP[PORT_IP]
                if(event.port == portIP[pPORT]):
                    ipShell.srcip = selfip
                    break
            ipShell.dstip = ipLoad.srcip
            ipShell.payload = reply
            etherShell = ethernet()
            etherShell.type = ethernet.IP_TYPE
            etherShell.src = packet.dst
            etherShell.dst = packet.src
            etherShell.payload = ipShell

            msg = of.ofp_packet_out()
            msg.data = etherShell.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

def handleARP(self, event):
        dpid = self.connection.dpid
        packet = event.parsed
        arpLoad = packet.payload
        #if is a arp.REPLY packet
        if arpLoad.opcode == arp.REPLY:
            #add both source and destination IP and MAC into ArpCache
            arpCache[dpid][event.ofp.in_port][arpLoad.protosrc] = arpLoad.hwsrc
            arpCache[dpid][event.ofp.in_port][arpLoad.protodst] = arpLoad.hwdst
        #if is a arp.REQUEST
        if arpLoad.opcode == arp.REQUEST:
            log.debug('------Arp request-----')
            log.debug('------' + arpLoad._to_str())
            #add source IP and MAC into arpCache
            arpCache[dpid][event.ofp.in_port][arpLoad.protosrc] = arpLoad.hwsrc
            log.debug('------arpTable learned form arp Request-----')
            log.debug('------' + str(arpCache))
            log.debug('-------'+ str(arpLoad.protodst))
            log.debug('-------'+ str(self.connection.dpid))
            log.debug('-------'+ str(event.ofp.in_port))
            log.debug('-------'+ str(arpLoad.protodst in arpCache[self.connection.dpid][event.ofp.in_port]))
            if arpLoad.protodst in arpCache[dpid][event.ofp.in_port]:
                log.debug('------I know that ip %s, send reply-----'%arpLoad.protodst)
                    
                reArp = arpLoad
                fBack = arp()

                fBack.protolen = reArp.protolen
                fBack.opcode = arp.REPLY
                fBack.hwdst = reArp.hwsrc
                fBack.hwtype = reArp.hwtype
                fBack.prototype = reArp.prototype
                fBack.hwlen = reArp.hwlen
                fBack.protodst = reArp.protosrc
                fBack.protosrc = reArp.protodst
                fBack.hwsrc = arpCache[dpid][event.ofp.in_port][arpLoad.protodst]
                fbEnther = ethernet(type=packet.type, src=fBack.hwsrc,dst=reArp.hwsrc)
                fbEnther.set_payload(fBack)
                msg = of.ofp_packet_out()
                msg.data = fbEnther.pack()
                msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
                self.connection.send(msg)

class router1(object):
    
    #initialize router1's data 
    def __init__(self,connection):
        dpid = connection.dpid
        log.debug('-----' + "dpid=" + str(dpid) + '-----')
        log.debug('-----' + "I am Router1" +  '-----')
        arpCache[dpid]={}
        portsIP[dpid]=[]
        #bind router ports with a IP in topo and initialize the ArpTable
        for ports in connection.ports.values():
            port=ports.port_no
            mac=ports.hw_addr
            arpCache[dpid][port]={}
            if port == 1:
                ip = IPAddr('10.0.1.1')
                arpCache[dpid][port][ip]=mac
                portsIP[dpid].append([port, ip, mac])
            elif port == 2:
                ip = IPAddr('10.0.2.1')
                arpCache[dpid][port][ip]=mac
                portsIP[dpid].append([port, ip, mac])
            elif port == 3:
                ip = IPAddr('10.0.3.1')
                arpCache[dpid][port][ip]=mac
                portsIP[dpid].append([port, ip, mac])
            else:
                ip = IPAddr('0.0.0.0')
                arpCache[dpid][port][ip]=mac
                portsIP[dpid].append([port, ip, mac])
       
        log.debug('-----' + 'arpCache' + '-----')
        log.debug(arpCache)

        log.debug('-----'+ 'portsTable' + '-----')
        log.debug(portsIP)

        #create a route table
        self.routeTable = []
        self.routeTable.append(['10.0.1.0/24', '10.0.1.100', '10.0.1.1', 1])
        self.routeTable.append(['10.0.2.0/24', '10.0.2.100', '10.0.2.1', 2])
        self.routeTable.append(['10.0.3.0/24', '10.0.3.100', '10.0.3.1', 3])
        
        #add listener to a event
        self.connection = connection
        connection.addListeners(self)

    #handle the event called PacketIn
    def _handle_PacketIn(self,event):
        dpid = self.connection.dpid
        log.debug('-----' + "dpid=" + str(dpid) + '-----' )
        log.debug("-----A PacketIn event occurs-----")
        log.debug(event.ofp.in_port)
        packet = event.parsed
        
        if packet.type == ethernet.ARP_TYPE:
            log.debug('-----It is an arp packet-----')
            handleARP(self, event)

            
        
        if packet.type == ethernet.IP_TYPE:
            log.debug('-----It is an ip packet-----')
            handleIP(self, event)
    
class SwitchWarmUp(object):
    def __init__(self):
        core.openflow.addListeners(self)  # add listeners to listen event
    
    def _handle_ConnectionUp(self,event): # handle event called ConnectionUp 
        dpid = event.connection.dpid
        log.debug("-----dpid=" + str(dpid))
        log.debug('------'+ "A Switch ConnectionUp" + '-----')
        if dpid ==1:
            router1(event.connection)
        

#register a new component to handle event
def launch():
    core.registerNew(SwitchWarmUp)










