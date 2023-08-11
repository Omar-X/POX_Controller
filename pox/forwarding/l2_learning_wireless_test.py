# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

import time
import sys
import random  # EDIT MESH TEAM
import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
from pox.lib import packet as pkt
from pox.openflow.discovery_new import LLDPSender, Link, LinksHandler, even_round_include_list, \
    odd_round_include_list  # EDIT MESH TEAM
from rich import inspect  # EDIT MESH TEAM

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

# EDITS MESH TEAM
SAVE_OUT = True
FILENAME = '/home/omar/Documents/GraduationProject/X_SDN_X/researches/CollectedData/lldp_packets_pack.txt'
COUNTER = 0
max_time = 60
current_time = 0
totalMacToPort = {}
links = {}
connectionsList = set()
LinkHandle = LinksHandler()
last_arp_request = {}  # arp_request: (time.time(), dp_id, port)


def send_message_with_save(msg, filename, save_out, send_func=None, msg_section="", in_or_out="OUT"):
    global COUNTER, max_time, current_time
    COUNTER += 1
    if COUNTER == 1:
        current_time = time.time()
    if time.time() - current_time <= max_time and save_out:
        with open(filename, 'a') as f:
            data_split = str(msg).replace(" ", "").split("\n")
            f.write(str(COUNTER) + f" {in_or_out}: {msg_section} --> " + " | ".join(data_split[:]) + ' \n')
    if send_func:
        send_func(msg)


def save_data_in_file(msg, filename):
    global COUNTER, max_time, current_time
    COUNTER += 1
    if time.time() - current_time <= max_time:
        with open(filename, 'a') as f:
            f.write(str(COUNTER) + " Packet IN: " + str(msg) + '\n')


class LearningSwitch(object):
    """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """

    def __init__(self, connection, transparent):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent

        self.macToPort = {}

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        # We just use this to know when to log a helpful message
        self.hold_down_expired = _flood_delay == 0

        # EDITS MESH TEAM Delete this line later
        self.diff_time = []
        self.diff_list = []
        self.unique_id = random.randint(0, 1000000)
        self.read_once = False
        self.current_time = time.time()
        self.linkHandler = LinkHandle

        # log.debug("Initializing LearningSwitch, transparent=%s",
        #          str(self.transparent))

    def handle_closed_loop(self, event):
        """
        Handle closed loop
        """
        print("an event with dp_id:", event.dpid, "is not checked for closed loops yet")
        links_to_block = self.linkHandler.dpid_closed_paths(event.dpid)
        print("links to block:", links_to_block)
        print("Total flood blocked links:", self.linkHandler.flood_blocked_links)
        print("links not to block:", self.linkHandler.dont_block_links)
        for link_id in links_to_block:
            if link_id not in self.linkHandler.dont_block_links:
                self.linkHandler.no_flood_link(link_id)
        self.linkHandler.dpids[event.dpid].closed_paths_handled = True

    def lldp_packets_handler(self, event, packet):
        """
        Handle lldp packets
        """
        lldph = packet.find(pkt.lldp)
        # if lldph.tlvs[0].id.decode("utf-8")[-1] == "1":
        # print("Time:", round(time.time() - self.current_time, 3), end=" ")
        if event.port == 65535:
            print("packet received from switch with no specific destination")
        else:
            # print("Src address:", packet.src, "Dst address:", event.connection.ports[event.port],
            #       event.connection.ports[event.port].hw_addr)
            # print(round(time.time() - self.current_time, 3), end=" ")
            # print the size of the packet
            # print("packet size:", len(event.ofp), end=" ")
            # print(lldph.tlvs[0].id.decode("utf-8") + " <-> Port: " + (totalMacToPort[packet.src] if packet.src in totalMacToPort.keys() else "unknown")
            #       + " --> dpid:" + str(event.dpid) + " <-> Port: " + str(event.port))
            if packet.src in totalMacToPort.keys():
                self.linkHandler.set_link(
                    Link(event.dpid, event.port, int(lldph.tlvs[0].id.decode("utf-8").split(":")[-1], 16),
                         int(totalMacToPort[packet.src])))
                links[
                    (int(lldph.tlvs[0].id.decode("utf-8").split(":")[-1], 16), int(totalMacToPort[packet.src]))] = (
                    event.dpid, event.port)
                links[event.dpid, event.port] = (
                    int(lldph.tlvs[0].id.decode("utf-8").split(":")[-1], 16), int(totalMacToPort[packet.src]))
                host_ports = self.linkHandler.get_dpid_host_ports(event.dpid)
            # print("self mac to port: \n", self.macToPort)
            # print("total mac to port: \n", totalMacToPort)
            # print("--------------------------------------")
        # for tlv in lldph.tlvs:
        #     # if not self.read_once:
        #     #     inspect(tlv, methods=True)
        #     print(tlv.tlv_type, tlv.pack(), tlv.id if tlv.tlv_type in [1, 2] else None)
        #     send_message_with_save(tlv.pack(), FILENAME, SAVE_OUT, in_or_out="Packet IN")
        # self.read_once = True

    def arp_packets_handler(self, event, packet):
        """Flooding ARP requests across all ports in the network can lead to unnecessary traffic and increase the
        load on the controller and switches. By selectively forwarding ARP requests to the relevant ports,
        you are reducing the broadcast domain and limiting the scope of the ARP resolution process,
        which can improve network performance and reduce latency. """
        if packet.payload.opcode == pkt.arp.REQUEST:
            if packet.payload in last_arp_request.keys():
                if time.time() - last_arp_request[packet.payload][0] < 1:
                    return
                else:  # pop the old one
                    last_arp_request.pop(packet.payload)
            last_arp_request[packet.payload] = [time.time(), event.dpid, event.port]
            # inspect(event.ofp, methods=True)
            for dpid in self.linkHandler.dpids.keys():
                available_ports = self.linkHandler.get_dpid_host_ports(dpid)
                msg = of.ofp_packet_out()
                event.ofp.in_port = of.OFPP_NONE  # this point is critical
                msg.data = event.ofp
                # msg.in_port = of.OFPP_NONE
                if available_ports:
                    for port in available_ports:
                        msg.actions.append(of.ofp_action_output(port=port))
                    self.linkHandler.dpids[dpid].send_msg(msg)
        elif packet.payload.opcode == pkt.arp.REPLY:
            for key in last_arp_request.keys():
                if key.hwsrc == packet.payload.hwdst:
                    msg = of.ofp_packet_out()
                    # msg.in_port = event.port
                    event.ofp.in_port = of.OFPP_NONE  # this point is critical
                    msg.data = event.ofp
                    msg.actions.append(of.ofp_action_output(port=last_arp_request[key][2]))
                    if last_arp_request[key][1] in self.linkHandler.dpids.keys():
                        self.linkHandler.dpids[last_arp_request[key][1]].send_msg(msg)
                    else:
                        print("dpid not found in linkHandler.dpids")
                        core.openflow.sendToDPID(last_arp_request[key][1], msg)
                    last_arp_request.pop(key)
                    break
        else:
            print("Unknown ARP opcode:", packet.payload.opcode)

    def _handle_PacketIn(self, event):
        """
    Handle packet in messages from the switch to implement above algorithm.
    """

        packet = event.parsed
        # MESH TEAM EDITS Delete these lines later
        # Check if the packet is ICMP or ARP
        # if packet.type == packet.IP_TYPE or packet.type == packet.ARP_TYPE:
        #     print("dpid:", event.dpid,"port:", event.port, "packet received:", packet.payload)
        # inspect(event.connection.ports, methods=True)
        # inspect(self.connection.ports, methods=True)
        # if packet.dst != pkt.ETHERNET.NDP_MULTICAST:
        #     print("packet source: ", packet.src, " packet destination: ", packet.dst)
        # MESH TEAM EDITS Delete these lines later
        # check if the packet is an ICMP packet
        # print(self.unique_id, " --> packet received --> ", packet.payload)
        # check if the packet is an ICMP packet
        # if packet.type == packet.IP_TYPE:
        #     # if the packet is an ICMP packet, send it to the controller
        #     msg = of.ofp_packet_out()
        #     msg.data = event.ofp
        #     # msg.actions.append(of.ofp_action_ output(port=of.OFPP_CONTROLLER))
        #     self.connection.send(msg)
        #     print("ICMP packet received\n")
        #     if not self.diff_time:  # if the dict is empty
        #         print(self.unique_id, " Time difference: ", 0)
        #         self.diff_time.append(time.time())
        #     else:
        #         self.diff_time.append(time.time())
        #         self.diff_list.append(self.diff_time[-1] - self.diff_time[-2])
        #         print(self.unique_id, " Time difference: ", self.diff_list[-1])
        #         print(self.unique_id, " Average time difference: ", sum(self.diff_list) / len(self.diff_list))

        if packet.effective_ethertype == packet.LLDP_TYPE:
            self.lldp_packets_handler(event, packet)
            # return
        if packet.effective_ethertype != packet.LLDP_TYPE and packet.effective_ethertype != packet.IPV6_TYPE:
            print("packet received at dpid:", event.dpid, "port:", event.port, "packet:", hex(packet.effective_ethertype),
                  packet.src, packet.dst)

        def flood(message=None):
            """ Floods the packet """
            if not self.linkHandler.dpids[event.dpid].closed_paths_handled:
                self.handle_closed_loop(event)
            if packet.effective_ethertype != packet.LLDP_TYPE and packet.effective_ethertype != packet.IPV6_TYPE:
                print("flooded")
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                # Only flood if we've been connected for a little while...

                if self.hold_down_expired is False:
                    # Oh yes it is!
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding",
                             dpid_to_str(event.dpid))

                if message is not None: log.debug(message)
                # log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
                # OFPP_FLOOD is optional; on some switches you may need to change
                # this to OFPP_ALL.
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            else:
                pass
                # log.info("Holding down flood for %s", dpid_to_str(event.dpid))
            msg.data = event.ofp
            msg.in_port = event.port

            self.connection.send(msg)
            # send_message_with_save(msg, FILENAME, self.connection.send, SAVE_OUT, "FLOOD")

        def drop(duration=None):
            """
              Drops this packet and optionally installs a flow to continue
              dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration, duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
                # send_message_with_save(msg, FILENAME, self.connection.send, SAVE_OUT, "DROP")
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)
                # send_message_with_save(msg, FILENAME, self.connection.send, SAVE_OUT, "DROP")

        self.macToPort[packet.src] = event.port  # 1
        if packet.type == packet.ARP_TYPE:
            self.arp_packets_handler(event, packet)
            return
        if not self.transparent:  # 2
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                log.debug("Ignoring LLDP or STP packet")
                drop()  # 2a
                return

        if packet.dst.is_multicast:
            log.debug("Flooding multicast packet")
            flood()  # 3a
        else:
            if packet.dst not in self.macToPort:  # 4
                flood("Port for %s unknown -- flooding" % (packet.dst,))  # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:  # 5
                    # print("Time:", round(time.time() - self.current_time, 3), end=" ")
                    # 5a
                    log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                                % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return
                # 6
                log.debug("installing flow for %s.%i -> %s.%i" %
                          (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port=port))
                msg.data = event.ofp  # 6a
                self.connection.send(msg)
                # send_message_with_save(msg, FILENAME, self.connection.send, SAVE_OUT, "SEND TO TARGET")


class l2_learning(object):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """

    def __init__(self, transparent, ignore=None):
        """
    Initialize

    See LearningSwitch for meaning of 'transparent'
    'ignore' is an optional list/set of DPIDs to ignore
    """
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.ignore = set(ignore) if ignore else ()

        # Mesh Team Edit
        self.linkHandler = LinkHandle

    def _handle_ConnectionUp(self, event):
        if event.dpid in self.ignore:
            log.debug("Ignoring connection %s" % (event.connection,))
            return
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)
        connectionsList.add(event.connection)  # MESH TEAM EDIT
        self.linkHandler.set_dpid(event.dpid, event.connection)  # MESH TEAM EDIT
        self.set_lldp_rules_on_switch(event.connection)  # MESH TEAM EDIT

        # set a rule on switch number 3,1 to stop flooding on port 3
        # if event.dpid == 3 or event.dpid == 1:
        #     msg = of.ofp_flow_mod()
        #     msg.match.in_port = 3
        #     msg.actions.append(of.ofp_action_output(port=of.OFPPC_NO_FLOOD))
        #     event.connection.send(msg)
        #     print("No flood rule on switch:", event.dpid)

    def _handle_ConnectionDown(self, event):
        log.debug("Connection %s" % (event.connection,))
        connectionsList.remove(event.connection)
        self.linkHandler.drop_dpid(event.dpid)  # MESH TEAM EDIT

    def set_lldp_rules_on_switch(self, connection):
        msg = of.ofp_flow_mod()
        # msg.priority = 65535
        msg.match.in_port = of.OFPP_CONTROLLER
        msg.match.dl_type = pkt.ethernet.LLDP_TYPE
        for port in connection.ports:
            if port != of.OFPP_LOCAL:
                # MESH TEAM EDIT for easy access
                self.linkHandler.mac_to_dpid[connection.ports[port].hw_addr] = connection.dpid
                totalMacToPort[connection.ports[port].hw_addr] = str(port)
                msg.actions.append(of.ofp_action_dl_addr.set_src(connection.ports[port].hw_addr))
                msg.actions.append(of.ofp_action_output(port=port))
        connection.send(msg)
        # print("DPID:", connection.dpid)
        # print("OFP message:\n", msg)
        # send_message_with_save(msg, FILENAME, connection.send, SAVE_OUT, "LLDP RULES")


def launch(transparent=False, hold_down=_flood_delay, ignore=None):
    """
  Starts an L2 learning switch.
  """
    global current_time  # MESH TEAM EDIT
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    if ignore:
        ignore = ignore.replace(',', ' ').split()
        ignore = set(str_to_dpid(dpid) for dpid in ignore)

    core.registerNew(l2_learning, str_to_bool(transparent), ignore)
    LLDPSender(8)
    # print("Time (s), CPU Time, CPU cumulative time (ms), Total system CPU time (ms), CPU usage (%)")
    current_time = time.time()  # MESH TEAM EDIT
