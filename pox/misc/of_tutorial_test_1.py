# Copyright 2012 James McCauley
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
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.discovery import Discovery, LLDPSender, LinkEvent
import pox.lib.packet as pkt
import time
from rich import inspect
from threading import Thread

log = core.getLogger()


class Tutorial(object):
    """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # self.lldp_sender = LLDPSender(5)
        # self.disc = Discovery()
        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}
        self.dpid_to_mac = {}
        self.lldp_packets_sent = 0
        self.lldp_packets_received = 0
        # Thread(target=self.send_lldp_loop).start()
        # self.send_lldps()

    def send_packet(self, packet, out_port):
        """
        Send packet to out_port
        :param packet:
        :param out_port:
        :return:
        """
        msg = of.ofp_packet_out()
        msg.data = packet
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def resend_packet(self, packet_in, out_port):
        """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def act_like_hub(self, packet, packet_in):
        """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

        # We want to output to all ports -- we do that using the special
        # OFPP_ALL port as the output port.  (We could have also used
        # OFPP_FLOOD.)
        self.resend_packet(packet_in, of.OFPP_ALL)

        # Note that if we didn't get a valid buffer_id, a slightly better
        # implementation would check that we got the full data before
        # sending it (len(packet_in.data) should be == packet_in.total_len)).

    def act_like_switch(self, packet, packet_in):
        """
    Implement switch-like behavior.
    """

        # Learn the port for the source MAC
        log.debug("Packet: %s" % packet)
        if packet.dst in self.mac_to_port.keys():
            # Send packet out the associated port
            self.resend_packet(packet_in, self.mac_to_port[packet.dst])
        else:
            # Flood the packet out everything but the input port
            # This part looks familiar, right?
            self.resend_packet(packet_in, of.OFPP_ALL)

        """# Here's some psuedocode to start you off implementing a learning
        # switch.  You'll need to rewrite it as real Python code.
        
        # Learn the port for the source MAC
        self.mac_to_port ... <add or update entry>
        
        if the port associated with the destination MAC of the packet is known:
        # Send packet out the associated port
            self.resend_packet(packet_in, ...)
        
        # Once you have the above working, try pushing a flow entry
        # instead of resending the packet (comment out the above and
        # uncomment and complete the below.)
        
        log.debug("Installing flow...")
        # Maybe the log statement should have source/destination/port?
        
        #msg = of.ofp_flow_mod()
        #
        ## Set fields to match received packet
        #msg.match = of.ofp_match.from_packet(packet)
        #
        #< Set other fields of flow_mod (timeouts? buffer_id?) >
        #
        #< Add an output action, and send -- similar to resend_packet() >
        
        else:
          # Flood the packet out everything but the input port
          # This part looks familiar, right?
          self.resend_packet(packet_in, of.OFPP_ALL)
"""

    def send_lldp_loop(self):
        """
        Send LLDP packet every 5 seconds
        :return:
        """
        while True:
            self.send_lldps()
            log.debug("=================================\n")
            time.sleep(5)

    def send_lldps(self):
        """
        Send LLDP packet
        :return:
        """
        for key in self.dpid_to_mac.keys():
            self.lldp_packets_sent += 1
            log.debug(f"Sending LLDP packet {self.lldp_packets_sent} | number of ports {len(self.mac_to_port)} |"
                      f" key {key} | mac {self.dpid_to_mac[key]} ")

            lldp_packet = self.lldp_sender.create_packet_out(key, self.mac_to_port[self.dpid_to_mac[key]],
                                                             self.dpid_to_mac[key])
            self.connection.send(lldp_packet)

    def _handle_PacketIn(self, event):
        """
    Handles packet in messages from the switch.
    """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        # get the dpid of the switch
        dpid = event.dpid
        self.dpid_to_mac[dpid] = packet.src
        self.mac_to_port[packet.src] = packet_in.in_port

        # Comment out the following line and uncomment the one after
        # when starting the exercise.
        # self.act_like_hub(packet, packet_in)
        # check the ethernet type
        if packet.type == pkt.ethernet.LLDP_TYPE:  # packet type variable exist?
            log.debug(f"LLDP packet received: {packet}")
            return
        self.act_like_switch(packet, packet_in)


def launch():
    """
  Starts the component
  """

    def start_switch(event):
        log.debug("Controlling %s" % event.connection)
        Tutorial(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    LLDPSender(5)
