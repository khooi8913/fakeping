/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xzk.fakeping;

import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

/**
 * Fake ping application
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;
    private PacketChecker packetChecker = new PacketChecker();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.foo.app");
        packetService.addProcessor(packetChecker, PacketProcessor.director(2));
        requestIntercepts();
        log.info("Started", appId.id());
    }

    // Request packet in via packet service
    private void requestIntercepts() {
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(trafficSelector.build(), PacketPriority.REACTIVE, appId);
    }

    // To cancel request for packet in via packet service
    private void withdrawIntercepts() {
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(trafficSelector.build(), PacketPriority.REACTIVE, appId);
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        log.info("Stopped", appId.id());
    }

    private class PacketChecker implements PacketProcessor {

        @Override
        public void process(PacketContext packetContext) {

            // Stop processing if the packet has already been handled.
            // Nothing much more can be done.
            if(packetContext.isHandled()){
                return;
            }

            InboundPacket inboundPacket = packetContext.inPacket();
            Ethernet ethernetPacket = inboundPacket.parsed();

            if(isControlPacket(ethernetPacket)) return;

            log.info("Packet received from device -> " + inboundPacket.receivedFrom().deviceId() +
                    " port number -> " + inboundPacket.receivedFrom().port().toString());


            switch(EthType.EtherType.lookup(ethernetPacket.getEtherType())){
                case ARP:
                    log.info("ARP packet received!");
                    ARP arpPacket = (ARP) ethernetPacket.getPayload();
                    Ip4Address targetIpAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                    // Generate fake ARP reply with fake MAC
                    byte [] tempMac = {22,22,22,22,22,22};
                    MacAddress macAddress = new MacAddress(tempMac);
                    Ethernet ethernet = ARP.buildArpReply(targetIpAddress, macAddress, ethernetPacket);

                    TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
                    builder.setOutput(inboundPacket.receivedFrom().port());
                    packetService.emit(new DefaultOutboundPacket(
                            inboundPacket.receivedFrom().deviceId(),
                            builder.build(),
                            ByteBuffer.wrap(ethernet.serialize())));
                    break;

                case IPV4:
                    log.info("IPv4 packet received!");
                    IPv4 ipv4Packet = (IPv4) ethernetPacket.getPayload();

                    log.info("Source IP -> " + Ip4Address.valueOf(ipv4Packet.getSourceAddress())
                            .getIp4Address().toString() +
                            " Destination IP -> " + Ip4Address.valueOf(ipv4Packet.getDestinationAddress())
                            .getIp4Address().toString());

                    // Generate fake ICMP reply
                    if(ipv4Packet.getProtocol() == IPv4.PROTOCOL_ICMP){
                        log.info("Ping detected! ");

                        // ICMP
                        ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                        icmpPacket.setIcmpCode(ICMP.TYPE_ECHO_REPLY);
                        ipv4Packet.setPayload(icmpPacket);

                        // IP
                        String sourceAddress = Ip4Address.valueOf(ipv4Packet.getSourceAddress())
                                .getIp4Address().toString();
                        String destAddress = Ip4Address.valueOf(ipv4Packet.getDestinationAddress())
                                .getIp4Address().toString();
                        ipv4Packet.setDestinationAddress(sourceAddress);
                        ipv4Packet.setSourceAddress(destAddress);
                        ethernetPacket.setPayload(ipv4Packet);

                        // Ethernet
                        MacAddress sourceMac = ethernetPacket.getSourceMAC();
                        MacAddress destMac = ethernetPacket.getDestinationMAC();
                        ethernetPacket.setSourceMACAddress(destMac);
                        ethernetPacket.setDestinationMACAddress(sourceMac);

                        // Output packet
                        builder = DefaultTrafficTreatment.builder();
                        builder.setOutput(inboundPacket.receivedFrom().port());
                        packetService.emit(new DefaultOutboundPacket(
                                inboundPacket.receivedFrom().deviceId(),
                                builder.build(),
                                ByteBuffer.wrap(ethernetPacket.serialize())));
                    }
                    break;
            }
        }
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

}
