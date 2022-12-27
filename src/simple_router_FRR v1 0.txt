#include <core.p4>
#include <v1model.p4>


struct routing_metadata_t {
    bit<32> nhop_ipv4;
}


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


header  my_metadata_t {
     bit<1> link_state;
     bit<1> link_local;
     bit<1> link_uplink;

}

struct metadata {
    routing_metadata_t routing_metadata;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    my_metadata_t m;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {


    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
 transition accept;
    }
    state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    action _drop() {
        mark_to_drop();
    }
  table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }


    apply {

        send_frame.apply();

    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
   action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

   action drop(){
        mark_to_drop();
    }

   action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + (hdr.ipv4.ttl - 8w1);
    }

   action set_link_state(bit<1> link_state) {
        hdr.m.link_state = link_state;
    }

   action set_port_type(bit<1> link_local,bit<1> link_uplink) {
        hdr.m.link_local = link_local;
        hdr.m.link_uplink = link_uplink;
 }


   table port_type {
       actions = {
           set_port_type;

       }
       key = {
          standard_metadata.ingress_port: exact;
       }
       size = 512;
   }


    table forward {
        actions = {
            set_dmac;
            drop;

        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
        size = 512;
    }



    table ipv4_lpm_local {
        actions = {
            set_nhop;
            drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }


   table ipv4_lpm_transit {
        actions = {
            set_nhop;
            drop;
        }
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
  table egress_port_link_state {
         actions = {
            set_link_state;
            drop;
         }
         key = {
             standard_metadata.egress_spec : exact;
         }
         size = 512;
         default_action = drop();
    }

     apply {

              port_type.apply();
              ipv4_lpm_local.apply();
              ipv4_lpm_transit.apply();
              egress_port_link_state.apply();

              if (hdr.m.link_state == 1) {
                       if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
                       }


             } else {


                      if (hdr.m.link_state == 0) {
                          if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {

                                if (hdr.m.link_local == 1 && standard_metadata.egress_spec == 1){

                                    standard_metadata.egress_spec = 2;

                                } else {

                                       if (hdr.m.link_local == 1 && standard_metadata.egress_spec == 2){

                                          standard_metadata.egress_spec = 1;
                                       } else {

                                             if (hdr.m.link_local == 1 && standard_metadata.egress_spec > 2){
                                             standard_metadata.egress_spec = 0;
                                             }
                                       }
                                }


                                if (hdr.m.link_uplink == 1 && standard_metadata.egress_spec == 1){

                                     standard_metadata.egress_spec = standard_metadata.ingress_port;

                                } else {
                                         if (hdr.m.link_uplink == 1 && standard_metadata.egress_spec == 2){

                                            standard_metadata.egress_spec = standard_metadata.ingress_port;

                                         }  else {
                                               if (hdr.m.link_uplink == 1 && standard_metadata.egress_spec > 2){
                                                      standard_metadata.egress_spec = 0;
                                               }
                                         }
                                }

                          }
                       }
               }

            forward.apply();

      }

}

control DeparserImpl(packet_out packet, in headers hdr) {

    apply {
              packet.emit(hdr.ethernet);
              packet.emit(hdr.ipv4);

    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                                hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
                                hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
                                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                                hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                                hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
                                hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
                                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                                hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         DeparserImpl()) main;


