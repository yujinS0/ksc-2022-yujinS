#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#define OP_GET 0
#define OP_G_REPLY 1
#define OP_MULTIGET 2
#define OP_MG_REPLY 3

#define NUM_OBJ 131072
#define MAX_KEY 8
#define NUM_SRV 4

#define OPTION1 32768
#define OPTION2 16384
#define OPTION3 8192

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> ether_type_t;
const ether_type_t TYPE_IPV4 = 0x800;
typedef bit<8> trans_protocol_t;
const trans_protocol_t TYPE_TCP = 6;
const trans_protocol_t TYPE_UDP = 17;
const bit<16> TYPE_NETSZ = 4321; // NOT 0x1234 // 수정
typedef bit<3> mirror_type_t; // ! mirror
const mirror_type_t MIRROR_TYPE_I2E = 1; // ! mirror

header ethernet_h {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header netsz_h { // Total 25 bytes actually
    bit<8> op; //operator
    bit<16> id; //request id = packet id
    bit<16> value; 
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header tcp_h {
    bit<16> srcport;
    bit<16> dstport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    netsz_h netsz;
}


struct metadata_t {
    bit<8> stage_num; // 몇번 째 스테이지까지 
    
    bit<16> count_invalid; 
    bit<16> chk_keyNum; 
    bit<16> cut_idx; //cutidx 저장하는 temp
    bit<16> key_num; //keynum 저장하는 temp
    bit<16> count_key_num; //value arr에서 사용하는 counter (패킷이 몇개 왔는지)
    bit<16> req_value; //요청(서버)에서 오는 value를 저장함, A+
    bit<16> last_pkt; // last packet
    bit<16> req_id; 
    bit<32> dst_srv_idx; //요청이 어떤 서버로 갈지
}

struct custom_metadata_t {

}

struct empty_header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    netsz_h netsz;
}

struct empty_metadata_t {
    custom_metadata_t custom_metadata;
}

Register<bit<16>,_>(1,0) dst_srv_idx; // result of hash server
Register<bit<16>,_>(1,0) pkt_idx;
Register<bit<8>,_>(NUM_OBJ,0) value; // stage


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort){
            TYPE_NETSZ: parse_netsz;
            default: accept;
        }
    }

    state parse_netsz {
        pkt.extract(hdr.netsz);
        transition accept;
    }

}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    action drop() {
        ig_intr_dprsr_md.drop_ctl=1;
    }

    action ipv4_forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 16;
       default_action = drop();
    }

    table ipv4_exact_netsz {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 16;
       default_action = drop();
    }

    // action get_dst_srv_action(){
    //     ig_md.dst_srv_idx = hdr.keys[0].oid%NUM_SRV; 
    // }

    // table get_dst_srv_table{
    //     actions = {
    //         get_dst_srv_action;
    //     }
    //     size = 1;
    //     default_action = get_dst_srv_action;
    // }

    // action get_dst_ip_action(bit<32> addr, bit<9> port){
    //     hdr.ipv4.dstAddr = addr;
    //     ig_tm_md.ucast_egress_port = port;
    // }

    // table get_dst_ip_table{
    //     key = {
    //         ig_md.dst_srv_idx: exact;
    //     }
    //     actions = {
    //         get_dst_ip_action;
    //     }
    //     size = 16;
    //     default_action = get_dst_ip_action(0,0x0);
    // }


    // Register
    RegisterAction<bit<16>, _, bit<16>>(value) check_stage_1 = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            return_value = reg_value;
        }
    };
    action check_stage_1_action(){
        check_stage_1.execute(hdr.netsz.value);
        //stage_num = 1; // 사용된 stage 개수 지정
    }
    table check_stage_1_table{
        actions = {
            check_stage_1_action;
        }
        size = 1;
        default_action = check_stage_1_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(value) check_stage_2 = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            return_value = reg_value;
        }
    };
    action check_stage_2_action(){
        check_stage_2.execute(hdr.netsz.value);
        //stage_num = stage_num + 1; // stage 개수 증가?
    }
    table check_stage_2_table{
        actions = {
            check_stage_2_action;
        }
        size = 1;
        default_action = check_stage_2_action;
    }
    
    RegisterAction<bit<16>, _, bit<16>>(value) check_stage_3 = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            return_value = reg_value;
        }
    };
    action check_stage_3_action(){
        check_stage_3.execute(hdr.netsz.value);
        //stage_num = stage_num + 1; // stage 개수 증가?
    }
    table check_stage_3_table{
        actions = {
            check_stage_3_action;
        }
        size = 1;
        default_action = check_stage_3_action;
    }

    RegisterAction<bit<16>, _, bit<16>>(value) check_stage_4 = {
        void apply(inout bit<16> reg_value, out bit<16> return_value){
            return_value = reg_value;
        }
    };
    action check_stage_4_action(){
        check_stage_4.execute(hdr.netsz.value);
        //stage_num = stage_num + 1; // stage 개수 증가?
    }
    table check_stage_4_table{
        actions = {
            check_stage_4_action;
        }
        size = 1;
        default_action = check_stage_4_action;
    }

    // RegisterAction<bit<16>, _, bit<16>>(value) check_stage_5 = {
    //     void apply(inout bit<16> reg_value, out bit<16> return_value){
    //         return_value = reg_value;
    //     }
    // };
    // action check_stage_5_action(){
    //     check_stage_5.execute(hdr.netsz.value);
    //     //stage_num = stage_num + 1; // stage 개수 증가?
    // }
    // table check_stage_5_table{
    //     actions = {
    //         check_stage_5_action;
    //     }
    //     size = 1;
    //     default_action = check_stage_5_action;
    // }

    // RegisterAction<bit<16>, _, bit<16>>(value) check_stage_6 = {
    //     void apply(inout bit<16> reg_value, out bit<16> return_value){
    //         return_value = reg_value;
    //     }
    // };
    // action check_stage_6_action(){
    //     check_stage_6.execute(hdr.netsz.value);
    //     //stage_num = stage_num + 1; // stage 개수 증가?
    // }
    // table check_stage_6_table{
    //     actions = {
    //         check_stage_6_action;
    //     }
    //     size = 1;
    //     default_action = check_stage_6_action;
    // }
    
    // RegisterAction<bit<16>, _, bit<16>>(value) check_stage_7 = {
    //     void apply(inout bit<16> reg_value, out bit<16> return_value){
    //         return_value = reg_value;
    //     }
    // };
    // action check_stage_7_action(){
    //     check_stage_7.execute(value);
    //     //stage_num = stage_num + 1; // stage 개수 증가?
    // }
    // table check_stage_7_table{
    //     actions = {
    //         check_stage_7_action;
    //     }
    //     size = 1;
    //     default_action = check_stage_7_action;
    // }

    // RegisterAction<bit<16>, _, bit<16>>(value) check_stage_8 = {
    //     void apply(inout bit<16> reg_value, out bit<16> return_value){
    //         return_value = reg_value;
    //     }
    // };
    // action check_stage_8_action(){
    //     check_stage_8.execute(value);
    //     //stage_num = stage_num + 1; // stage 개수 증가?
    // }
    // table check_stage_8_table{
    //     actions = {
    //         check_stage_8_action;
    //     }
    //     size = 1;
    //     default_action = check_stage_8_action;
    // }

    


    apply {
        /*************** NetSZ Block START *****************************/
        //if(hdr.netmc.isValid()){}
        //else
        check_stage_1_table.apply();
        check_stage_2_table.apply();
        check_stage_3_table.apply();
        check_stage_4_table.apply();
        //check_stage_5_table.apply();
        // check_stage_6_table.apply();
        // check_stage_7_table.apply();
        // check_stage_8_table.apply();
        ipv4_exact.apply(); // 기본 처리
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(hdr); // 원래는 이 코드 하나만 apply 안에 있었음
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser SwitchEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
            
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

control SwitchEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {

    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;