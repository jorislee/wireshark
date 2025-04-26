/* packet-hsl.c
 * Routines for EtherCAT Switch Link disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 #include "config.h"

 #include <epan/packet.h>
 #include <epan/prefs.h>
 #include <epan/tfs.h>
 #include <wsutil/array.h>
 
 void proto_register_hsl(void);
 
 #if 0
 /* XXX: using bitfields is compiler dependent: See README.developer */
 
 typedef union _EslFlagsUnion
 {
     struct
     {
         uint16_t   port7        : 1;
         uint16_t   port6        : 1;
         uint16_t   port5        : 1;
         uint16_t   port4        : 1;
         uint16_t   port3        : 1;
         uint16_t   port2        : 1;
         uint16_t   port1        : 1;
         uint16_t   port0        : 1;
         uint16_t   extended     : 1;
         uint16_t   port11       : 1;
         uint16_t   port10       : 1;
         uint16_t   alignError   : 1;
         uint16_t   crcError     : 1;
         uint16_t   timeStampEna : 1;
         uint16_t   port9        : 1;
         uint16_t   port8        : 1;
     }d;
     struct
     {
         uint8_t    loPorts      : 1;
         uint8_t    flagsHiPorts : 1;
     }lo_hi_flags;
     unsigned   flags;
 } EslFlagsUnion;
 #endif
 
 #define hsl_port7_bitmask        0x0001
 #define hsl_port6_bitmask        0x0002
 #define hsl_port5_bitmask        0x0004
 #define hsl_port4_bitmask        0x0008
 #define hsl_port3_bitmask        0x0010
 #define hsl_port2_bitmask        0x0020
 #define hsl_port1_bitmask        0x0040
 #define hsl_port0_bitmask        0x0080
 #define hsl_extended_bitmask     0x0100
 #define hsl_port11_bitmask       0x0200
 #define hsl_port10_bitmask       0x0400
 #define hsl_alignError_bitmask   0x0800
 #define hsl_crcError_bitmask     0x1000
 #define hsl_timeStampEna_bitmask 0x2000
 #define hsl_port9_bitmask        0x4000
 #define hsl_port8_bitmask        0x8000
 
 #if 0
 typedef struct _EslHeader
 {
     uint8_t        hslCookie[6];           /* 01 01 05 10 00 00 */
     EslFlagsUnion  flags;
     uint64_t       timeStamp;
 } EslHeader, *PEslHeader;
 #endif
 
 
 #define SIZEOF_HSLHEADER 16
 
 static dissector_handle_t eth_withoutfcs_handle;
 
 void proto_reg_handoff_hsl(void);
 
 /* Define the hsl proto */
 int proto_hsl;
 
 static int ett_hsl;
 
 static int hf_hsl_timestamp;
 static int hf_hsl_port;
 static int hf_hsl_crcerror;
 static int hf_hsl_alignerror;
 
 /* Note: using external tfs strings apparently doesn't work in a plugin */
 static const true_false_string flags_yes_no = {
     "yes",
     "no"
 };
 
 #if 0
 /* XXX: using bitfields is compiler dependent: See README.developer */
 static uint16_t flags_to_port(uint16_t flagsValue) {
     EslFlagsUnion flagsUnion;
     flagsUnion.flags = flagsValue;
     if ( flagsUnion.d.port0 )
         return 0;
     else if ( flagsUnion.d.port1 )
         return 1;
     else if ( flagsUnion.d.port2 )
         return 2;
     else if ( flagsUnion.d.port3 )
         return 3;
     else if ( flagsUnion.d.port4 )
         return 4;
     else if ( flagsUnion.d.port5 )
         return 5;
     else if ( flagsUnion.d.port6 )
         return 6;
     else if ( flagsUnion.d.port7 )
         return 7;
     else if ( flagsUnion.d.port8 )
         return 8;
     else if ( flagsUnion.d.port9 )
         return 9;
 
     return -1;
 }
 #endif
 
 static uint16_t flags_to_port(uint16_t flagsValue) {
     if ( (flagsValue & hsl_port0_bitmask) != 0 )
         return 0;
     else if ( (flagsValue & hsl_port1_bitmask) != 0 )
         return 1;
     else if ( (flagsValue & hsl_port2_bitmask) != 0 )
         return 2;
     else if ( (flagsValue & hsl_port3_bitmask) != 0 )
         return 3;
     else if ( (flagsValue & hsl_port4_bitmask) != 0 )
         return 4;
     else if ( (flagsValue & hsl_port5_bitmask) != 0 )
         return 5;
     else if ( (flagsValue & hsl_port6_bitmask) != 0 )
         return 6;
     else if ( (flagsValue & hsl_port7_bitmask) != 0 )
         return 7;
     else if ( (flagsValue & hsl_port8_bitmask) != 0 )
         return 8;
     else if ( (flagsValue & hsl_port9_bitmask) != 0 )
         return 9;
     else if ( (flagsValue & hsl_port10_bitmask) != 0 )
         return 10;
     else if ( (flagsValue & hsl_port11_bitmask) != 0 )
         return 11;
 
     return -1;
 }
 
 /*hsl*/
 static int
 dissect_hsl_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {
 
     proto_item *ti = NULL;
     proto_tree *hsl_header_tree;
     int offset = 0;
 
     unsigned hsl_length = tvb_reported_length(tvb);
     if ( hsl_length >= SIZEOF_HSLHEADER )
     {
         if (tree)
         {
             uint16_t flags;
 
             ti = proto_tree_add_item(tree, proto_hsl, tvb, 0, SIZEOF_HSLHEADER, ENC_NA);
             hsl_header_tree = proto_item_add_subtree(ti, ett_hsl);
             offset+=6;
 
             flags =  tvb_get_letohs(tvb, offset);
             proto_tree_add_uint(hsl_header_tree, hf_hsl_port, tvb, offset, 2, flags_to_port(flags));
 
             proto_tree_add_item(hsl_header_tree, hf_hsl_alignerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);
             proto_tree_add_item(hsl_header_tree, hf_hsl_crcerror, tvb, offset, 2, ENC_LITTLE_ENDIAN);
 
             offset+=2;
 
             proto_tree_add_item(hsl_header_tree, hf_hsl_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN);
         }
     }
     return tvb_captured_length(tvb);
 }
 
 typedef struct _ref_time_frame_info
 {
     frame_data  *fd;
     uint64_t     hsl_ts;
     nstime_t     abs_ts;
     uint32_t     num;
 } ref_time_frame_info;
 
 static ref_time_frame_info ref_time_frame;
 
 static bool is_hsl_header(tvbuff_t *tvb, int offset)
 {
     return tvb_get_uint8(tvb, offset) == 0x01 &&
         tvb_get_uint8(tvb, offset+1) == 0x01 &&
         tvb_get_uint8(tvb, offset+2) == 0x05 &&
         (tvb_get_uint8(tvb, offset+3) == 0x10 ||tvb_get_uint8(tvb, offset+3) == 0x11)&&
         tvb_get_uint8(tvb, offset+4) == 0x00 &&
         tvb_get_uint8(tvb, offset+5) == 0x00;
 }
 
 static void modify_times(tvbuff_t *tvb, int offset, packet_info *pinfo)
 {
     if ( ref_time_frame.fd == NULL )
     {
         ref_time_frame.hsl_ts = tvb_get_letoh64(tvb, offset+8);
         ref_time_frame.fd = pinfo->fd;
         ref_time_frame.num = pinfo->num;
         ref_time_frame.abs_ts = pinfo->abs_ts;
     }
     else if ( !pinfo->fd->visited )
     {
         uint64_t nsecs = tvb_get_letoh64(tvb, offset+8) - ref_time_frame.hsl_ts;
         uint64_t secs = nsecs/1000000000;
         nstime_t ts;
         nstime_t ts_delta;
 
         ts.nsecs = ref_time_frame.abs_ts.nsecs + (int)(nsecs-(secs*1000000000));
         if ( ts.nsecs > 1000000000 )
         {
             ts.nsecs-=1000000000;
             secs++;
         }
 
         ts.secs = ref_time_frame.abs_ts.secs+(int)secs;
         nstime_delta(&ts_delta, &ts, &pinfo->abs_ts);
 
         pinfo->abs_ts = ts;
         pinfo->fd->abs_ts = ts;
         nstime_add(&pinfo->rel_ts, &ts_delta);
     }
 }
 
 static bool
 dissect_hsl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
 {
     static bool      in_heur    = false;
     bool             result;
     tvbuff_t        *next_tvb;
     unsigned         hsl_length = tvb_captured_length(tvb);
 
     if ( in_heur )
         return false;
 
     in_heur = true;
     /*TRY */
     {
         if ( ref_time_frame.fd != NULL && !pinfo->fd->visited && pinfo->num <= ref_time_frame.num )
             ref_time_frame.fd = NULL;
 
         /* Check that there's enough data */
         if ( hsl_length < SIZEOF_HSLHEADER )
             return false;
 
         /* check for Esl frame, this has a unique destination MAC from Beckhoff range
            First 6 bytes must be: 01 01 05 10 00 00 */
         if ( is_hsl_header(tvb, 0) )
         {
             dissect_hsl_header(tvb, pinfo, tree, data);
             if ( eth_withoutfcs_handle != NULL )
             {
                 next_tvb = tvb_new_subset_remaining(tvb, SIZEOF_HSLHEADER);
                 call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
             }
             modify_times(tvb, 0, pinfo);
             result = true;
         }
         else if ( is_hsl_header(tvb, hsl_length-SIZEOF_HSLHEADER) )
         {
             if ( eth_withoutfcs_handle != NULL )
             {
                 next_tvb = tvb_new_subset_length(tvb, 0, hsl_length-SIZEOF_HSLHEADER);
                 call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
             }
             next_tvb = tvb_new_subset_length(tvb, hsl_length-SIZEOF_HSLHEADER, SIZEOF_HSLHEADER);
             dissect_hsl_header(next_tvb, pinfo, tree, data);
             modify_times(tvb, hsl_length-SIZEOF_HSLHEADER, pinfo);
 
             result = true;
         }
         else
         {
             result = false;
         }
     }
     /*CATCH_ALL{
       in_heur = false;
       RETHROW;
       }ENDTRY;*/
     in_heur = false;
     return result;
 }
 
 void
 proto_register_hsl(void) {
     static hf_register_info hf[] = {
         { &hf_hsl_port,
           { "Port", "hsl.port",
             FT_UINT16, BASE_DEC, NULL, 0x00,
             NULL, HFILL }
         },
         { &hf_hsl_crcerror,
           { "Crc Error", "hsl.crcerror",
             FT_BOOLEAN, 16, TFS(&flags_yes_no), hsl_crcError_bitmask,
             NULL, HFILL }
         },
         { &hf_hsl_alignerror,
           { "Alignment Error", "hsl.alignerror",
             FT_BOOLEAN, 16, TFS(&flags_yes_no), hsl_alignError_bitmask,
             NULL, HFILL }
         },
         { &hf_hsl_timestamp,
           { "timestamp", "hsl.timestamp",
             FT_UINT64, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },
     };
 
     static int *ett[] = {
         &ett_hsl,
     };
 
     module_t *hsl_module;
 
     proto_hsl = proto_register_protocol("EtherCAT Switch Link",
                                         "HSL","hsl");
 
     hsl_module = prefs_register_protocol_obsolete(proto_hsl);
 
     prefs_register_obsolete_preference(hsl_module, "enable");
 
     proto_register_field_array(proto_hsl,hf,array_length(hf));
     proto_register_subtree_array(ett,array_length(ett));
 
     register_dissector("hsl", dissect_hsl_header, proto_hsl);
 }
 
 void
 proto_reg_handoff_hsl(void) {
     static bool initialized = false;
 
     if (!initialized) {
         eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_hsl);
         heur_dissector_add("eth", dissect_hsl_heur, "EtherCAT over Ethernet", "hsl_eth", proto_hsl, HEURISTIC_DISABLE);
         initialized = true;
     }
 }
 
 /*
  * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
  *
  * Local variables:
  * c-basic-offset: 4
  * tab-width: 8
  * indent-tabs-mode: nil
  * End:
  *
  * vi: set shiftwidth=4 tabstop=8 expandtab:
  * :indentSize=4:tabSize=8:noTabs=true:
  */
