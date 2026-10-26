/*
 * packet-slsdet.c - Wireshark binary plugin for SLS detector UDP packets
 * (slsDetectorPackage "sls_detector_header", 48 bytes, little-endian)
 *
 * Builds against Wireshark 2.6, 3.6 and 4.6 (Linux, Windows, macOS).
 * For 3.x/4.x a ws_version.h must be on the include path.
 *
 *  off  type      field
 *   0   uint64    frameNumber
 *   8   uint32    expLength
 *  12   uint32    packetNumber
 *  16   uint64    detSpec1
 *  24   uint64    timestamp
 *  32   uint16    modId
 *  34   uint16    row
 *  36   uint16    column
 *  38   uint16    detSpec2
 *  40   uint32    detSpec3
 *  44   uint16    detSpec4
 *  46   uint8     detType
 *  47   uint8     version
 */

#ifndef HAVE_PLUGINS
#  define HAVE_PLUGINS   /* 2.6 hides proto_plugin behind this */
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

/* ws_version.h exists from 3.0 on (generated; CI provides it) */
#if defined(__has_include)
#  if __has_include(<ws_version.h>)
#    include <ws_version.h>
#  endif
#endif

#if defined(WIRESHARK_VERSION_MAJOR)
#  define SLS_WS_VER (WIRESHARK_VERSION_MAJOR * 100 + WIRESHARK_VERSION_MINOR)
#else
#  define SLS_WS_VER 206
#endif

/* 4.4+ uses C99 bool for callbacks and bool preferences */
#if SLS_WS_VER >= 403
#  include <stdbool.h>
typedef bool sls_bool;
#  define SLS_TRUE  true
#  define SLS_FALSE false
#else
typedef gboolean sls_bool;
#  define SLS_TRUE  TRUE
#  define SLS_FALSE FALSE
#endif

#if SLS_WS_VER >= 403
#  define sls_get_u8(tvb, off) tvb_get_uint8(tvb, off)
#else
#  define sls_get_u8(tvb, off) tvb_get_guint8(tvb, off)
#endif

#ifndef PROTO_ITEM_SET_GENERATED
#  define PROTO_ITEM_SET_GENERATED(pi) proto_item_set_generated(pi)
#endif

/* Symbols exported by the plugin itself */
#if defined(_WIN32)
#  define SLS_EXPORT __declspec(dllexport)
#else
#  define SLS_EXPORT __attribute__((visibility("default")))
#endif

#ifndef SLS_PLUGIN_VERSION
#  define SLS_PLUGIN_VERSION "1.0.0"   /* CI passes the release tag */
#endif
#define SLS_HDR_LEN        48
#define SLS_DEFAULT_PORTS  "32410-32420"   /* UDP source ports, inclusive */
#define SLS_MATTERHORN_PLEN 8192           /* MATTERHORN payload bytes per packet */

static int proto_sls = -1;

static int hf_sls_frame      = -1;
static int hf_sls_explength  = -1;
static int hf_sls_packet     = -1;
static int hf_sls_detspec1   = -1;
static int hf_sls_timestamp  = -1;
static int hf_sls_modid      = -1;
static int hf_sls_row        = -1;
static int hf_sls_column     = -1;
static int hf_sls_detspec2   = -1;
static int hf_sls_detspec3   = -1;
static int hf_sls_detspec4   = -1;
static int hf_sls_dettype    = -1;
static int hf_sls_version    = -1;
static int hf_sls_payload    = -1;
static int hf_sls_plen       = -1;
static int hf_sls_bitdepth   = -1;
static int hf_sls_npix       = -1;
static int hf_sls_ncounters  = -1;

static gint ett_sls         = -1;
static gint ett_sls_header  = -1;
static gint ett_sls_payload = -1;

/* Preferences */
static gint     pref_eiger_bits  = 16;
static gint     pref_mythen_bits = 32;
static gint     pref_mh_bits     = 16;
static gint     pref_mh_counters = 1;
static range_t *pref_src_ports   = NULL;

static dissector_handle_t sls_handle;

static const value_string sls_det_types[] = {
    { 0, "GENERIC" },
    { 1, "EIGER" },
    { 2, "GOTTHARD" },
    { 3, "JUNGFRAU" },
    { 4, "CHIPTESTBOARD" },
    { 5, "MOENCH" },
    { 6, "MYTHEN3" },
    { 7, "GOTTHARD2" },
    { 8, "XILINX_CHIPTESTBOARD" },
    { 9, "MATTERHORN" },
    { 0, NULL }
};
#define SLS_DET_TYPE_MAX 9

/* Dynamic ranges allowed by slsDetectorPackage (Detector::getDynamicRangeList) */
static const enum_val_t sls_eiger_bits[] = {
    { "4",  "4 bit",  4 },
    { "8",  "8 bit",  8 },
    { "12", "12 bit", 12 },
    { "16", "16 bit", 16 },
    { "32", "32 bit", 32 },
    { NULL, NULL, 0 }
};

static const enum_val_t sls_mythen_bits[] = {
    { "8",  "8 bit",  8 },
    { "16", "16 bit", 16 },
    { "32", "32 bit", 32 },
    { NULL, NULL, 0 }
};

static const enum_val_t sls_mh_bits[] = {
    { "4",  "4 bit",  4 },
    { "8",  "8 bit",  8 },
    { "16", "16 bit", 16 },
    { NULL, NULL, 0 }
};

static const enum_val_t sls_mh_counters[] = {
    { "1", "1 counter",  1 },
    { "2", "2 counters", 2 },
    { "3", "3 counters", 3 },
    { "4", "4 counters", 4 },
    { NULL, NULL, 0 }
};

static const char *
sls_det_type_name(guint8 t)
{
    guint i;
    for (i = 0; sls_det_types[i].strptr != NULL; i++)
        if (sls_det_types[i].value == t)
            return sls_det_types[i].strptr;
    return "UNKNOWN";
}

/* Bits per pixel in the payload, 0 if the payload is not a pixel array
 * (GENERIC, and the chip test boards whose payload mixes analog, digital
 * and transceiver samples). Sizes follow slsReceiverSoftware GeneralData.h. */
static guint
sls_bits_per_pixel(guint8 t)
{
    switch (t) {
    case 1:  return (guint)pref_eiger_bits;   /* EIGER: configurable */
    case 2:                                   /* GOTTHARD */
    case 3:                                   /* JUNGFRAU */
    case 5:                                   /* MOENCH */
    case 7:  return 16;                       /* GOTTHARD2 */
    case 6:  return (guint)pref_mythen_bits;  /* MYTHEN3: configurable */
    case 9:  return (guint)pref_mh_bits;      /* MATTERHORN: configurable */
    default: return 0;
    }
}

/* Counters per pixel: MATTERHORN has 1-4 configurable, all others 1 */
static guint
sls_counters_per_pixel(guint8 t)
{
    return t == 9 ? (guint)pref_mh_counters : 1;
}

static int
dissect_sls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint       len = tvb_captured_length(tvb);
    proto_item *ti, *pi;
    proto_tree *sls_tree, *hdr_tree, *pl_tree;
    guint64     frame;
    guint8      dettype;

    if (len < SLS_HDR_LEN)
        return 0;

    frame   = tvb_get_letoh64(tvb, 0);
    dettype = sls_get_u8(tvb, 46);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLSDET");
    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "%s  frame=%" G_GUINT64_FORMAT "  pkt=%u  mod=%u  row=%u  col=%u",
                 sls_det_type_name(dettype),
                 frame,
                 tvb_get_letohl(tvb, 12),
                 tvb_get_letohs(tvb, 32),
                 tvb_get_letohs(tvb, 34),
                 tvb_get_letohs(tvb, 36));

    if (!tree)
        return tvb_captured_length(tvb);

    ti = proto_tree_add_item(tree, proto_sls, tvb, 0, -1, ENC_NA);
    sls_tree = proto_item_add_subtree(ti, ett_sls);

    hdr_tree = proto_tree_add_subtree(sls_tree, tvb, 0, SLS_HDR_LEN,
                                      ett_sls_header, NULL, "Header (48 bytes)");

    proto_tree_add_item(hdr_tree, hf_sls_frame,     tvb,  0, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_explength, tvb,  8, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_packet,    tvb, 12, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_detspec1,  tvb, 16, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_timestamp, tvb, 24, 8, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_modid,    tvb, 32, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_row,      tvb, 34, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_column,   tvb, 36, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_detspec2, tvb, 38, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_detspec3, tvb, 40, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_detspec4, tvb, 44, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_dettype,  tvb, 46, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_sls_version,  tvb, 47, 1, ENC_LITTLE_ENDIAN);

    if (len > SLS_HDR_LEN) {
        guint plen = len - SLS_HDR_LEN;
        guint bits = sls_bits_per_pixel(dettype);
        guint ncnt = sls_counters_per_pixel(dettype);

        pi = proto_tree_add_item(sls_tree, hf_sls_payload, tvb, SLS_HDR_LEN, plen, ENC_NA);
        pl_tree = proto_item_add_subtree(pi, ett_sls_payload);

        pi = proto_tree_add_uint(pl_tree, hf_sls_plen, tvb, SLS_HDR_LEN, plen, plen);
        PROTO_ITEM_SET_GENERATED(pi);
        if (dettype == 9 && plen != SLS_MATTERHORN_PLEN)
            proto_item_append_text(pi, " (expected %u)", SLS_MATTERHORN_PLEN);

        if (bits > 0) {
            pi = proto_tree_add_uint(pl_tree, hf_sls_bitdepth, tvb, SLS_HDR_LEN, plen, bits);
            PROTO_ITEM_SET_GENERATED(pi);
            if (dettype == 9) {
                pi = proto_tree_add_uint(pl_tree, hf_sls_ncounters, tvb, SLS_HDR_LEN, plen, ncnt);
                PROTO_ITEM_SET_GENERATED(pi);
            }
            pi = proto_tree_add_uint(pl_tree, hf_sls_npix, tvb, SLS_HDR_LEN, plen,
                                     (guint)(((guint64)plen * 8) / (bits * ncnt)));
            PROTO_ITEM_SET_GENERATED(pi);
        }
    }

    return tvb_captured_length(tvb);
}

/* Port table entry: only accept packets sent from one of the SLS source ports */
static int
dissect_sls_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!value_is_in_range(pref_src_ports, pinfo->srcport))
        return 0;
    return dissect_sls(tvb, pinfo, tree, data);
}

/* Optional heuristic: enable via Analyze > Enabled Protocols > "slsdet_udp" */
static sls_bool
dissect_sls_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint len = tvb_captured_length(tvb);

    if (len < SLS_HDR_LEN || ((len - SLS_HDR_LEN) % 2) != 0)
        return SLS_FALSE;
    if (sls_get_u8(tvb, 47) != 2)
        return SLS_FALSE;
    if (sls_get_u8(tvb, 46) > SLS_DET_TYPE_MAX)
        return SLS_FALSE;

    dissect_sls(tvb, pinfo, tree, data);
    return SLS_TRUE;
}

/* (Re)register the source port range on the UDP port table */
static void
sls_apply_prefs(void)
{
    dissector_delete_all("udp.port", sls_handle);
    dissector_add_uint_range("udp.port", pref_src_ports, sls_handle);
}

void
proto_register_sls(void)
{
    module_t *sls_module;

    static hf_register_info hf[] = {
        { &hf_sls_frame,     { "Frame Number",   "slsdet.frame",       FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_explength, { "Exp Length",     "slsdet.explength",   FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_packet,    { "Packet Number",  "slsdet.packet",      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_detspec1,  { "DetSpec1",       "slsdet.detspec1",    FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_sls_timestamp, { "Timestamp",      "slsdet.timestamp",   FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_modid,     { "Module ID",      "slsdet.modid",       FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_row,       { "Row",            "slsdet.row",         FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_column,    { "Column",         "slsdet.column",      FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_detspec2,  { "DetSpec2",       "slsdet.detspec2",    FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_sls_detspec3,  { "DetSpec3",       "slsdet.detspec3",    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_sls_detspec4,  { "DetSpec4",       "slsdet.detspec4",    FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_sls_dettype,   { "Detector Type",  "slsdet.dettype",     FT_UINT8,  BASE_DEC, VALS(sls_det_types), 0, NULL, HFILL } },
        { &hf_sls_version,   { "Header Version", "slsdet.version",     FT_UINT8,  BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_payload,   { "Payload",        "slsdet.payload",     FT_BYTES,  BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_sls_plen,      { "Payload Size",   "slsdet.payload_len", FT_UINT32, BASE_DEC, NULL, 0, "Payload size in bytes", HFILL } },
        { &hf_sls_bitdepth,  { "Bits per Pixel", "slsdet.bitdepth",    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_npix,      { "Pixel Count",    "slsdet.pixels",      FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_sls_ncounters, { "Counters per Pixel", "slsdet.counters", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_sls,
        &ett_sls_header,
        &ett_sls_payload,
    };

    proto_sls = proto_register_protocol("SLS Detector", "SLSDET", "slsdet");
    proto_register_field_array(proto_sls, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    sls_handle = create_dissector_handle(dissect_sls_udp, proto_sls);

    sls_module = prefs_register_protocol(proto_sls, sls_apply_prefs);
    range_convert_str(wmem_epan_scope(), &pref_src_ports, SLS_DEFAULT_PORTS, 65535);
    prefs_register_range_preference(sls_module, "src_ports", "UDP source port(s)",
        "Packets sent from these UDP source ports are decoded as SLS", &pref_src_ports, 65535);
    prefs_register_enum_preference(sls_module, "eiger_bits", "EIGER dynamic range",
        "Bits per pixel of EIGER payloads (set by the detector's dynamic range)",
        &pref_eiger_bits, sls_eiger_bits, SLS_FALSE);
    prefs_register_enum_preference(sls_module, "mythen3_bits", "MYTHEN3 dynamic range",
        "Bits per pixel of MYTHEN3 payloads (set by the detector's dynamic range)",
        &pref_mythen_bits, sls_mythen_bits, SLS_FALSE);
    prefs_register_enum_preference(sls_module, "matterhorn_bits", "MATTERHORN counter depth",
        "Bits per counter of MATTERHORN payloads",
        &pref_mh_bits, sls_mh_bits, SLS_FALSE);
    prefs_register_enum_preference(sls_module, "matterhorn_counters", "MATTERHORN counters",
        "Number of enabled counters per MATTERHORN pixel",
        &pref_mh_counters, sls_mh_counters, SLS_FALSE);
    prefs_register_obsolete_preference(sls_module, "clock_mhz");
    prefs_register_obsolete_preference(sls_module, "stats");
    prefs_register_obsolete_preference(sls_module, "show_pixels");
    prefs_register_obsolete_preference(sls_module, "max_pixels");
}

void
proto_reg_handoff_sls(void)
{
    sls_apply_prefs();
    heur_dissector_add("udp", dissect_sls_heur, "SLS Detector over UDP (any port)",
                       "slsdet_udp", proto_sls, HEURISTIC_DISABLE);
}

/* ---------------------------------------------------------------------
 * Plugin entry points
 * ------------------------------------------------------------------- */
SLS_EXPORT const char plugin_version[] = SLS_PLUGIN_VERSION;

#if SLS_WS_VER >= 300
/* Wireshark 3.x / 4.x */
SLS_EXPORT const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
SLS_EXPORT const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
#else
/* Wireshark 2.6: must match VERSION_RELEASE of the running Wireshark */
SLS_EXPORT const char plugin_release[] = "2.6";
#endif

SLS_EXPORT void plugin_register(void);

void
plugin_register(void)
{
    static proto_plugin plug_sls;

    plug_sls.register_protoinfo = proto_register_sls;
    plug_sls.register_handoff   = proto_reg_handoff_sls;
    proto_register_plugin(&plug_sls);
}
