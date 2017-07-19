/*
 * Copyright 2009 `date +paul@ant%m%y.sbrk.co.uk`
 * Released under GPLv3
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>
#include <epan/conversation.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include <epan/reassemble.h>

#include "packet-ant.h"

#define ANTITEM(TREE, SYNC, LEN) {if (tree) proto_tree_add_item(TREE, SYNC, tvb, offset, LEN, TRUE); offset += LEN;}
#define NANTITEM(TREE, SYNC, LEN) {if (tree) proto_tree_add_item(TREE, SYNC, tvb, offset, LEN, TRUE);}

void proto_reg_handoff_ant(void);

/* per conversation details */
struct ant_info {
	guint8 first[MAXCHAN];		/* whether the lastXX fields are valid */
	guint16 devtype[MAXCHAN];	/* device type */
	struct {
		struct {
			guint16 rr[MAXCHAN];	/* last r-r for HR records */
			guint8 seq[MAXCHAN];	/* last sequence# for HR records */
		} hr;
		struct {
			guint8 r1[MAXCHAN];		/* last R1 for power */
			guint8 r2[MAXCHAN];		/* last R2 for power */
			guint8 n[MAXCHAN];		/* last N for power */
			guint16 p[MAXCHAN];		/* last P for power */
			guint16 t[MAXCHAN];		/* last T for power */
		} power;
		struct {
			guint16 cranktime[MAXCHAN];
			guint16 crankrev[MAXCHAN];
			guint16 wheeltime[MAXCHAN];
			guint16 wheelrev[MAXCHAN];
		} bike;
		struct {
			guint16 time[MAXCHAN];
			guint16 dist[MAXCHAN];
			guint16 speed[MAXCHAN];
			guint8 stridecnt[MAXCHAN];
			guint8 updlatency[MAXCHAN];
			guint8 cad[MAXCHAN];
			guint16 spdp1[MAXCHAN];
		} foot;
		struct {
			guint16 seq[MAXCHAN];
			guint8 burst_seq[MAXCHAN];
			guint8 seq_id[MAXCHAN];
			guint8 islast[MAXCHAN];
		} burst;
	} last;
};

/* per packet data. */
struct pkt_data {
	guint8 first;
	guint8 devtype;
	struct {
		struct {
			guint16 rr;
			guint8 seq;
		} hr;
		struct {
			guint8 r1;
			guint8 r2;
			guint8 n;
			guint16 p;
			guint16 t;
		} power;
		struct {
			guint16 cranktime;
			guint16 crankrev;
			guint16 wheeltime;
			guint16 wheelrev;
		} bike;
		struct {
			guint16 time;
			guint16 dist;
			guint16 speed;
			guint8 stridecnt;
			guint8 updlatency;
			guint8 cad;
			guint16 spdp1;
		} foot;
	} last;
	struct {
		struct {
			guint16 seq;
			guint8 burst_seq;
			guint8 seq_id;
			guint8 islast;
		} burst;
	} meta;
};

static reassembly_table ip_reassembly_table;

static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
    &hf_msg_reassembled_length,
	/* Reassembled data field */
    NULL,
	/* Tag */
	"Message fragments"
};

static int proto_ant = -1;

static int hf_ant_sync = -1;
static int hf_ant_msg_length = -1;
static int hf_ant_msg_id = -1;
static int hf_ant_data = -1;
static int hf_ant_checksum = -1;
static int hf_ant_data_chan = -1;
static int hf_ant_data_chanstat = -1;
static int hf_ant_data_period = -1;
static int hf_ant_data_devno = -1;
static int hf_ant_data_devtype = -1;
static int hf_ant_data_transtype = -1;
static int hf_ant_data_waveform = -1;
static int hf_ant_data_data = -1;
static int hf_ant_data_mbz = -1;
static int hf_ant_data_nk = -1;
static int hf_ant_data_msgid = -1;
static int hf_ant_data_msgcode = -1;
static int hf_ant_data_chtype = -1;
static int hf_ant_data_net = -1;
static int hf_ant_pd_page = -1;
static int hf_ant_pd_rr = -1;
static int hf_ant_pd_oldrr = -1;
static int hf_ant_pd_newrr = -1;
static int hf_ant_pd_prevrr = -1;
static int hf_ant_pd_seq = -1;
static int hf_ant_pd_hr = -1;
static int hf_ant_data_maxchan = -1;
static int hf_ant_data_maxnet = -1;
static int hf_ant_data_srchto = -1;
static int hf_ant_data_freq = -1;

static int hf_ant_bm_no_rx_chans = -1;
static int hf_ant_bm_no_tx_chans = -1;
static int hf_ant_bm_no_rx_msgs = -1;
static int hf_ant_bm_no_tx_msgs = -1;
static int hf_ant_bm_no_ackd_msgs = -1;
static int hf_ant_bm_no_burst_msgs = -1;
static int hf_ant_bm_net = -1;
static int hf_ant_bm_serial = -1;
static int hf_ant_bm_per_chan_tx_power = -1;
static int hf_ant_bm_low_prio_srch = -1;
static int hf_ant_bm_script = -1;
static int hf_ant_bm_search_list = -1;
static int hf_ant_bm_led = -1;
static int hf_ant_bm_ext_msg = -1;
static int hf_ant_bm_scan_mode = -1;
static int hf_ant_bm_prox_srch = -1;
static int hf_ant_bm_ext_assign = -1;

static int hf_ant_bm_burst_seq_end = -1;
static int hf_ant_bm_burst_seq = -1;
static int hf_ant_bm_burst_chan = -1;

static int hf_ant_unk = -1;
static int hf_ant_ub = -1;
static int hf_ant_u0 = -1;
static int hf_ant_u1 = -1;
static int hf_ant_u2 = -1;
static int hf_ant_hwver = -1;
static int hf_ant_manu = -1;
static int hf_ant_model = -1;
static int hf_ant_swver = -1;
static int hf_ant_serial = -1;

static int hf_ant_torque_cfg = -1;
static int hf_ant_torque_raw = -1;
static int hf_ant_torque_offset = -1;

static int hf_ant_batt = -1;

static int hf_ant_r1 = -1;
static int hf_ant_r2 = -1;
static int hf_ant_n = -1;
static int hf_ant_p = -1;
static int hf_ant_t = -1;

static int hf_ant_cranktime = -1;
static int hf_ant_crankrev = -1;
static int hf_ant_wheeltime = -1;
static int hf_ant_wheelrev = -1;

static int hf_ant_cadx = -1;

static int hf_ant_time_frac = -1;
static int hf_ant_time_int = -1;
static int hf_ant_dist_int = -1;
static int hf_ant_dist_frac = -1;
static int hf_ant_spd_int = -1;
static int hf_ant_spd_frac = -1;
static int hf_ant_stride_count = -1;
static int hf_ant_update_latency = -1;

static int hf_ant_pref1f0 = -1;
static int hf_ant_pref1f1 = -1;
static int hf_ant_pref1f2 = -1;
static int hf_ant_pref1f3 = -1;
static int hf_ant_pref1f4 = -1;
static int hf_ant_pref1f5 = -1;
static int hf_ant_pref1f6 = -1;
static int hf_ant_pref1f7 = -1;
static int hf_ant_pref2f0 = -1;
static int hf_ant_pref2f1 = -1;
static int hf_ant_pref2f2 = -1;
static int hf_ant_pref2f3 = -1;
static int hf_ant_pref2f4 = -1;
static int hf_ant_pref2f5 = -1;
static int hf_ant_pref2f6 = -1;
static int hf_ant_pref2f7 = -1;

static int hf_ant_43_b1f0 = -1;
static int hf_ant_43_b1f1 = -1;
static int hf_ant_43_b1f2 = -1;
static int hf_ant_43_b1f3 = -1;
static int hf_ant_43_b1f4 = -1;
static int hf_ant_43_b1f5 = -1;
static int hf_ant_43_b1f6 = -1;
static int hf_ant_43_b1f7 = -1;
static int hf_ant_phase = -1;
static int hf_ant_b2 = -1;
static int hf_ant_b3 = -1;
static int hf_ant_product_id = -1;
static int hf_ant_b4 = -1;
static int hf_ant_b5 = -1;
static int hf_ant_b6 = -1;
static int hf_ant_b7 = -1;

static int hf_ant_cmd = -1;
static int hf_ant_pcid = -1;
static int hf_ant_fpodid = -1;
static int hf_ant_bpodid = -1;
static int hf_ant_hrmid = -1;
static int hf_ant_unitid = -1;
static int hf_ant_unitname = -1;
static int hf_ant_firmware = -1;
static int hf_ant_auth = -1;
static int hf_ant_autolap = -1;

static int hf_ant_run_lo = -1;
static int hf_ant_run_hi = -1;
static int hf_ant_hrm_lo = -1;
static int hf_ant_hrm_hi = -1;
static int hf_ant_weight = -1;
static int hf_ant_pref_cksum = -1;
static int hf_ant_xid = -1;
static int hf_ant_x0 = -1;
static int hf_ant_x1 = -1;
static int hf_ant_x2 = -1;
static int hf_ant_x3 = -1;
static int hf_ant_run_id = -1;
static int hf_ant_run_prev = -1;
static int hf_ant_run_time = -1;
static int hf_ant_run_date = -1;

static int hf_ant_lap_next = -1;
static int hf_ant_lap_type = -1;
static int hf_ant_lap_speed = -1;
static int hf_ant_lap_dist = -1;
static int hf_ant_lap_time = -1;
static int hf_ant_lap_cals = -1;
static int hf_ant_lap_avghr = -1;
static int hf_ant_lap_maxhr = -1;
static int hf_ant_lap_avgcad = -1;
static int hf_ant_lap_maxcad = -1;
static int hf_ant_lap_steps = -1;
static int hf_ant_speed_dist = -1;
static int hf_ant_cad = -1;
static int hf_ant_hr = -1;
static int hf_ant_auth_len = -1;


/* TODO tfs_enabled_disabled in tfs.h */
static const true_false_string tfs_enabled = {
	"Enabled",
	"Disabled"
};

static const value_string product_ids[] = {
	{1, "HRM1"},
	{2, "AXH01"},
	{3, "AXB01"},
	{4, "AXB02"},
	{5, "HRM2SS"},
	{717, "FR405"},
	{782, "FR50"},
	{988, "FR60"},
	{1018, "FR310XT"},
	{1036, "EDGE500"},
	{10007, "SDM4"},
	{20119, "TRAINING_CENTER"},
	{65534, "CONNECT"},
	{0, NULL}
};
	
static const value_string chtypes[] = {
	{0x00, "Bidirectional Slave"},
	{0x10, "Bidirectional Master" },
	{0x20, "Shared Bidrectional Slave" },
	{0x30, "Shared Bidirectional Master" },
	{0x40, "RX Only" },
	{0x50, "TX Only" },
	{0, NULL}
};

static const value_string devtypes[] = {
	{DEVTYPE_ANTFS, "ANTFS"},
	{DEVTYPE_SUUHRM, "Suunto HRM"},
	{DEVTYPE_HRM, "HRM"},
	{DEVTYPE_BIKE_POWER, "Bike power" },
	{DEVTYPE_SDM, "SDM" },
	{DEVTYPE_BIKE_SPEED_CADENCE, "Bike speed cadence"},
	{DEVTYPE_ENVIRONMENT_SENSOR, "Environment sensor"},
	{DEVTYPE_FITNESS_EQUIPMENT, "Fitness equipment"},
	{DEVTYPE_WEIGHT_SCALE, "Weight scale"},
	{DEVTYPE_BIKE_CADENCE, "Bike cadence"},
	{DEVTYPE_BIKE_SPEED, "Bike speed"},
	{0, NULL}
};

static const value_string cmds44[] = {
	{2, "Switch frequency"},
	{3, "Authenticate"},
	{4, "Request ID"},
	{0, NULL}
};

static const value_string chanstats[] = {
	{0, "Unassigned"},
	{1, "Assigned" },
	{2, "Searching" },
	{3, "Tracking" },
	{0, NULL}
};

static const value_string codes[] = {
	{0x0, "No error"},
	{0x1, "Search Timeout" },
	{0x2, "RX Fail" },
	{0x3, "TX" },
	{0x4, "Transfer RX Failed" },
	{0x5, "Transfer TX Completed" },
	{0x6, "Transfer TX Failed" },
	{0x7, "Channel Closed" },
	{0x8, "RX Fail Go To Search" },
	{0x9, "Channel Collision" },
	{0xa, "Transfer TX Start" },
	{0x28, "Invalid message"},
	{0, NULL}
};

#if 0
static const value_string periods[] = {
	{4096, "Garmin head unit"},
	{6554, "Suunto"},
	{8070, "ANT+ HRM"},
	{0, NULL}
};
#endif

static const value_string msgs[] = {
	{0x1, "Channel event"},
	{0x3d, "Suunto config"},
	{MESG_RESPONSE_EVENT_ID, "Response event"},
	{MESG_UNASSIGN_CHANNEL_ID, "Unassign channel" },
	{MESG_ASSIGN_CHANNEL_ID, "Assign channel" },
	{MESG_CHANNEL_MESG_PERIOD_ID, "Message period" },
	{MESG_CHANNEL_SEARCH_TIMEOUT_ID, "Search timeout" },
	{MESG_CHANNEL_RADIO_FREQ_ID, "Radio frequency" },
	{MESG_NETWORK_KEY_ID, "Network key" },
	{MESG_SEARCH_WAVEFORM_ID, "Search waveform" },
	{MESG_SYSTEM_RESET_ID, "System reset" },
	{MESG_OPEN_CHANNEL_ID, "Open channel" },
	{MESG_CLOSE_CHANNEL_ID, "Close channel" },
	{MESG_REQUEST_ID, "Request" },
	{MESG_BROADCAST_DATA_ID, "Broadcast data" },
	{MESG_ACKNOWLEDGED_DATA_ID, "Acknowledged data" },
	{MESG_BURST_DATA_ID, "Burst data" },
	{MESG_CHANNEL_ID_ID, "Channel ID" },
	{MESG_CHANNEL_STATUS_ID, "Channel status" },
	{MESG_CAPABILITIES_ID, "Capabilities" },
	{MESG_EXT_BROADCAST_DATA_ID, "Extended Broadcast data" },
	{MESG_EXT_ACKNOWLEDGED_DATA_ID, "Extended Acknowledged data" },
	{MESG_EXT_BURST_DATA_ID, "Extended Burst data" },
	{0, NULL}
};

#if 0
static const value_string netkeys[] = {
	{0xb9ad3228757ec74dULL, "Suunto"},
	{0xa8a423b9f55e63c1ULL, "Garmin head unit"},
	{0xb9a521fbbd72c345ULL, "ANT+"},
	{0, NULL}
};
#endif

static gint ett_ant = -1;
static gint ett_ant_data = -1;

static void
msg_init_protocol(void)
{
	fprintf(stderr, "msginit\n");
	reassembly_table_init(&ip_reassembly_table, 
	                      &addresses_reassembly_table_functions);
}


/* get per conversation channel data */
static struct ant_info *
get_ant_infop(packet_info *pinfo)
{
	conversation_t *conversation;
	struct ant_info *ant_infop;
	int i;

	if (!(conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0))) {
			conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport,pinfo->destport, 0);
	}
	ant_infop = (struct ant_info *) conversation_get_proto_data(conversation, proto_ant);
	if (!ant_infop) {
		ant_infop = (struct ant_info *) wmem_alloc0(wmem_epan_scope(), (sizeof(struct ant_info)));
		for (i = 0; i < MAXCHAN; i++) {
			ant_infop->first[i] = 1;
		}
		conversation_add_proto_data(conversation, proto_ant, ant_infop);
	}
	return ant_infop;
}

/* initialise per packet data from per conv data */
static struct pkt_data *
new_pdata(struct ant_info *ant_infop, guint8 chan)
{
	struct pkt_data *p_data;

	p_data = (struct pkt_data *) wmem_alloc0(wmem_epan_scope(), (sizeof(struct pkt_data)));
	p_data->first = ant_infop->first[chan];
	p_data->devtype = ant_infop->devtype[chan];
	/* copy should depend on devtype, but should get away with it */
	p_data->last.hr.rr = ant_infop->last.hr.rr[chan];
	p_data->last.hr.seq = ant_infop->last.hr.seq[chan];
	p_data->last.power.r1 = ant_infop->last.power.r1[chan];
	p_data->last.power.r2 = ant_infop->last.power.r2[chan];
	p_data->last.power.n = ant_infop->last.power.n[chan];
	p_data->last.power.p = ant_infop->last.power.p[chan];
	p_data->last.power.t = ant_infop->last.power.t[chan];
	p_data->last.power.t = ant_infop->last.power.t[chan];
	p_data->last.bike.cranktime = ant_infop->last.bike.cranktime[chan];
	p_data->last.bike.crankrev = ant_infop->last.bike.crankrev[chan];
	p_data->last.bike.wheeltime = ant_infop->last.bike.wheeltime[chan];
	p_data->last.bike.wheelrev = ant_infop->last.bike.wheelrev[chan];

	return p_data;
}

static int
dissect_burst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct pkt_data *p_data;
	int offset;
	guint8 phase;
	guint8 page;
	guint8 flag;
	int i, j;
	int val;

	if (tree) {
		p_data = (struct pkt_data *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ant, 0);
		//fprintf(stderr, "pdata %p\n", p_data);
		page = tvb_get_guint8(tvb, offset);
		ANTITEM(tree, hf_ant_pd_page, 1);
		NANTITEM(tree, hf_ant_43_b1f0, 1);
		NANTITEM(tree, hf_ant_43_b1f1, 1);
		NANTITEM(tree, hf_ant_43_b1f2, 1);
		NANTITEM(tree, hf_ant_43_b1f3, 1);
		NANTITEM(tree, hf_ant_43_b1f4, 1);
		NANTITEM(tree, hf_ant_43_b1f5, 1);
		NANTITEM(tree, hf_ant_43_b1f6, 1);
		ANTITEM(tree, hf_ant_43_b1f7, 1);
		phase = tvb_get_guint8(tvb, offset);
		switch (page) {
		case 0x43:
			ANTITEM(tree, hf_ant_phase, 1);
			ANTITEM(tree, hf_ant_b3, 1);
			switch (phase) {
			case 1:
				ANTITEM(tree, hf_ant_pcid, 4);
				ANTITEM(tree, hf_ant_u0, 2);
				ANTITEM(tree, hf_ant_ub, 1);
				ANTITEM(tree, hf_ant_ub, 1);
				ANTITEM(tree, hf_ant_unitid, 4);
				if (tvb_length_remaining(tvb, offset)) {
					ANTITEM(tree, hf_ant_unitname, 16);
				}
				break;
			case 3:
				flag = tvb_get_guint8(tvb, offset+2);
				switch (flag) {
				case 0:
					ANTITEM(tree, hf_ant_pcid, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u1, 4);
					ANTITEM(tree, hf_ant_unitid, 4);
					break;
				case 1:
					/* Forerunner 50 decoder from: http://darkskiez.co.uk/index.php?page=Garmin_ForeRunner_Decoder */
					ANTITEM(tree, hf_ant_product_id, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_product_id, 2);
					ANTITEM(tree, hf_ant_unitname, 16);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_unitid, 4);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_auth, 8);
					ANTITEM(tree, hf_ant_fpodid, 2);
					ANTITEM(tree, hf_ant_hrmid, 2);
					ANTITEM(tree, hf_ant_bpodid, 2); /* TODO: confirm */
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_firmware, 16);
					NANTITEM(tree, hf_ant_pref1f0, 1);
					NANTITEM(tree, hf_ant_pref1f1, 1);
					NANTITEM(tree, hf_ant_pref1f2, 1);
					NANTITEM(tree, hf_ant_pref1f3, 1);
					NANTITEM(tree, hf_ant_pref1f4, 1);
					NANTITEM(tree, hf_ant_pref1f5, 1);
					NANTITEM(tree, hf_ant_pref1f6, 1);
					ANTITEM(tree, hf_ant_pref1f7, 1);
					NANTITEM(tree, hf_ant_pref2f0, 1);
					NANTITEM(tree, hf_ant_pref2f1, 1);
					NANTITEM(tree, hf_ant_pref2f2, 1);
					NANTITEM(tree, hf_ant_pref2f3, 1);
					NANTITEM(tree, hf_ant_pref2f4, 1);
					NANTITEM(tree, hf_ant_pref2f5, 1);
					NANTITEM(tree, hf_ant_pref2f6, 1);
					ANTITEM(tree, hf_ant_pref2f7, 1);
					ANTITEM(tree, hf_ant_autolap, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_run_lo, 2);
					ANTITEM(tree, hf_ant_run_hi, 2);
					ANTITEM(tree, hf_ant_hrm_lo, 1);
					ANTITEM(tree, hf_ant_hrm_hi, 1);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_weight, 1);
					ANTITEM(tree, hf_ant_ub, 1);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_pref_cksum, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_xid, 1);
					ANTITEM(tree, hf_ant_ub, 1);
					ANTITEM(tree, hf_ant_x0, 6);
					ANTITEM(tree, hf_ant_x1, 6);
					ANTITEM(tree, hf_ant_x2, 6);
					ANTITEM(tree, hf_ant_x3, 6);
					for (i = 1; i <= 100; i++) {
						val = tvb_get_guint8(tvb, offset);
						proto_tree_add_uint_format_value(tree, hf_ant_run_id, tvb, offset, 1, i, "%d %d", val, i); offset++;
						//ANTITEM(tree, hf_ant_run_id, 1);
						ANTITEM(tree, hf_ant_run_prev, 1);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_run_time, 2);
						ANTITEM(tree, hf_ant_run_date, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
					}
					for (i = 1; i <= 100; i++) {
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_lap_next, 1);
						ANTITEM(tree, hf_ant_lap_type, 1);
						ANTITEM(tree, hf_ant_lap_speed, 2);
						ANTITEM(tree, hf_ant_lap_dist, 4);
						ANTITEM(tree, hf_ant_lap_time, 4);
						ANTITEM(tree, hf_ant_lap_cals, 2);
						ANTITEM(tree, hf_ant_lap_avghr, 1);
						ANTITEM(tree, hf_ant_lap_maxhr, 1);
						ANTITEM(tree, hf_ant_lap_avgcad, 1);
						ANTITEM(tree, hf_ant_lap_maxcad, 1);
						ANTITEM(tree, hf_ant_lap_steps, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
						ANTITEM(tree, hf_ant_u0, 2);
					}
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					ANTITEM(tree, hf_ant_u0, 2);
					for (i = 1; i <= 100; i++) {
						ANTITEM(tree, hf_ant_u0, 2);
						for (j = 1; j <= 50; j++) {
							ANTITEM(tree, hf_ant_speed_dist, 3);
							ANTITEM(tree, hf_ant_cad, 1);
							ANTITEM(tree, hf_ant_hr, 1);
						}
					}
					break;
				}
				break;
			}
			break;
		case 0x44:
			ANTITEM(tree, hf_ant_cmd, 1);
			ANTITEM(tree, hf_ant_auth_len, 1);
			switch (phase) {
			case 3:
				ANTITEM(tree, hf_ant_pcid, 4);
				//ANTITEM(tree, hf_ant_u0, 2);
				ANTITEM(tree, hf_ant_auth, 8);
				ANTITEM(tree, hf_ant_data_mbz, 8);
				break;
			}
			break;
		}
	}
	return offset;
}

static int
dissect_ant(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset;
	int len;
	int msgid;
	int rmsg;
	guint16 newrr;
	guint8 newseq;
	guint8 newr1;
	guint8 newr2;
	guint8 newn;
	guint16 newp;
	guint16 newt;
	int chan;
	guint64 netkey;
	char *netstr;
	guint16 val;
	guint8 page;
	float batt;
	struct ant_info *ant_infop;
	struct pkt_data *p_data;
	guint8 rdiff;
	guint8 ndiff;
	guint16 pdiff;
	guint16 tdiff;
	float nm;
	float rpm;
	float watts;
	guint8 ext;
	guint16 newwheeltime, diffwheeltime;
	guint16 newcranktime, diffcranktime;
	guint16 newwheelrev, diffwheelrev;
	guint16 newcrankrev, diffcrankrev;
	guint8 cadx1, cadx2;
	guint8 cmd;
	guint8 phase;
	guint8 burst_last, burst_seq, burst_chan;
	fragment_data *frag_msg;
	tvbuff_t *new_tvb, *next_tvb;
	proto_tree *msg_tree;
	gboolean save_fragmented = FALSE;
	proto_item *antdata_item = NULL;
	proto_item *ti;
	proto_tree *ant_tree;
	proto_tree *dtree = NULL;	/* data tree. TODO: dissect ANT data in subdissector */
	int i;
	packet_info cpinfo;
	guint8 cksum;
	

	/*
	 * requirements for ANT packet: len >= ANT_MIN_LEN, must start with SYNC
	 * could also use:
	 * valid checksum
	 * tvb len = len + header + trailer, though would miss packets with trailing nulls
	 */

	if (tvb_length(tvb) < ANT_MIN_LEN) {
		return 0;
	}
	if (MESG_TX_SYNC != tvb_get_guint8(tvb, 0)) {
		fprintf(stderr, "not sync len %d isfrag %d\n", tvb_length(tvb), pinfo->fragmented);
		return 0;
	}

	len = tvb_get_guint8(tvb, LEN_OFFSET);
	msgid = tvb_get_guint8(tvb, MSGID_OFFSET);

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANT");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "ANT Message");

	offset = 0;
	if (tree) {

		ti = proto_tree_add_item(tree, proto_ant, tvb, 0, -1, TRUE);

		ant_tree = proto_item_add_subtree(ti, ett_ant);
		msg_tree = proto_item_add_subtree(dtree, ett_msg_fragments);
	}

	ANTITEM(ant_tree, hf_ant_sync, 1);
	ANTITEM(ant_tree, hf_ant_msg_length, 1);
	ANTITEM(ant_tree, hf_ant_msg_id, 1);

	if (len > 0) {
		if (tree) {
			/*antdata_item = NANTITEM(ant_tree, hf_ant_data, len);*/ /* TODO no data for meta */
			antdata_item = proto_tree_add_item(ant_tree, hf_ant_data, tvb, offset, len, TRUE);
			dtree = proto_item_add_subtree(antdata_item, ett_ant_data);
		}
		switch (msgid) {
		case MESG_CAPABILITIES_ID:
			ANTITEM(dtree, hf_ant_data_maxchan, 1);
			ANTITEM(dtree, hf_ant_data_maxnet, 1);

			/* TODO - show reserved bits */
			NANTITEM(dtree, hf_ant_bm_no_rx_chans, 1);
			NANTITEM(dtree, hf_ant_bm_no_tx_chans, 1);
			NANTITEM(dtree, hf_ant_bm_no_rx_msgs, 1);
			NANTITEM(dtree, hf_ant_bm_no_tx_msgs, 1);
			NANTITEM(dtree, hf_ant_bm_no_ackd_msgs, 1);
			ANTITEM(dtree, hf_ant_bm_no_burst_msgs, 1);
			
			NANTITEM(dtree, hf_ant_bm_net, 1);
			NANTITEM(dtree, hf_ant_bm_serial, 1);
			NANTITEM(dtree, hf_ant_bm_per_chan_tx_power, 1);
			NANTITEM(dtree, hf_ant_bm_low_prio_srch, 1);
			NANTITEM(dtree, hf_ant_bm_script, 1);
			ANTITEM(dtree, hf_ant_bm_search_list, 1);
			if (len > 4) {
				NANTITEM(dtree, hf_ant_bm_led, 1);
				NANTITEM(dtree, hf_ant_bm_ext_msg, 1);
				NANTITEM(dtree, hf_ant_bm_scan_mode, 1);
				NANTITEM(dtree, hf_ant_bm_prox_srch, 1);
				ANTITEM(dtree, hf_ant_bm_ext_assign, 1);
			}
			break;
		case MESG_ASSIGN_CHANNEL_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			ANTITEM(dtree, hf_ant_data_chtype, 1);
			ANTITEM(dtree, hf_ant_data_net, 1);
			break;
		case MESG_CHANNEL_SEARCH_TIMEOUT_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			val = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format_value(dtree, hf_ant_data_srchto, tvb, offset, 1, val, "%d (%.1f secs)", val, val*2.5); offset++;
			break;
		case MESG_CHANNEL_RADIO_FREQ_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			val = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format_value(dtree, hf_ant_data_freq, tvb, offset, 1, val, "%d (%dMHz)", val, 2400+val); offset++;
			break;
		case MESG_BURST_DATA_ID:
			burst_last = tvb_get_guint8(tvb, offset) & (1 << 7);
			burst_seq = (tvb_get_guint8(tvb, offset) & (3 << 5)) >> 5;
			burst_chan = tvb_get_guint8(tvb, offset) & 31;
			p_data = (struct pkt_data *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ant, 0);
			ant_infop = 0;
			if (!p_data) {
				ant_infop = get_ant_infop(pinfo);
				p_data = new_pdata(ant_infop, burst_chan);
				p_data->meta.burst.seq = ant_infop->last.burst.seq[burst_chan]++;
				p_data->meta.burst.seq_id = ant_infop->last.burst.seq_id[burst_chan];
				p_data->meta.burst.islast = burst_last;
				p_data->meta.burst.burst_seq = ant_infop->last.burst.burst_seq[burst_chan] = burst_seq;
				p_add_proto_data(pinfo->fd, proto_ant, p_data);
				if (burst_last) {
					//fprintf(stderr, "burst %d %d %d\n", burst_seq, burst_chan, burst_last);
					ant_infop->last.burst.seq[burst_chan] = 0;
					ant_infop->last.burst.seq_id[burst_chan]++;
				}
			}
			NANTITEM(dtree, hf_ant_bm_burst_seq_end, 1);
			NANTITEM(dtree, hf_ant_bm_burst_seq, 1);
			ANTITEM(dtree, hf_ant_bm_burst_chan, 1);
			save_fragmented = pinfo->fragmented;
			pinfo->fragmented = 1;
			frag_msg = fragment_add_seq_check(&ip_reassembly_table, tvb, offset,
			    pinfo, p_data->meta.burst.seq_id, NULL, p_data->meta.burst.seq,
				MIN(8, tvb_length_remaining(tvb, offset)-1), burst_last?0:1);
			//fprintf(stderr, "frag %p seq %d last %d seq %d\n", frag_msg, p_data->meta.burst.seq, burst_last?1:0, p_data->meta.burst.seq_id);
			//fprintf(stderr, "burst rem %d %d\n", tvb_length_remaining(tvb, offset)-1, MIN(8,tvb_length_remaining(tvb, offset)-1));
			new_tvb = process_reassembled_data(tvb, offset, pinfo, "reassembled burst", frag_msg,
				&msg_frag_items, NULL, dtree);
			ANTITEM(dtree, hf_ant_data_data, len-1);
			if (tree) {
				if (frag_msg) {
					col_append_str(pinfo->cinfo, COL_INFO, " burst reassembled");
				} else {
					col_append_fstr(pinfo->cinfo, COL_INFO, " burst %u", p_data->meta.burst.seq);
				}
			}
			if (new_tvb) {
				//fprintf(stderr, "new size %d\n", tvb_reported_length_remaining(new_tvb, 0));
				next_tvb = new_tvb;
				dissect_burst(new_tvb, pinfo, dtree);
			} else {
				next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			}
			pinfo->fragmented = save_fragmented;
			/*
			if (burst_last && next_tvb) {
				dissect_ant(new_tvb, pinfo, msg_tree);
			}
			*/
			break;
		case MESG_CHANNEL_ID_ID:
			chan = tvb_get_guint8(tvb, CHAN_OFFSET);
			ANTITEM(dtree, hf_ant_data_chan, 1);
			ANTITEM(dtree, hf_ant_data_devno, 2);
			ant_infop = get_ant_infop(pinfo);
			ant_infop->devtype[chan] = tvb_get_guint8(tvb, DEVTYPE_OFFSET);
			ANTITEM(dtree, hf_ant_data_devtype, 1);
			ANTITEM(dtree, hf_ant_data_transtype, 1);
			break;
		case MESG_SEARCH_WAVEFORM_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1)
			ANTITEM(dtree, hf_ant_data_waveform, 2);
			break;
		case MESG_CHANNEL_MESG_PERIOD_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			val = tvb_get_letohs(tvb, PERIOD_OFFSET);
			proto_tree_add_uint_format_value(dtree, hf_ant_data_period, tvb, offset, 2,
				val, "%d (%.2fHz)", val, 32768.0/val); offset += 2;
			break;
		case MESG_REQUEST_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			ANTITEM(dtree, hf_ant_data_msgid, 1);
			break;
		case MESG_CHANNEL_STATUS_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			ANTITEM(dtree, hf_ant_data_chanstat, 1);
			break;
		case MESG_NETWORK_KEY_ID:
			ANTITEM(dtree, hf_ant_data_net, 1);
			netkey = tvb_get_ntoh64(tvb, offset);
			if ((netkey & ANTP_MASK) == ANTP_MASK)
				netstr = "(unknown)";
			else
				netstr = "(invalid key)";
			switch (netkey) {
			case SUUNTO_KEY:
				netstr = "(Suunto)";
				break;
			case GMNHU_KEY:
				netstr = "(Garmin head unit)";
				break;
			case ANTP_KEY:
				netstr = "(ANT+)";
				break;
			}
			proto_tree_add_text(dtree, tvb, offset, 8, "Network key: %" G_GINT64_MODIFIER "x %s",
				netkey, netstr);
			offset+= 8;
			break;
		case MESG_RESPONSE_EVENT_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			rmsg = tvb_get_guint8(tvb, RMSG_OFFSET); /* special case == 1 */
			ANTITEM(dtree, hf_ant_data_msgid, 1);
			ANTITEM(dtree, hf_ant_data_msgcode, 1);
			break;
		case MESG_SYSTEM_RESET_ID:
			ANTITEM(dtree, hf_ant_data_mbz, 1);
			break;
		case MESG_BROADCAST_DATA_ID:
		case MESG_EXT_BROADCAST_DATA_ID:
			chan = tvb_get_guint8(tvb, CHAN_OFFSET);
			ANTITEM(dtree, hf_ant_data_chan, 1);
			if (MESG_EXT_BROADCAST_DATA_ID == msgid) {
				ANTITEM(dtree, hf_ant_data_devno, 2);
				ANTITEM(dtree, hf_ant_data_devtype, 1);
				ANTITEM(dtree, hf_ant_data_transtype, 1);
				ext = EXT_ADD;
			} else
				ext = 0;
			p_data = (struct pkt_data *) p_get_proto_data(wmem_file_scope(), pinfo, proto_ant, 0);
			ant_infop = 0;
			if (!p_data) {
				ant_infop = get_ant_infop(pinfo);
				p_data = new_pdata(ant_infop, chan);
				if (MESG_EXT_BROADCAST_DATA_ID == msgid)
					p_data->devtype = tvb_get_guint8(tvb, DEVTYPE_OFFSET);
				p_add_proto_data(pinfo->fd, proto_ant, p_data);
			}
			page = tvb_get_guint8(tvb, offset);
			if (p_data->devtype == DEVTYPE_HRM) {
				ANTITEM(dtree, hf_ant_pd_page, 1);
				ANTITEM(dtree, hf_ant_data_data, 3);
				newrr = tvb_get_letohs(tvb, RR_OFFSET+ext);
				newseq = tvb_get_guint8(tvb, SEQ_OFFSET+ext);
				if (ant_infop) {
					ant_infop->last.hr.rr[chan] = newrr;
					ant_infop->last.hr.seq[chan] = newseq;
					ant_infop->first[chan] = 0;
				}
				if (p_data->last.hr.seq != newseq && !p_data->first) {
					proto_tree_add_text(dtree, tvb, offset, 2, "R-R time: %d was %d, diff %d, R-R HR %.1f",
						newrr, p_data->last.hr.rr, newrr-p_data->last.hr.rr, 60.0*1024.0/(newrr-p_data->last.hr.rr));
				} else {
					NANTITEM(dtree, hf_ant_pd_rr, 2);
				}
				offset += 2;
				ANTITEM(dtree, hf_ant_pd_seq, 1);
				ANTITEM(dtree, hf_ant_pd_hr, 1);
			} else if (p_data->devtype == DEVTYPE_SUUHRM) {
				ANTITEM(dtree, hf_ant_pd_hr, 1);
				ANTITEM(dtree, hf_ant_pd_seq, 1);
				newrr = tvb_get_letohs(tvb, SUU_RR_OFFSET+ext);
				proto_tree_add_text(dtree, tvb, offset, 2, "R-R time: %d was %d, diff %d, R-R HR %.1f",
					newrr, p_data->last.hr.rr, newrr-p_data->last.hr.rr, 60.0*1024.0/(newrr-p_data->last.hr.rr));
				ANTITEM(dtree, hf_ant_pd_newrr, 2);
				ANTITEM(dtree, hf_ant_pd_oldrr, 2);
				ANTITEM(dtree, hf_ant_pd_prevrr, 2);
			} else if (p_data->devtype == DEVTYPE_BIKE_POWER) {
				switch (page) {
				case 0x01:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_unk, 1);
					ANTITEM(dtree, hf_ant_torque_cfg, 1);
					ANTITEM(dtree, hf_ant_torque_raw, 2);
					ANTITEM(dtree, hf_ant_torque_offset, 2);
					ANTITEM(dtree, hf_ant_unk, 1);
					break;
				case 0x12:
					newr1 = tvb_get_guint8(tvb, R1_OFFSET+ext);
					newr2 = tvb_get_guint8(tvb, R2_OFFSET+ext);
					newn = tvb_get_guint8(tvb, N_OFFSET+ext);
					newp = tvb_get_letohs(tvb, P_OFFSET+ext);
					newt = tvb_get_letohs(tvb, T_OFFSET+ext);
					if (ant_infop) {
						ant_infop->first[chan] = 0;
						ant_infop->last.power.r1[chan] = newr1;
						ant_infop->last.power.r2[chan] = newr2;
						ant_infop->last.power.n[chan] = newn;
						ant_infop->last.power.p[chan] = newp;
						ant_infop->last.power.t[chan] = newt;
					}

					ANTITEM(dtree, hf_ant_pd_page, 1);
					rdiff = newr1-p_data->last.power.r1;
					ndiff = newn-p_data->last.power.n;
					tdiff = newt-p_data->last.power.t;
					pdiff = newp-p_data->last.power.p;
					if (p_data->last.power.r1 != newr1 && !p_data->first && pdiff && tdiff) {
						nm = tdiff/(rdiff*32.0);
						rpm = rdiff*122880.0/pdiff;
						watts = rpm*nm*2*M_PI/60;
						proto_tree_add_text(dtree, tvb, offset, 2, "r1 %d %d r2 %d %d n %d %d p %d %d t %d %d",
							newr1, p_data->last.power.r1, newr2, p_data->last.power.r2, newn, p_data->last.power.n,
							newp, p_data->last.power.p, newt, p_data->last.power.t);

						proto_tree_add_uint_format_value(dtree, hf_ant_r1, tvb, offset, 1, hf_ant_r1,
							"%d (old %d diff %d)", newr1, p_data->last.power.r1, rdiff);
						proto_tree_add_uint_format_value(dtree, hf_ant_r2, tvb, offset, 1, hf_ant_r2,
							"%d (old %d diff %d)", newr2, p_data->last.power.r2, rdiff);
						proto_tree_add_uint_format_value(dtree, hf_ant_n, tvb, offset, 1, hf_ant_n,
							"%d (old %d diff %d)", newn, p_data->last.power.n, ndiff);
						proto_tree_add_uint_format_value(dtree, hf_ant_p, tvb, offset, 2, hf_ant_p,
							"%d (old %d diff %d)", newp, p_data->last.power.p, pdiff);
						proto_tree_add_uint_format_value(dtree, hf_ant_t, tvb, offset, 2, hf_ant_t,
							"%d (old %d diff %d)", newt, p_data->last.power.t, tdiff);
						proto_tree_add_text(dtree, tvb, offset, 1, "Nm: %.2f (tdiff/(rdiff*32)", nm);
						proto_tree_add_text(dtree, tvb, offset, 1, "RPM: %.2f (rdiff*122880/pdiff)", rpm);
						proto_tree_add_text(dtree, tvb, offset, 1, "Watts: %.2f (rpm*nm*2pi/60)", watts);
					} else {
						ANTITEM(dtree, hf_ant_r1, 1);
						ANTITEM(dtree, hf_ant_r2, 1);
						ANTITEM(dtree, hf_ant_n, 1);
						ANTITEM(dtree, hf_ant_p, 2);
						ANTITEM(dtree, hf_ant_t, 2);
					}
					break;
				case 0x50:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_unk, 2);
					ANTITEM(dtree, hf_ant_hwver, 1);
					ANTITEM(dtree, hf_ant_manu, 2);
					ANTITEM(dtree, hf_ant_model, 2);
					break;
				case 0x51:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_unk, 2);
					ANTITEM(dtree, hf_ant_swver, 1);
					ANTITEM(dtree, hf_ant_serial, 4);
					break;
				case 0x52:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_unk, 5);
					batt = (tvb_get_guint8(tvb, offset+1)&0x0f);
					batt += tvb_get_guint8(tvb, offset)/256.0;
					/* FIXME: bitmask output doesn't match data */
					proto_tree_add_uint_format_value(dtree, hf_ant_batt, tvb, offset, 2, hf_ant_batt, "%.2fV", batt);
					break;
				default:
					ANTITEM(dtree, hf_ant_data_data, len-1);
				}
			} else if (p_data->devtype == DEVTYPE_BIKE_POWER) {
				newcranktime = tvb_get_letohs(tvb, CT_OFFSET+ext);
				newcrankrev = tvb_get_letohs(tvb, CR_OFFSET+ext);
				newwheeltime = tvb_get_letohs(tvb, WT_OFFSET+ext);
				newwheelrev = tvb_get_letohs(tvb, WR_OFFSET+ext);
				if (ant_infop) {
					ant_infop->last.bike.cranktime[chan] = newcranktime;
					ant_infop->last.bike.crankrev[chan] = newcrankrev;
					ant_infop->last.bike.wheeltime[chan] = newwheeltime;
					ant_infop->last.bike.wheelrev[chan] = newwheelrev;
					ant_infop->first[chan] = 0;
				}
				diffcranktime = newcranktime-p_data->last.bike.cranktime;
				diffcrankrev = newcrankrev-p_data->last.bike.crankrev;
				diffwheeltime = newwheeltime-p_data->last.bike.wheeltime;
				diffwheelrev = newwheelrev-p_data->last.bike.wheelrev;
				if (newcrankrev == p_data->last.bike.crankrev) {
					ANTITEM(dtree, hf_ant_cranktime, 2);
					ANTITEM(dtree, hf_ant_crankrev, 2);
				} else {
					proto_tree_add_uint_format_value(dtree, hf_ant_cranktime, tvb, offset, 2, hf_ant_cranktime,
						"%d (old %d diff %d cadence %.1f)", newcranktime, p_data->last.bike.cranktime, diffcranktime,
						1024.0*60.0/diffcranktime/diffcrankrev); offset += 2;
					proto_tree_add_uint_format_value(dtree, hf_ant_crankrev, tvb, offset, 2, hf_ant_crankrev,
						"%d (old %d diff %d)", newcrankrev, p_data->last.bike.crankrev, diffcrankrev); offset += 2;
				}
				if (newwheelrev == p_data->last.bike.wheelrev) {
					ANTITEM(dtree, hf_ant_wheeltime, 2);
					ANTITEM(dtree, hf_ant_wheelrev, 2);
				} else {
					proto_tree_add_uint_format_value(dtree, hf_ant_wheeltime, tvb, offset, 2, hf_ant_wheeltime,
						"%d (old %d diff %d rpm %.1f)", newwheeltime, p_data->last.bike.wheeltime, diffwheeltime,
						1024.0*60.0/diffwheeltime/diffwheelrev); offset += 2;
					proto_tree_add_uint_format_value(dtree, hf_ant_wheelrev, tvb, offset, 2, hf_ant_wheelrev,
						"%d (old %d diff %d)", newwheelrev, p_data->last.bike.wheelrev, diffwheelrev); offset += 2;
				}
			} else if (p_data->devtype == DEVTYPE_SDM) {
				fprintf(stderr, "foot page %d\n", page);
				switch (page) {
				case 0x01:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_time_frac, 1);
					ANTITEM(dtree, hf_ant_time_int, 1);
					ANTITEM(dtree, hf_ant_dist_int, 1);
					NANTITEM(dtree, hf_ant_dist_frac, 1);
					ANTITEM(dtree, hf_ant_spd_int, 1);
					ANTITEM(dtree, hf_ant_spd_frac, 1);
					ANTITEM(dtree, hf_ant_stride_count, 1);
					ANTITEM(dtree, hf_ant_update_latency, 1);
					break;
				case 0x02:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					ANTITEM(dtree, hf_ant_unk, 2);
					ANTITEM(dtree, hf_ant_cad, 1);
					/*ANTITEM(dtree, hf_ant_cadx, 2);*/
					cadx1 = tvb_get_guint8(tvb, offset);
					cadx2 = tvb_get_guint8(tvb, offset+1);
					proto_tree_add_uint_format_value(dtree, hf_ant_cadx, tvb, offset, 2, hf_ant_cadx,
						"%d %02x%02x %d %d", cadx1+256*cadx2, cadx1, cadx2, cadx1, cadx2);
						offset += 2;
					ANTITEM(dtree, hf_ant_unk, 2);
					break;
				default:
					ANTITEM(dtree, hf_ant_data_data, len-1-ext);
				}
			} else if (p_data->devtype == DEVTYPE_ANTFS) {
				switch (page) {
				case 0x43:
					ANTITEM(dtree, hf_ant_pd_page, 1);
					NANTITEM(dtree, hf_ant_43_b1f0, 1);
					NANTITEM(dtree, hf_ant_43_b1f1, 1);
					NANTITEM(dtree, hf_ant_43_b1f2, 1);
					NANTITEM(dtree, hf_ant_43_b1f3, 1);
					NANTITEM(dtree, hf_ant_43_b1f4, 1);
					NANTITEM(dtree, hf_ant_43_b1f5, 1);
					NANTITEM(dtree, hf_ant_43_b1f6, 1);
					ANTITEM(dtree, hf_ant_43_b1f7, 1);
					phase = tvb_get_guint8(tvb, offset);
					ANTITEM(dtree, hf_ant_phase, 1);
					switch (phase) {
					case 0:
						ANTITEM(dtree, hf_ant_b3, 1);
						ANTITEM(dtree, hf_ant_product_id, 2);
						ANTITEM(dtree, hf_ant_b6, 1);
						ANTITEM(dtree, hf_ant_b7, 1);
						break;
					case 1:
						ANTITEM(dtree, hf_ant_b3, 1);
						ANTITEM(dtree, hf_ant_pcid, 4);
						//ANTITEM(tree, hf_ant_u0, 2);
						break;
					case 2:
						ANTITEM(dtree, hf_ant_b3, 1);
						ANTITEM(dtree, hf_ant_pcid, 4);
						//ANTITEM(tree, hf_ant_u0, 2);
						break;
					case 3:
						ANTITEM(dtree, hf_ant_b3, 1);
						ANTITEM(dtree, hf_ant_pcid, 4);
						//ANTITEM(tree, hf_ant_u0, 2);
						break;
					default:
						ANTITEM(dtree, hf_ant_b3, 1);
						ANTITEM(dtree, hf_ant_b4, 1);
						ANTITEM(dtree, hf_ant_b5, 1);
						ANTITEM(dtree, hf_ant_b6, 1);
						ANTITEM(dtree, hf_ant_b7, 1);
					}
					break;
				default:
					ANTITEM(dtree, hf_ant_data_data, len-1-ext);
				}
			} else {
				ANTITEM(dtree, hf_ant_data_data, len-1-ext);
			}
			break;
		case MESG_ACKNOWLEDGED_DATA_ID:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			ANTITEM(dtree, hf_ant_pd_page, 1);
			cmd = tvb_get_guint8(tvb, offset);
			ANTITEM(dtree, hf_ant_cmd, 1);
			switch (cmd) {
			case 2:
				val = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint_format_value(dtree, hf_ant_data_freq, tvb, offset, 1, val, "%d (%dMHz)", val, 2400+val); offset++;
				ANTITEM(dtree, hf_ant_b3, 1);
				ANTITEM(dtree, hf_ant_pcid, 4);
				break;
			case 3:
				ANTITEM(dtree, hf_ant_data_mbz, 6);
				break;
			case 4:
				ANTITEM(dtree, hf_ant_b2, 1);
				ANTITEM(dtree, hf_ant_b3, 1);
				ANTITEM(dtree, hf_ant_pcid, 4);
				break;
			default:
				ANTITEM(dtree, hf_ant_b2, 1);
				ANTITEM(dtree, hf_ant_b3, 1);
				ANTITEM(dtree, hf_ant_b4, 1);
				ANTITEM(dtree, hf_ant_b5, 1);
				ANTITEM(dtree, hf_ant_b6, 1);
				ANTITEM(dtree, hf_ant_b7, 1);
			}
			break;
		default:
			ANTITEM(dtree, hf_ant_data_chan, 1);
			if (len > 1) {
				ANTITEM(dtree, hf_ant_data_data, len-1);
			}
		}

	}
	cksum = 0;
	for (i = 0; i < offset; i++)
		cksum ^= tvb_get_guint8(tvb, i);
	val = tvb_get_guint8(tvb, offset);
	if (cksum == val)
		proto_tree_add_uint_format_value(dtree, hf_ant_checksum, tvb, offset, 1, val, "%02x (correct ck %02x)", val, cksum);
	else
		proto_tree_add_uint_format_value(dtree, hf_ant_checksum, tvb, offset, 1, val, "%02x (incorrect, should be %02x)", cksum, val);
	offset++;


	/* ANTITEM(ant_tree, hf_ant_checksum, 1);  TODO - validate */
	/* See if another ANT message got stuck on the end */
	/* TODO: do this like (with?) tcp_dissect_pdus() */
	for (i = 0; i < tvb_length_remaining(tvb, offset); i++) {
		if (MESG_TX_SYNC == tvb_get_guint8(tvb, offset+i)) {
			memcpy(&cpinfo, pinfo, sizeof cpinfo);
			return dissect_ant(
				tvb_new_subset(tvb, offset+i, tvb_length_remaining(tvb, offset)-i, tvb_length_remaining(tvb, offset)-i),
				&cpinfo, tree);
		}
	}

	return offset;
	/*return tvb_length(tvb); */
}

void
proto_register_ant(void)
{
	module_t *ant_module;

	static hf_register_info hf[] = {

		{&hf_msg_fragments,
		 {"Message fragments", "msg.fragments",
		 FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment,
		 {"Message fragment", "msg.fragment",
		 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_overlap,
		 {"Message fragment overlap", "msg.fragment.overlap",
		 FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_overlap_conflicts,
		 {"Message fragment overlapping with conflicting data",
		 "msg.fragment.overlap.conflicts",
		 FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_multiple_tails,
		 {"Message has multiple tail fragments",
		 "msg.fragment.multiple_tails",
		 FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_too_long_fragment,
		 {"Message fragment too long", "msg.fragment.too_long_fragment",
		 FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_fragment_error,
		 {"Message defragmentation error", "msg.fragment.error",
		 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_reassembled_in,
		 {"Reassembled in", "msg.reassembled.in",
		 FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },

		{ &hf_ant_r1,
			{ "R1","ant.r1", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_r2,
			{ "R2","ant.r2", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_n,
			{ "N","ant.n", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_p,
			{ "P","ant.p", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_t,
			{ "T","ant.t", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_sync,
			{ "SYNC","ant.sync", FT_UINT8, BASE_HEX, NULL, 0, "Sync byte, must be 0xA4", HFILL }
		},
		{ &hf_ant_cmd,
			{ "Cmd","ant.Cmd", FT_UINT8, BASE_DEC, VALS(cmds44), 0, "", HFILL }
		},
		{ &hf_ant_phase,
			{ "Phase","ant.phase", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_product_id,
			{ "Product id","ant.product_id", FT_UINT16, BASE_DEC, VALS(product_ids), 0, "", HFILL }
		},
		{ &hf_ant_b6,
			{ "Byte 6","ant.b6", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_b7,
			{ "Byte 7","ant.b7", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_b2,
			{ "Byte 2","ant.b2", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_b3,
			{ "Byte 3","ant.b3", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_b4,
			{ "Byte 4","ant.b4", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_b5,
			{ "Byte 5","ant.b5", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_unk,
			{ "Unknown","ant.unk", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_torque_raw,
			{ "Torque raw","ant.torque_raw", FT_INT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_torque_offset,
			{ "Torque offset","ant.torque_offset", FT_INT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_torque_cfg,
			{ "Torque config","ant.torque_cfg", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_swver,
			{ "Software version","ant.swver", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_ub,
			{ "Unknown","ant.ub", FT_UINT8, BASE_HEX_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_u0,
			{ "Unknown","ant.u0", FT_UINT16, BASE_HEX_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_u1,
			{ "Unknown","ant.u1", FT_UINT32, BASE_HEX_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_u2,
			{ "Unknown","ant.u2", FT_UINT32, BASE_HEX_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_unitid,
			{ "Unit ID","ant.unitid", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_auth,
			{ "Auth","ant.auth", FT_UINT64, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_fpodid,
			{ "Foot Pod ID","ant.fpodid", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_bpodid,
			{ "Bike Pod ID","ant.bpodid", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_hrmid,
			{ "HRM ID","ant.hrmid", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pcid,
			{ "PC ID","ant.pcid", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_serial,
			{ "Software serial#","ant.serial", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_hwver,
			{ "Hardware version","ant.hwver", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_manu,
			{ "Hardware manufacturer","ant.manu", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_model,
			{ "Hardware model","ant.model", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_page,
			{ "Page","ant.pd.page", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_oldrr,
			{ "Old R-R time","ant.pd.oldrr", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_newrr,
			{ "R-R time","ant.pd.newrr", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_prevrr,
			{ "Prev R-R time","ant.pd.prevrr", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_rr,
			{ "R-R time","ant.pd.rr", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_seq,
			{ "Seq#","ant.pd.seq", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_maxchan,
			{ "Max channel","ant.maxchan", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_maxnet,
			{ "Max network","ant.maxnet", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_freq,
			{ "Frequency","ant.freq", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_srchto,
			{ "Search timeout","ant.srchto", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_pd_hr,
			{ "HR","ant.pd.hr", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_msg_length,
			{ "Message length","ant.msglen", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_msg_id,
			{ "Message ID","ant.msgid", FT_UINT8, BASE_HEX, VALS(msgs), 0, "", HFILL }
		},
		{ &hf_ant_data_msgid,
			{ "Message ID","ant.data.msgid", FT_UINT8, BASE_HEX, VALS(msgs), 0, "", HFILL }
		},
		{ &hf_ant_data_chtype,
			{ "Message ID","ant.data.chtype", FT_UINT8, BASE_HEX, VALS(chtypes), 0, "", HFILL }
		},
		{ &hf_ant_data_msgcode,
			{ "Message Code","ant.data.msgcode", FT_UINT8, BASE_HEX, VALS(codes), 0, "", HFILL }
		},
		{ &hf_ant_data_chanstat,
			{ "Channel Status","ant.data.chanstat", FT_UINT8, BASE_HEX, VALS(chanstats), 0, "", HFILL }
		},
		{ &hf_ant_firmware,
			{ "Firmware","ant.firmware", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_unitname,
			{ "Unit name","ant.unitname", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data,
			{ "Data","ant.data", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_checksum,
			{ "Checksum","ant.chksum", FT_UINT8, BASE_HEX, NULL, 0, "XOR of all data", HFILL }
		},
		{ &hf_ant_data_net,
			{ "Net","ant.data.net", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_chan,
			{ "Chan","ant.data.chan", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_devtype,
			{ "Device type","ant.data.devtype", FT_UINT8, BASE_HEX, VALS(devtypes), 0, "", HFILL }
		},
		{ &hf_ant_data_transtype,
			{ "Transmission type","ant.data.transtype", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_cranktime,
			{ "Crank time","ant.cranktime", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_crankrev,
			{ "Crank revs","ant.cranktrev", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_wheeltime,
			{ "Wheel time","ant.wheeltime", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_wheelrev,
			{ "Wheel revs","ant.wheelrev", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_period,
			{ "Period","ant.data.period", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_devno,
			{ "Device#","ant.data.devno", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_waveform,
			{ "Waveform","ant.data.waveform", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_xid,
			{ "XID","ant.xid", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_x0,
			{ "X0","ant.x0", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_x1,
			{ "X1","ant.x1", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_x2,
			{ "X2","ant.x2", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_x3,
			{ "X3","ant.x3", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_data,
			{ "Data","ant.data.data", FT_BYTES, BASE_NONE, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_nk,
			{ "Network Key","ant.data.nk", FT_UINT64, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_data_mbz,
			{ "MBZ","ant.data.mbz", FT_BYTES, BASE_NONE, NULL, 0, "Must be zero", HFILL }
		},
		{ &hf_ant_time_frac,
			{ "Time fractional", "ant.time_frac", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_time_int,
			{ "Time integer", "ant.time_int", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_dist_int,
			{ "Distance integer", "ant.dist_int", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_spd_frac,
			{ "Speed fractional", "ant.spd_frac", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_stride_count,
			{ "Stride count", "ant.stride_count", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_update_latency,
			{ "Update latency", "ant.update_latency", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_dist_frac,
			{ "Distance fractional", "ant.dist_frac", FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL }
		},
		{ &hf_ant_spd_int,
			{ "Speed integer", "ant.dist_frac", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL }
		},
		{ &hf_ant_run_lo,
			{ "Run low", "ant.runlo", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_auth_len,
			{ "Auth len", "ant.authlen", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_run_hi,
			{ "Run high", "ant.runhigh", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_hrm_lo,
			{ "HRM low", "ant.hrmlo", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_hrm_hi,
			{ "HRM high", "ant.hrmhi", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_run_id,
			{ "Run ID", "ant.run_id", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_run_prev,
			{ "Prev run ID", "ant.run_previd", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_steps,
			{ "Lap steps", "ant.lap_steps", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_avgcad,
			{ "Lap avg cadence", "ant.lap_avgcad", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_speed_dist,
			{ "Speed/distance", "ant.spddist", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_hr,
			{ "HR", "ant.hr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_maxcad,
			{ "Lap max cadence", "ant.lap_maxcad", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_maxhr,
			{ "Lap max HR", "ant.lap_maxhr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_avghr,
			{ "Lap average HR", "ant.lap_avghr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_cals,
			{ "Lap cals", "ant.lap_cals", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_time,
			{ "Lap time", "ant.lap_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_dist,
			{ "Lap distance", "ant.lap_dist", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_speed,
			{ "Lap speed", "ant.lap_speed", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_type,
			{ "Lap type", "ant.lap_type", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_lap_next,
			{ "Lap next", "ant.lap_next", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_ant_weight,
			{ "Weight", "ant.weight", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_pref_cksum,
			{ "Pref cksum", "ant.prefcksum", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_run_time,
			{ "Run time of day", "ant.run_time", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_run_date,
			{ "Run date", "ant.run_date", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_autolap,
			{ "Autolap distance", "ant.autolap", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_ant_batt,
			{ "Battery level", "ant.batt", FT_UINT16, BASE_HEX, NULL, 0xff0f << 0, NULL, HFILL }
		},
		{ &hf_ant_bm_burst_seq_end,
			{ "Last burst", "ant.burst_last", FT_BOOLEAN, 8, NULL, 1 << 7, NULL, HFILL }
		},
		{ &hf_ant_cad,
			{ "Cadence", "ant.cad", FT_UINT8, BASE_DEC, NULL, 0, "", HFILL }
		},
		{ &hf_ant_cadx,
			{ "Cadx", "ant.cadx", FT_UINT16, BASE_DEC_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_ant_bm_burst_seq,
			{ "Sequence#", "ant.burst_seq", FT_UINT8, BASE_OCT, NULL, 3 << 5, NULL, HFILL }
		},
		{ &hf_ant_bm_burst_chan,
			{ "Chan", "ant.burst_chan", FT_UINT8, BASE_DEC, NULL, 31, NULL, HFILL }
		},
		{ &hf_ant_bm_no_rx_chans,
			{ "No RX channels", "ant.no_rx", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 0, NULL, HFILL }
		},
		{ &hf_ant_bm_no_tx_chans,
			{ "No TX channels", "ant.no_tx", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_bm_no_rx_msgs,
			{ "No RX channels", "ant.no_rx", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 2, NULL, HFILL }
		},
		{ &hf_ant_bm_no_tx_msgs,
			{ "No TX messages", "ant.no_tx_msgs", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 3, NULL, HFILL }
		},
		{ &hf_ant_bm_no_ackd_msgs,
			{ "No ACKed messages", "ant.no_ackd_msgs", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_bm_no_burst_msgs,
			{ "No Burst messages", "ant.no_bursg_msgs", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_bm_net,
			{ "Network", "ant.net_enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_bm_serial,
			{ "Serial number", "ant.ser_enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 3, NULL, HFILL }
		},
		{ &hf_ant_bm_per_chan_tx_power,
			{ "Per channel TX power", "ant.per_chan_tx_power", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_bm_low_prio_srch,
			{ "Low priority search", "ant.low_prio_srch", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_bm_script,
			{ "Script", "ant.script", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 6, NULL, HFILL }
		},
		{ &hf_ant_bm_search_list,
			{ "Search list", "ant.srch_list", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 7, NULL, HFILL }
		},
		{ &hf_ant_bm_led,
			{ "LED", "ant.led", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 0, NULL, HFILL }
		},
		{ &hf_ant_bm_ext_msg,
			{ "Extended messages", "ant.ext_msgs", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_bm_scan_mode,
			{ "Scan mode", "ant.scan_mode", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 2, NULL, HFILL }
		},
		{ &hf_ant_bm_prox_srch,
			{ "Proximity search", "ant.prox_srch", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_bm_ext_assign,
			{ "Extended assign", "ant.ext_assign", FT_BOOLEAN, 8,
			TFS(&tfs_enabled), 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_43_b1f0,
			{ "Beacon 43 byte 1 bit 0", "ant.beacon43_b1f0", FT_BOOLEAN, 8, NULL, 1 << 0, NULL, HFILL }
		},
		{ &hf_ant_43_b1f1,
			{ "Beacon 43 byte 1 bit 1", "ant.beacon43_b1f1", FT_BOOLEAN, 8, NULL, 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_43_b1f2,
			{ "Beacon 43 byte 1 bit 2", "ant.beacon43_b1f2", FT_BOOLEAN, 8, NULL, 1 << 2, NULL, HFILL }
		},
		{ &hf_ant_43_b1f3,
			{ "Beacon 43 byte 1 bit 3 (pairing)", "ant.beacon43_b1f3", FT_BOOLEAN, 8, NULL, 1 << 3, NULL, HFILL }
		},
		{ &hf_ant_43_b1f4,
			{ "Beacon 43 byte 1 bit 4", "ant.beacon43_b1f4", FT_BOOLEAN, 8, NULL, 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_43_b1f5,
			{ "Beacon 43 byte 1 bit 5 (new data)", "ant.beacon43_b1f5", FT_BOOLEAN, 8, NULL, 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_43_b1f6,
			{ "Beacon 43 byte 1 bit 6", "ant.beacon43_b1f6", FT_BOOLEAN, 8, NULL, 1 << 6, NULL, HFILL }
		},
		{ &hf_ant_43_b1f7,
			{ "Beacon 43 byte 1 bit 7", "ant.beacon43_b1f7", FT_BOOLEAN, 8, NULL, 1 << 7, NULL, HFILL }
		},
		{ &hf_ant_pref1f0,
			{ "Prefs1 bit 0", "ant.pref1f0", FT_BOOLEAN, 8, NULL, 1 << 0, NULL, HFILL }
		},
		{ &hf_ant_pref1f1,
			{ "Prefs1 bit 1 (Imperial)", "ant.pref1f1", FT_BOOLEAN, 8, NULL, 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_pref1f2,
			{ "Prefs1 bit 2", "ant.pref1f2", FT_BOOLEAN, 8, NULL, 1 << 2, NULL, HFILL }
		},
		{ &hf_ant_pref1f3,
			{ "Prefs1 bit 3", "ant.pref1f3", FT_BOOLEAN, 8, NULL, 1 << 3, NULL, HFILL }
		},
		{ &hf_ant_pref1f4,
			{ "Prefs1 bit 4 (Male)", "ant.pref1f4", FT_BOOLEAN, 8, NULL, 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_pref1f5,
			{ "Prefs1 bit 5", "ant.pref1f5", FT_BOOLEAN, 8, NULL, 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_pref1f6,
			{ "Prefs1 bit 6", "ant.pref1f6", FT_BOOLEAN, 8, NULL, 1 << 6, NULL, HFILL }
		},
		{ &hf_ant_pref1f7,
			{ "Prefs1 bit 7 (Zones)", "ant.pref1f7", FT_BOOLEAN, 8, NULL, 1 << 7, NULL, HFILL }
		},
		{ &hf_ant_pref2f0,
			{ "Prefs2 bit 0 (Zones alm)", "ant.pref2f0", FT_BOOLEAN, 8, NULL, 1 << 0, NULL, HFILL }
		},
		{ &hf_ant_pref2f1,
			{ "Prefs2 bit 1 (Zones run)", "ant.pref2f1", FT_BOOLEAN, 8, NULL, 1 << 1, NULL, HFILL }
		},
		{ &hf_ant_pref2f2,
			{ "Prefs2 bit 2 (Zones hrm)", "ant.pref2f2", FT_BOOLEAN, 8, NULL, 1 << 2, NULL, HFILL }
		},
		{ &hf_ant_pref2f3,
			{ "Prefs2 bit 3", "ant.pref2f3", FT_BOOLEAN, 8, NULL, 1 << 3, NULL, HFILL }
		},
		{ &hf_ant_pref2f4,
			{ "Prefs2 bit 4", "ant.pref2f4", FT_BOOLEAN, 8, NULL, 1 << 4, NULL, HFILL }
		},
		{ &hf_ant_pref2f5,
			{ "Prefs2 bit 5", "ant.pref2f5", FT_BOOLEAN, 8, NULL, 1 << 5, NULL, HFILL }
		},
		{ &hf_ant_pref2f6,
			{ "Prefs2 bit 6", "ant.pref2f6", FT_BOOLEAN, 8, NULL, 1 << 6, NULL, HFILL }
		},
		{ &hf_ant_pref2f7,
			{ "Prefs2 bit 7", "ant.pref2f7", FT_BOOLEAN, 8, NULL, 1 << 7, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ant,
		&ett_ant_data,
		&ett_msg_fragment,
		&ett_msg_fragments,
	};

	proto_ant = proto_register_protocol("ANT", "ANT", "ant");

	proto_register_field_array(proto_ant, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ant_module = prefs_register_protocol(proto_ant,
	    proto_reg_handoff_ant);
}

void
proto_reg_handoff_ant(void)
{
	static gboolean initialised = FALSE;
	static dissector_handle_t ant_handle;

	if (!initialised) {
		ant_handle = new_create_dissector_handle(dissect_ant,
								 proto_ant);
		dissector_add("usb.bulk", 0xffff, ant_handle);
		dissector_add("usb.bulk", 0xff, ant_handle);

		//msg_init_protocol();
		register_init_routine(msg_init_protocol);

		initialised = TRUE;
	} else {
		/* ?? */
	}
}
