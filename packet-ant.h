/*
 * Copyright 2009 `date +paul@ant%m%y.sbrk.co.uk`
 * Released under GPLv3
 */
#define ANT_MIN_LEN	4	// maybe 6
#define MESG_TX_SYNC	0xa4

#define MAXCHAN		8

#define SYNC_OFFSET	0
#define LEN_OFFSET	1
#define MSGID_OFFSET	2
#define CHAN_OFFSET	3
#define DEVTYPE_OFFSET	6
#define PERIOD_OFFSET	4
#define RMSG_OFFSET	4

#define RR_OFFSET	8
#define SEQ_OFFSET	10

#define SUU_RR_OFFSET	2
#define SUU_NRR_OFFSET	4
#define SUU_PRR_OFFSET	6

/* power */
#define R1_OFFSET	5
#define R2_OFFSET	6
#define N_OFFSET	7
#define P_OFFSET	8
#define T_OFFSET	10

/* bike */
#define CT_OFFSET	4
#define CR_OFFSET	6
#define WT_OFFSET	8
#define WR_OFFSET	10

#define EXT_ADD	4 /* additional length of extended data xmit */

#define MESG_ACKNOWLEDGED_DATA_ID       0x4f
#define MESG_ASSIGN_CHANNEL_ID          0x42
#define MESG_BROADCAST_DATA_ID          0x4e
#define MESG_BURST_DATA_ID              0x50
#define MESG_CONFIG_LIST_ID             0x5a
#define MESG_CAPABILITIES_ID            0x54
#define MESG_CHANNEL_ID_ID              0x51
#define MESG_CHANNEL_MESG_PERIOD_ID     0x43
#define MESG_CHANNEL_RADIO_FREQ_ID      0x45
#define MESG_CHANNEL_SEARCH_TIMEOUT_ID  0x44
#define MESG_CHANNEL_STATUS_ID          0x52
#define MESG_CHANNEL_SEARCH_PRIORITY_ID 0x75
#define MESG_LIB_CONFIG_ID              0x6e
#define MESG_ADD_ENCRYPTION_ID_ID       0x59
#define MESG_START_UP_ID                0x6f
#define MESG_SERIAL_ERROR_ID            0xae
#define MESG_ANT_VERSION_ID             0x3e
#define MESG_PROXIMITY_SEARCH_ID        0x71
#define MESG_LOW_PRIORITY_TIMEOUT_ID    0x63
#define MESG_CLOSE_CHANNEL_ID           0x4c
#define MESG_EXT_ACKNOWLEDGED_DATA_ID   0x5e
#define MESG_EXT_BROADCAST_DATA_ID      0x5d
#define MESG_EXT_BURST_DATA_ID          0x5f
#define MESG_NETWORK_KEY_ID             0x46
#define MESG_OPEN_CHANNEL_ID            0x4b
#define MESG_OPEN_RX_SCAN_ID            0x5b
#define MESG_REQUEST_ID                 0x4d
#define MESG_RESPONSE_EVENT_ID          0x40
#define MESG_SEARCH_WAVEFORM_ID         0x49
#define MESG_SYSTEM_RESET_ID            0x4a
#define MESG_TX_SYNC                    0xa4
#define MESG_UNASSIGN_CHANNEL_ID        0x41
#define RESPONSE_NO_ERROR               0x00
#define EVENT_RX_FAIL                   0x02

#if 0
#define DEVTYPE_HRM	0x78	/* ANT+ HRM */
#define DEVTYPE_BIKE	0x79	/* ANT+ Bike speed and cadence */
#define DEVTYPE_FOOT	0x7c	/* ANT+ Foot pod */
#define DEVTYPE_PWR	0xb	/* ANT+ Power meter */
#define DEVTYPE_HEAD	0x1	/* Garmin head unit (FR50/705/310xt etc) */
#endif

#define DEVTYPE_SUUHRM	0x4	/* Suunto HRM */

#define DEVTYPE_ANTFS			1
#define DEVTYPE_BIKE_POWER              11
#define DEVTYPE_ENVIRONMENT_SENSOR      12
#define DEVTYPE_FITNESS_EQUIPMENT       17
#define DEVTYPE_WEIGHT_SCALE            119
#define DEVTYPE_HRM                     120
#define DEVTYPE_BIKE_SPEED_CADENCE      121
#define DEVTYPE_BIKE_CADENCE            122
#define DEVTYPE_BIKE_SPEED              123
#define DEVTYPE_SDM                     124


#define ANTP_MASK			G_GINT64_CONSTANT(0xA8A4202835524141U)
#define SUUNTO_KEY			G_GINT64_CONSTANT(0xb9ad3228757ec74dU)
#define	GMNHU_KEY			G_GINT64_CONSTANT(0xa8a423b9f55e63c1U)
#define	ANTP_KEY			G_GINT64_CONSTANT(0xb9a521fbbd72c345U)

/* vim: se ic ai sw=8 ts=8: */

