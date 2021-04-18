
#include <config.h>
#include <epan/packet.h>
#include <stdio.h>

#define NAMES_END { 0x00, NULL }

// "this" as handles
static int proto_nxbt = -1;
static gint ett_nxbt = -1;

//static dissector_table_t mcu_dissector_table;

/**
 * How to extend this:
 * Field xyz is not shown in Wireshark:
 * - add a handle
 * - add a register
 * - add the register to the list in proto_register
 * - call proto_tree_add_item at some point
 * - don't fuck up the cursor
 */

#define NEW_FIELD(HANDLE, NAME, ABBREV, TYPE, DISPLAY, VALUE_NAMES, BITMASK, DESC) \
    static int HANDLE = -1; \
    static const hf_register_info HANDLE ## _register = { \
        &HANDLE, \
        { \
            NAME, ABBREV, \
            TYPE, DISPLAY, \
            VALUE_NAMES, BITMASK, \
            DESC, HFILL \
        } \
    }

#define NEW_NUMBER_FIELD(HANDLE, NAME, ABBREV, TYPE, DISPLAY) \
    NEW_FIELD(HANDLE, NAME, ABBREV, TYPE, DISPLAY, NULL, 0x0, NULL)

#define NEW_STRING_FIELD(HANDLE, NAME, ABBREV, TYPE, STRINGS) \
    NEW_FIELD(HANDLE, NAME, ABBREV, TYPE, BASE_HEX, VALS(STRINGS), 0x0, NULL)

#define NEW_NONE_FIELD(HANDLE, NAME, ABBREV) \
    NEW_FIELD(HANDLE, NAME, ABBREV, FT_NONE, ENC_NA, NULL, 0x0, NULL)

#define NEW_BYTES_FIELD(HANDLE, NAME, ABBREV) \
    NEW_FIELD(HANDLE, NAME, ABBREV, FT_BYTES, SEP_SPACE, NULL, 0x0, NULL)

#define NEW_FLAG_FIELD(HANDLE, NAME, ABBREV, TOTAL_BITS, STRINGS, MASK) \
    NEW_FIELD(HANDLE, NAME, ABBREV, FT_BOOLEAN, TOTAL_BITS, TFS(&STRINGS), MASK, NULL)

#define NEW_MASKED_NUMBER_FIELD(HANDLE, NAME, ABBREV, TYPE, DISPLAY, MASK) \
    NEW_FIELD(HANDLE, NAME, ABBREV, TYPE, DISPLAY, NULL, MASK, NULL)

////////////////////////////////////////////////////////////////////////////////
// GENERAL HEADER
////////////////////////////////////////////////////////////////////////////////

/* turns out this is actually some L2cap-stuff and actually a bit field */
static const value_string direction_names[] = {
  { 0xa2, "Output" },
  { 0xa1, "Input"},
  NAMES_END
};
NEW_STRING_FIELD(hf_direction, "first byte", "nxbt.first", FT_UINT8, direction_names);

static const value_string type_names[] = {
  // Output types
    { 0x01, "Rumble and subc" },
    { 0x03, "NFC/IR Update" },
    { 0x10, "Rumble" },
    { 0x11, "Rumble and NFC/IR request" },
    { 0x12, "Unknown, similar to 0x28" },

  //Input types
    { 0x21, "subc reply"},
    { 0x23, "MCU firmware update"},
    { 0x30, "Standard input record"},
    { 0x31, "input and MCU data"},
    { 0x32, "Unknown, looks standard"},
    { 0x33, "Unknown, looks standard"},
    { 0x3F, "Pure BT HID"},
    NAMES_END
};
NEW_STRING_FIELD(hf_type, "Report type", "nxbt.type", FT_UINT8, type_names);

NEW_NUMBER_FIELD(hf_timer, "timer", "nxbt.timer", FT_UINT8, BASE_HEX);

////////////////////////////////////////////////////////////////////////////////
// CONTROLLER STATE - BUTTONS, BATTERY, ETC.
////////////////////////////////////////////////////////////////////////////////
#ifdef TRUE

NEW_NONE_FIELD(state, "Controller state", "nxbt.state");
static int state_tree_h = -1;

#define BATTERY_LEVEL_MASK (0b111 << 5)
NEW_MASKED_NUMBER_FIELD(battery, "battery level", "nxbt.state.battery", FT_UINT8, BASE_HEX, BATTERY_LEVEL_MASK);

#define CHARGING_FLAG (1 << 4)
static const true_false_string charging_names = {
    "Charging",
    "Discharging"
};
NEW_FLAG_FIELD(charging, "charging", "nxbt.state.charging", 8, charging_names, CHARGING_FLAG);

#define POWERSOURCE_FLAG 1
static const true_false_string powersource_names = {
    "external",
    "internal"
};
NEW_FLAG_FIELD(powersource, "powersource", "nxbt.state.powersrc", 8, powersource_names, POWERSOURCE_FLAG);

NEW_NONE_FIELD(buttons, "Buttons", "nxbt.btn");
static int buttons_tree_h = -1;

static const true_false_string button_names = {
    "down",
    "up"
};

#define BUTTON_Y_FLAG 0b10000000
NEW_FLAG_FIELD(button_y, "Y-button", "nxbt.btn.y", 8, button_names, BUTTON_Y_FLAG);

#define BUTTON_X_FLAG 0b1000000
NEW_FLAG_FIELD(button_x, "X-button", "nxbt.btn.x", 8, button_names, BUTTON_X_FLAG);

#define BUTTON_B_FLAG 0b1000000
NEW_FLAG_FIELD(button_b, "B-button", "nxbt.btn.b", 8, button_names, BUTTON_B_FLAG);

#define BUTTON_A_FLAG 0b100000
NEW_FLAG_FIELD(button_a, "A-button", "nxbt.btn.a", 8, button_names, BUTTON_A_FLAG);

#define BUTTON_RSR_FLAG 0b1000
NEW_FLAG_FIELD(button_rsr, "Right SR-button", "nxbt.btn.rsr", 8, button_names, BUTTON_RSR_FLAG);

#define BUTTON_RSL_FLAG 0b100
NEW_FLAG_FIELD(button_rsl, "Right SL-button", "nxbt.btn.rsl", 8, button_names, BUTTON_RSL_FLAG);

#define BUTTON_R_FLAG 0b10
NEW_FLAG_FIELD(button_r, "R-button", "nxbt.btn.r", 8, button_names, BUTTON_R_FLAG);

#define BUTTON_ZR_FLAG 0b1
NEW_FLAG_FIELD(button_zr, "ZR-button", "nxbt.btn.zr", 8, button_names, BUTTON_ZR_FLAG);

#define BUTTON_MINUS_FLAG 0b10000000
NEW_FLAG_FIELD(button_minus, "Minus-button", "nxbt.btn.minus", 8, button_names, BUTTON_MINUS_FLAG);

#define BUTTON_PLUS_FLAG 0b1000000
NEW_FLAG_FIELD(button_plus, "Plus-button", "nxbt.btn.plus", 8, button_names, BUTTON_PLUS_FLAG);

#define BUTTON_RSTICK_FLAG 0b100000
NEW_FLAG_FIELD(button_rstick, "Stick R-button", "nxbt.btn.rstick", 8, button_names, BUTTON_RSTICK_FLAG);

#define BUTTON_LSTICK_FLAG 0b10000
NEW_FLAG_FIELD(button_lstick, "Stick L-button", "nxbt.btn.lstick", 8, button_names, BUTTON_LSTICK_FLAG);

#define BUTTON_HOME_FLAG 0b1000
NEW_FLAG_FIELD(button_home, "Home-button", "nxbt.btn.home", 8, button_names, BUTTON_HOME_FLAG);

#define BUTTON_CAPTURE_FLAG 0b100
NEW_FLAG_FIELD(button_capture, "Capture-button", "nxbt.btn.capture", 8, button_names, BUTTON_CAPTURE_FLAG);

#define BUTTON_CHARGEGRIP_FLAG 0b1
NEW_FLAG_FIELD(button_chargegrip, "Charging-Grip", "nxbt.btn.chargegrip", 8, button_names, BUTTON_CHARGEGRIP_FLAG);

#define BUTTON_DOWN_FLAG 0b10000000
NEW_FLAG_FIELD(button_down, "Down-button", "nxbt.btn.down", 8, button_names, BUTTON_DOWN_FLAG);

#define BUTTON_UP_FLAG 0b1000000
NEW_FLAG_FIELD(button_up, "Up-button", "nxbt.btn.up", 8, button_names, BUTTON_UP_FLAG);

#define BUTTON_RIGHT_FLAG 0b100000
NEW_FLAG_FIELD(button_right, "Right-button", "nxbt.btn.right", 8, button_names, BUTTON_RIGHT_FLAG);

#define BUTTON_LEFT_FLAG 0b10000
NEW_FLAG_FIELD(button_left, "Left-button", "nxbt.btn.left", 8, button_names, BUTTON_LEFT_FLAG);

#define BUTTON_LSR_FLAG 0b1000
NEW_FLAG_FIELD(button_lsr, "Left SR-button", "nxbt.btn.lsr", 8, button_names, BUTTON_LSR_FLAG);

#define BUTTON_LSL_FLAG 0b100
NEW_FLAG_FIELD(button_lsl, "LEFT SL-button", "nxbt.btn.lsl", 8, button_names, BUTTON_LSL_FLAG);

#define BUTTON_L_FLAG 0b10
NEW_FLAG_FIELD(button_l, "L-button", "nxbt.btn.l", 8, button_names, BUTTON_L_FLAG);

#define BUTTON_ZL_FLAG 0b1
NEW_FLAG_FIELD(button_zl, "ZL-button", "nxbt.btn.zl", 8, button_names, BUTTON_ZL_FLAG);

NEW_BYTES_FIELD(stick_l, "left stick", "nxbt.stick.l");

NEW_BYTES_FIELD(stick_r, "right stick", "nxbt.stick.r");

NEW_NUMBER_FIELD(rumble_in, "rumble input report", "nxbt.state.rumble", FT_UINT8, BASE_HEX);

static int dissect_state(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  proto_item* state_item = proto_tree_add_none_format(nxbt_tree, state, tvb, cursor, 1+3+3+3+1, "Controller state");
  proto_tree* state_tree = proto_item_add_subtree(state_item, state_tree_h);
  proto_tree_add_item(state_tree, battery, tvb, cursor, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(state_tree, charging, tvb, cursor, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(state_tree, powersource, tvb, cursor++, 1, ENC_BIG_ENDIAN);
	{ // buttons
		guint8 buttons_l = tvb_get_guint8(tvb, cursor);
		guint8 buttons_b = tvb_get_guint8(tvb, cursor+1);
		guint8 buttons_r = tvb_get_guint8(tvb, cursor+2);

		proto_item* buttons_item = proto_tree_add_none_format(state_tree, buttons, tvb, cursor, 3, "Buttons: [%s%s%s%s%s%s%s%s%s%s%s%s%s%s_%s%s%s%s%s%s%s%s%s]",
			buttons_l & BUTTON_Y_FLAG ? "Y" : " ",
			buttons_l & BUTTON_X_FLAG ? "X" : " ",
			buttons_l & BUTTON_B_FLAG ? "B" : " ",
			buttons_l & BUTTON_A_FLAG ? "A" : " ",
			buttons_l & BUTTON_RSR_FLAG ? "r" : " ",
			buttons_l & BUTTON_RSL_FLAG ? "l" : " ",
			buttons_l & BUTTON_R_FLAG ? "R" : " ",
			buttons_l & BUTTON_ZR_FLAG ? "Z" : " ",
			buttons_b & BUTTON_MINUS_FLAG ? "-" : " ",
			buttons_b & BUTTON_PLUS_FLAG ? "+" : " ",
			buttons_b & BUTTON_RSTICK_FLAG ? "RS" : " ",
			buttons_b & BUTTON_LSTICK_FLAG ? "LS" : " ",
			buttons_b & BUTTON_HOME_FLAG ? "H" : " ",
			buttons_b & BUTTON_CAPTURE_FLAG ? "C" : " ",
			buttons_b & BUTTON_CHARGEGRIP_FLAG ? "G" : " ",
			buttons_r & BUTTON_DOWN_FLAG ? "v" : " ",
			buttons_r & BUTTON_UP_FLAG ? "^" : " ",
			buttons_r & BUTTON_RIGHT_FLAG ? ">" : " ",
			buttons_r & BUTTON_LEFT_FLAG ? "<" : " ",
			buttons_r & BUTTON_LSR_FLAG ? "r" : " ",
			buttons_r & BUTTON_LSL_FLAG ? "l" : " ",
			buttons_r & BUTTON_L_FLAG ? "L" : " ",
			buttons_r & BUTTON_ZL_FLAG ? "ZL" : " "
		);
		proto_tree* buttons_tree = proto_item_add_subtree(buttons_item, buttons_tree_h);

		int* buttons_arr[3][8] = {
			{
				&button_y,
				&button_x,
				&button_b,
				&button_a,
				&button_rsr,
				&button_rsl,
				&button_r,
				&button_zr
			}, {
				&button_minus,
				&button_plus,
				&button_rstick,
				&button_lstick,
				&button_home,
				&button_capture,
				NULL,
				&button_chargegrip
			}, {
				&button_down,
				&button_up,
				&button_right,
				&button_left,
				&button_lsr,
				&button_lsl,
				&button_l,
				&button_zl
			}
		};
		for (int s = 0; s < 3; ++s) {
			for (int b = 0; b < 8; ++b) {
				if (buttons_arr[s][b]) {
					proto_tree_add_item(buttons_tree, *(buttons_arr[s][b]), tvb, cursor, 1, ENC_BIG_ENDIAN);
				}
			}
			++cursor;
		}
	}

  proto_tree_add_item(state_tree, stick_l, tvb, cursor, 3, ENC_BIG_ENDIAN);
  cursor += 3;
  proto_tree_add_item(state_tree, stick_r, tvb, cursor, 3, ENC_BIG_ENDIAN);
  cursor +=3;
	proto_tree_add_item(state_tree, rumble_in, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  return ++cursor;
}

#endif

////////////////////////////////////////////////////////////////////////////////
// RUMBLE OUTPUT DATA
////////////////////////////////////////////////////////////////////////////////
#ifdef TRUE

NEW_NONE_FIELD(rumble, "Rumble data", "nxbt.rumble");
static int rumble_tree_h = -1;

NEW_NUMBER_FIELD(rumble_left, "Left rumble", "nxbt.rumble.left", FT_UINT32, BASE_HEX);

NEW_NUMBER_FIELD(rumble_right, "Left rumble", "nxbt.rumble.right", FT_UINT32, BASE_HEX);

static int dissect_rumble(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  proto_item* rumble_item = proto_tree_add_none_format(nxbt_tree, rumble, tvb, cursor, 8, "Rumble data");
  proto_tree* rumble_tree = proto_item_add_subtree(rumble_item, rumble_tree_h);
  proto_tree_add_item(rumble_tree, rumble_left, tvb, cursor, 4, ENC_BIG_ENDIAN);
  cursor += 4;
  proto_tree_add_item(rumble_tree, rumble_right, tvb, cursor, 4, ENC_BIG_ENDIAN);
  col_set_str(pinfo->cinfo, COL_INFO, "rumble data");
  return cursor + 4;
}
#endif

////////////////////////////////////////////////////////////////////////////////
// INDIVIDUAL SUBCOMMANDS
////////////////////////////////////////////////////////////////////////////////
#ifdef TRUE
// SPI READ & WRITES, IN & OUT
NEW_NUMBER_FIELD(spi_address, "Address", "nxbt.sub.spi.address", FT_UINT32, BASE_HEX);

NEW_NUMBER_FIELD(spi_length, "Amount", "nxbt.sub.spi.length", FT_UINT8, BASE_DEC);

NEW_BYTES_FIELD(spi_data, "data", "nxbt.sub.spi.data");

static int dissect_spi(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, uint cursor, char has_data) {
  proto_tree_add_item(tree, spi_address, tvb, cursor, 4, ENC_LITTLE_ENDIAN);
  cursor += 4;
  proto_tree_add_item(tree, spi_length, tvb, cursor++, 1, ENC_LITTLE_ENDIAN);
  if (has_data) {
    guint8 length = tvb_get_guint8(tvb, cursor-1);
    proto_tree_add_item(tree, spi_data, tvb, cursor, length, ENC_LITTLE_ENDIAN);
    cursor += length;
  }
  return cursor;
}


// subcommands
NEW_NONE_FIELD(subc, "Subcommand", "nxbt.sub");
static int subc_tree_h = -1;

static const value_string subc_c_names[] = {
  { 0x01, "Manual Pairing"},
  { 0x02, "Get device info"},
  { 0x03, "Set input Mode"},
  { 0x04, "Trigger buttons elapsed time"},
  { 0x05, "Get page list state"},
  { 0x06, "Set HCI state"},
  { 0x07, "Reset pairing info"},
  { 0x08, "Set shipment low power state"},
  { 0x10, "SPI flash read"},
  { 0x11, "SPI flash Write"},
  { 0x12, "SPI sector erase"},
  { 0x20, "Reset NFC/IR MCU"},
  { 0x21, "Set NFC/IR MCU configuration"},
  { 0x22, "Set NFC/IR MCU state"},
  { 0x24, "Set unknown data (fw 3.86 and up)"},
  { 0x25, "Reset 0x24 unknown data (fw 3.86 and up)"},
  { 0x28, "Set unknown NFC/IR MCU data A"},
  { 0x29, "Get unknown NFC/IR MCU data A"},
  { 0x2A, "Set GPIO Pin Output value (2 @Port 2)"},
  { 0x2B, "Get x29 NFC/IR MCU data"},
  { 0x30, "Set player lights"},
  { 0x31, "Get player lights"},
  { 0x38, "Set HOME Light"},
  { 0x40, "Enable IMU (6-Axis sensor)"},
  { 0x41, "Set IMU sensitivity"},
  { 0x42, "Write to IMU registers"},
  { 0x43, "Read IMU registers"},
  { 0x48, "Enable vibration"},
  { 0x50, "Get regulated voltage"},
  { 0x51, "Set GPIO Pin Output value (7 & 15 @Port 1)"},
  { 0x52, "Get GPIO Pin Input/Output value"},
  NAMES_END
};
NEW_STRING_FIELD(subc_c, "Subcommand", "nxbt.sub.c", FT_UINT8, subc_c_names);

// set mcu config
static const value_string mcu_power_state_names[] = {
  { 0x00, "Suspended" },
  { 0x01, "Ready" },
  { 0x02, "Ready for Update" },
  { 0x04, "Configured NFC" },
  { 0x05, "Configured IR" },
  { 0x06, "Configured Update" },
  NAMES_END
};
NEW_STRING_FIELD(subc_mcu_config, "Powerstate configuration", "nxbt.sub.mcu.config", FT_UINT8, mcu_power_state_names);

//set mcu state
static const value_string mcu_state_names[] = {
  { 0x00, "Suspended"},
  { 0x01, "Active"},
  { 0x02, "Active for Update"},
  NAMES_END
};
NEW_STRING_FIELD(subc_MCU_state, "State to go into", "nxbt.sub.mcu.state", FT_UINT8, mcu_state_names);

//set player lights
NEW_NUMBER_FIELD(subc_player_lights, "Player Lights", "nxbt.sub.player", FT_UINT8, BASE_OCT);

//set input report type
NEW_STRING_FIELD(subc_type, "Report type to switch to", "nxbt.sub.type", FT_UINT8, type_names);

static int dissect_subc(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  uint start = cursor;
  proto_item* subc_item = proto_tree_add_none_format(nxbt_tree, subc, tvb, cursor, -1, "Subcommand %s", val_to_str(subc_c, subc_c_names, "unknown %04x"));
  proto_tree* subc_tree = proto_item_add_subtree(subc_item, subc_tree_h);

	guint8 command = tvb_get_guint8(tvb, cursor);
	proto_tree_add_item(subc_tree, subc_c, tvb, cursor++, 1, ENC_BIG_ENDIAN);
	guint8 arg = tvb_get_guint8(tvb, cursor);

	col_set_str(pinfo->cinfo, COL_INFO, val_to_str(command, subc_c_names, "unknown Subcommand %04x"));
	switch (command) {
    case 0x03: // set input mode
      proto_tree_add_item(subc_tree, subc_type, tvb, cursor++, 1, ENC_BIG_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, " Mode %s", val_to_str(arg, type_names, "unknown %04x"));
      break;
    case 0x10: //SPI read
    case 0x11: //SPI write
      cursor = dissect_spi(tvb, pinfo, subc_tree, data, cursor, command == 0x11);
      break;
    case 0x20: //reset MCU
      break;
    case 0x21: //set MCU config
      cursor += 2;
      proto_tree_add_item(subc_tree, subc_mcu_config, tvb, cursor++, 1, ENC_LITTLE_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, " Config %s", val_to_str(arg, mcu_power_state_names, "unknown %04x"));
      cursor += 34;
      break;
    case 0x22: // Set MCU state
      proto_tree_add_item(subc_tree, subc_MCU_state, tvb, cursor++, 1, ENC_BIG_ENDIAN);
			col_add_fstr(pinfo->cinfo, COL_INFO, " Config %s", val_to_str(arg, mcu_state_names, "unknown %04x"));
      break;
    case 0x30: // set player lights
      proto_tree_add_item(subc_tree, subc_player_lights, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      break;
  }
  proto_item_set_len(subc_item, cursor - start);

  return cursor;
}



// subcommand replies
NEW_NONE_FIELD(rep, "Subcommand Reply", "nxbt.rep");
static int rep_tree_h = -1;

#define REP_ACK_FLAG (1 << 7)
static const true_false_string rep_ack_names = {
    "ACK",
    "NACK"
};
NEW_FLAG_FIELD(rep_ack, "ack flag", "nxbt.rep.ack", 8, rep_ack_names, REP_ACK_FLAG);

#define REP_DTYPE_MASK ((guint8) ~REP_ACK_FLAG)
NEW_MASKED_NUMBER_FIELD(rep_dtype, "reply dtype", "nxbt.rep.dtype", FT_UINT8, BASE_HEX, REP_DTYPE_MASK);

NEW_STRING_FIELD(rep_subc, "response to", "nxbt.rep.sub", FT_UINT8, subc_c_names);

static int dissect_subc_reply(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  guint8 ack = tvb_get_guint8(tvb, cursor) & REP_ACK_FLAG;
  guint8 command = tvb_get_guint8(tvb, cursor + 1);
  proto_item* rep_item = proto_tree_add_none_format(nxbt_tree, rep, tvb, cursor, 8,
     "Subcommand %s %s",
		 val_to_str(command, subc_c_names, "unknown subcommand %04x"),
		 ack ? "ACK" : "NACK"
	);
  proto_tree* rep_tree = proto_item_add_subtree(rep_item, rep_tree_h);
  proto_tree_add_item(rep_tree, rep_ack, tvb, cursor, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(rep_tree, rep_dtype, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(rep_tree, rep_subc, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  switch (command) {
    case 0x10:
    case 0x11:
      cursor = dissect_spi(tvb, pinfo, rep_tree, data, cursor, command != 0x11);
      break;
  }
  col_add_fstr(pinfo->cinfo, COL_INFO, ack ? "ACK %s" : "NACK %s",
			val_to_str(command, subc_c_names, "unknown subcommand %04x")
	);
  cursor += 34;
  return cursor;
}
#endif

////////////////////////////////////////////////////////////////////////////////
// MCU
////////////////////////////////////////////////////////////////////////////////
#ifdef TRUE

// General MCU stuff
NEW_NONE_FIELD(mcu, "MCU Data", "nxbt.mcu");
static int mcu_tree_h = -1;

// command and first are identical just on different sides
static const value_string mcu_c_names[] = {
  {0x01, "Status request"},
  {0x02, "NFC subsubcommand"},
  NAMES_END
};
NEW_STRING_FIELD(mcu_c, "command", "nxbt.mcu.c", FT_UINT8, mcu_c_names);

static const value_string mcu_first_names[] = {
  {0x01, "MCU status"},
  {0x2a, "NFC status"},
  {0x3a, "NFC data buffered"},
  {0xff, "No response/MCU disabled"},
  NAMES_END
};
NEW_STRING_FIELD(mcu_first, "type of MCU message", "nxbt.mcu.first", FT_UINT8, mcu_first_names);

NEW_NUMBER_FIELD(mcu_seqno, "Sequence number", "nxbt.mcu.seq", FT_UINT8, BASE_DEC);

NEW_NUMBER_FIELD(mcu_ackseqno, "Acked sequence number", "nxbt.mcu.ackseqno", FT_UINT8, BASE_DEC);

#define MCUC_EOT_FLAG 0x08
static const true_false_string mcu_eot_names = {
    "EOT",
    "MORE"
};
NEW_FLAG_FIELD(mcu_eot, "eot flag", "nxbt.mcu.eot", 8, mcu_eot_names, MCUC_EOT_FLAG);

NEW_NUMBER_FIELD(mcu_payload_len, "Payload length", "nxbt.mcu.data.len", FT_UINT8, BASE_DEC);

NEW_BYTES_FIELD(mcu_payload_data, "Payload data", "nxbt.mcu.data");

NEW_NUMBER_FIELD(mcu_crc, "MCU crc", "nxbt.mcu.crc", FT_UINT8, BASE_HEX);

NEW_BYTES_FIELD(mcu_nfc_uuid, "UUID of tag", "nxbt.mcu.nfc.uuid");

// MCU out
static const value_string mcu_nfcc_names[] = {
  {0x01, "Start Polling"},
  {0x02, "Stop Polling"},
  {0x04, "Get next Data / Status"},
  {0x06, "Read and buffer NTag"},
  {0x08, "Write to NTag"},
  {0x0f, "Read mifare data"},
  NAMES_END
};
NEW_STRING_FIELD(mcu_nfcc, "Subcommand for NFC", "nxbt.mcu.nfc.c", FT_UINT8, mcu_nfcc_names);

static int dissect_mcu_out(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  uint start = cursor;
  proto_item* mcu_item = proto_tree_add_none_format(nxbt_tree, mcu, tvb, cursor, -1, "Mcu Command");
  proto_tree* mcu_tree = proto_item_add_subtree(mcu_item, mcu_tree_h);
  guint8 command = tvb_get_guint8(tvb, cursor);
  proto_tree_add_item(mcu_tree, mcu_c, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  if (command == 0x02) { // NFC
    guint8 nfc_command = tvb_get_guint8(tvb, cursor);
    proto_tree_add_item(mcu_tree, mcu_nfcc, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    guint8 seqno = tvb_get_guint8(tvb, cursor);
    proto_tree_add_item(mcu_tree, mcu_seqno, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(mcu_tree, mcu_ackseqno, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(mcu_tree, mcu_eot, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    guint8 payload_len = tvb_get_guint8(tvb, cursor);
    proto_tree_add_item(mcu_tree, mcu_payload_len, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(mcu_tree, mcu_payload_data, tvb, cursor, payload_len, ENC_BIG_ENDIAN);
    if (seqno <= 1)
      proto_tree_add_item(mcu_tree, mcu_nfc_uuid, tvb, cursor + 2, 7, ENC_BIG_ENDIAN);
    cursor += 31;
    proto_tree_add_item(mcu_tree, mcu_crc, tvb, cursor++, 1, ENC_BIG_ENDIAN);
    col_add_fstr(pinfo->cinfo, COL_INFO, "MCU-NFC command %s", val_to_str(nfc_command, mcu_nfcc_names, "unknown 0x%02x"));
  } else {
    col_add_fstr(pinfo->cinfo, COL_INFO, "MCU command %s", val_to_str(command, mcu_c_names, "unknown 0x%02x"));
  }
  proto_item_set_len(mcu_item, cursor - start);
  return cursor;
}


// MCU in
NEW_STRING_FIELD(mcu_power_state, "MCU's powerstate", "nxbt.mcu.state", FT_UINT8, mcu_power_state_names);

//static int mcu_error = -1;

//static int mcu_nfc_type = -1;

static const value_string mcu_nfc_state_names[] = {
  { 0x00, "None" },
  { 0x01, "Polled" },
  { 0x02, "Buffered data / Pending read" },
  { 0x03, "[Buffering] Write to NTag"},
  { 0x05, "[Processing] Write to Ntag"},
  { 0x09, "Polled, found tag again" },
  NAMES_END
};
NEW_STRING_FIELD(mcu_nfc_state, "NFC subsystem state", "nxbt.mcu.nfc.state", FT_UINT8, mcu_nfc_state_names);

//NEW_NUMBER_FIELD(mcu_nfc_unknown_len, "Unknown NFC data length", "nxbt.mcu.nfc.unknown.len", FT_UINT8, BASE_DEC);

//NEW_NONE_FIELD(mcu_nfc_unknown_data, "Unknown NFC data", "nxbt.mcu.nfc.unknown");

NEW_NONE_FIELD(mcu_nfc_data, "Nfc tag data transmitted", "nxbt.mcu.nfc.data");

static int dissect_mcu_in(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* nxbt_tree _U_, void* data _U_, uint cursor) {
  proto_item* mcu_item = proto_tree_add_none_format(nxbt_tree, mcu, tvb, cursor, 313,
     "MCU response");
  proto_tree* mcu_tree = proto_item_add_subtree(mcu_item, mcu_tree_h);
  guint8 first = tvb_get_guint8(tvb, cursor);
  proto_tree_add_item(mcu_tree, mcu_first, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  guint8 tmp;
  guint8 seqno = 0;
  //guint8 mcu_seqno = 0;
  guint8 payload_len = 0;
  switch (first) {
    case 0x01:
      cursor += 6;
      tmp =  tvb_get_guint8(tvb, cursor); // power state
      proto_tree_add_item(mcu_tree, mcu_power_state, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      col_set_str(pinfo->cinfo, COL_INFO, "MCU status is ");
      col_add_str(pinfo->cinfo, COL_INFO, val_to_str(tmp, mcu_power_state_names, "unknown 0x%02x"));
      cursor += 304;
      break;
    case 0x2a:
    case 0x3a:
      cursor += 2;
      proto_tree_add_item(mcu_tree, mcu_seqno, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(mcu_tree, mcu_ackseqno, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(mcu_tree, mcu_eot, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      if (first == 0x3a)
        goto actual_0x3a;
      cursor += 1;
      tmp = tvb_get_guint8(tvb, cursor); // nfc state
      proto_tree_add_item(mcu_tree, mcu_nfc_state, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      cursor += 7;
      payload_len = tvb_get_guint8(tvb, cursor);
      proto_tree_add_item(mcu_tree, mcu_payload_len, tvb, cursor++, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(mcu_tree, mcu_nfc_uuid, tvb, cursor, 7, ENC_BIG_ENDIAN);
      cursor += 7;
      cursor += 289;
      col_clear(pinfo->cinfo, COL_INFO);
      col_add_fstr(pinfo->cinfo, COL_INFO,
          payload_len == 0 ? "NFC status %s" : "NFC status (%s) with payload",
          val_to_str(tmp, mcu_nfc_state_names, "unknown 0x%02x")
      );
      break;
    actual_0x3a:
      if (seqno == 1) {
        cursor += 1;
        proto_tree_add_item(mcu_tree, mcu_nfc_state, tvb, cursor++, 1, ENC_BIG_ENDIAN);
        cursor += 6;
        proto_tree_add_item(mcu_tree, mcu_payload_len, tvb, cursor++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mcu_tree, mcu_nfc_uuid, tvb, cursor, 7, ENC_BIG_ENDIAN);
        cursor += 7;
        cursor += 45;
        proto_tree_add_none_format(mcu_tree, mcu_nfc_data, tvb, cursor, 245, "Raw NFC tag data");
        cursor += 245;
        col_set_str(pinfo->cinfo, COL_INFO, "NFC read buffered data #1");
      } else if (seqno == 2) {
        cursor += 1;
        proto_tree_add_none_format(mcu_tree, mcu_nfc_data, tvb, cursor, 295, "Raw NFC tag data");
        cursor += 295;
        cursor += 11;
        col_set_str(pinfo->cinfo, COL_INFO, "NFC read buffered data #2");
      }
      break;
    case 0xff:
      cursor += 311;
      break;
  }
  proto_tree_add_item(mcu_tree, mcu_crc, tvb, cursor, 1, ENC_BIG_ENDIAN);
  return cursor;
}
#endif

static int dissect_nxbt(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NX BT");
  col_clear(pinfo->cinfo, COL_INFO);

  // the root node in the details view for our stuff
	proto_item* ti = proto_tree_add_item(tree, proto_nxbt, tvb, 0, -1, ENC_NA);
  proto_tree *nxbt_tree = proto_item_add_subtree(ti, ett_nxbt);

  unsigned int cursor = 0;

  // header
  proto_tree_add_item(nxbt_tree, hf_direction, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(nxbt_tree, hf_type, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(nxbt_tree, hf_timer, tvb, cursor++, 1, ENC_BIG_ENDIAN);
  guint type = tvb_get_guint8(tvb, 1);

  // Output
  if (type == 0x01 || type == 0x10 || type == 0x11) { //have rumble
    cursor = dissect_rumble(tvb, pinfo, nxbt_tree, data, cursor);
  }
  if (type == 0x01) {
    cursor = dissect_subc(tvb, pinfo, nxbt_tree, data, cursor);
    //proto_tree_add_item(nxbt_tree, subc_data, tvb, cursor, 1, ENC_BIG_ENDIAN);
  } else if (type == 0x11) {
    cursor = dissect_mcu_out(tvb, pinfo, nxbt_tree, data, cursor);
  }

  // Input
  if (type == 0x30 || type == 0x31 || type == 0x31 || type == 0x32) {
    cursor += dissect_state(tvb, pinfo, nxbt_tree, data, cursor);
  } else if (type == 0x21 || type == 0x23) { // no input data
    cursor += 1+3+3+3+1;
  }
  if (type == 0x21) { // subcommand reply
    cursor = dissect_subc_reply(tvb, pinfo, nxbt_tree, data, cursor);
  } else if (type == 0x23) {
    // NFC stuff
    cursor += 36;
  } else if (type == 0x30 || type == 0x31 || type == 0x32 || type == 0x33) {
    // TODO 6 Axis data
    cursor += 36;
  }
  if (type == 0x31) {
    cursor = dissect_mcu_in(tvb, pinfo, nxbt_tree, data, cursor);
  }
  return tvb_captured_length(tvb);
}

void proto_register_nxbt(void) {
  static hf_register_info fields[] = {
    hf_direction_register,
		hf_type_register,
    hf_timer_register,

		state_register,
		battery_register,
		charging_register,
		powersource_register,
		buttons_register,
		rumble_in_register,

		button_y_register,
		button_x_register,
		button_b_register,
		button_a_register,
		button_rsr_register,
		button_rsl_register,
		button_r_register,
		button_zr_register,
		button_minus_register,
		button_plus_register,
		button_rstick_register,
		button_lstick_register,
		button_home_register,
		button_capture_register,
		button_chargegrip_register,
		button_down_register,
		button_up_register,
		button_right_register,
		button_left_register,
		button_lsr_register,
		button_lsl_register,
		button_l_register,
		button_zl_register,

		stick_l_register,
		stick_r_register,

    rumble_register,
    rumble_left_register,
    rumble_right_register,

    spi_address_register,
    spi_length_register,
    spi_data_register,

    subc_register,
    subc_c_register,
    subc_mcu_config_register,
    subc_MCU_state_register,
    subc_player_lights_register,
    subc_type_register,

    rep_register,
    rep_ack_register,
    rep_dtype_register,
    rep_subc_register,

    mcu_register,
    mcu_c_register,
    mcu_first_register,
    mcu_seqno_register,
    mcu_ackseqno_register,
    mcu_eot_register,
    mcu_payload_len_register,
		mcu_payload_data_register,
    mcu_crc_register,

		mcu_nfc_uuid_register,

    mcu_nfcc_register,

    mcu_power_state_register,
    mcu_nfc_state_register,
    mcu_nfc_data_register,

	};

  static gint* trees[] = {
    &ett_nxbt,
		&state_tree_h,
		&buttons_tree_h,
    &rumble_tree_h,
    &subc_tree_h,
    &mcu_tree_h,
    &rep_tree_h,
  };
  printf("registered nxbt dissector\n");
	proto_nxbt = proto_register_protocol(
		"Nintendo Switch Bluetooth Controller Kommunikation",
		"NX_BT",
		"nxbt"
	);

  register_dissector("nxbt", dissect_nxbt, proto_nxbt);
  proto_register_field_array(proto_nxbt, fields, array_length(fields));
  proto_register_subtree_array(trees, array_length(trees));
}

void proto_reg_handoff_nxbt(void) {
	static dissector_handle_t nxbt_handle;
	nxbt_handle = create_dissector_handle(dissect_nxbt, proto_nxbt);
	//dissector_add_string("bluetooth.src", SWITCH_MAC, nxbl_handle);
	//dissector_add_string("bluetooth.dest", SWITCH_MAC, nxbl_handle);
	//dissector_add_uint("llc.bluetooth_pid", 1, nxbl_handle); // overwrite L2CAP
	dissector_add_uint("btl2cap.psm", 17, nxbt_handle);
	dissector_add_uint("btl2cap.psm", 19, nxbt_handle);
  dissector_add_uint("wtap_encap", 45, nxbt_handle);
  /*udp_dissector_table = register_dissector_table("nxbt.mcu",
                                                 "Communication to the MCU", proto_nxbt, FT_UINT16, BASE_DEC);*/
	//dissector_add_for_decode_as("btl2cap.cid", nxbt_handle);
}
