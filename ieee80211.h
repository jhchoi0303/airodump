struct IEEE80211_request_header {
   uint16_t frame_control_field;
   uint16_t duration;
};

struct mac_address {
   uint8_t addr[6];
};

struct IEEE80211_address {
   mac_address receiver_address;
   mac_address transmitter_address;
   mac_address bss_id;
   uint16_t fragment_sequence_number;
};