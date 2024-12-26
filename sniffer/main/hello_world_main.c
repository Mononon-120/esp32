#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (14)

#define WLAN_FC_GET_STYPE(fc)  (((fc) & 0x00f0) >> 4)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc = "JP", .schan = 1, .nchan = 14}; //Most recent esp32 library struct

typedef struct {
  unsigned frame_ctrl: 16;
  unsigned duration_id: 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl: 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void wifi_sniffer_init(void) {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );

  wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
}

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch (type) {
    case WIFI_PKT_MGMT:
      return "MGMT";
    case WIFI_PKT_DATA:
      return "DATA";
    default:
    case WIFI_PKT_MISC:
      return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // not beacon
  if (WLAN_FC_GET_STYPE(hdr->frame_ctrl) != 0x08) {
    return;
  }

  char ssid[33];
  memset(ssid, 0, sizeof(ssid));
  memcpy(ssid, &ipkt->payload[6], ipkt->payload[5]);

  printf("PACKET FC=%04x, TYPE=%s, STYPE=%02x, CHAN=%02d, RSSI=%02d,"
         " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
         " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
         " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x,"
         " ADDR4=%02x:%02x:%02x:%02x:%02x:%02x,"
         " SSID=%s\n",
         hdr->frame_ctrl,
         wifi_sniffer_packet_type2str(type),
         WLAN_FC_GET_STYPE(hdr->frame_ctrl),
         ppkt->rx_ctrl.channel,
         ppkt->rx_ctrl.rssi,
         /* ADDR1 */
         hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
         hdr->addr1[3], hdr->addr1[4], hdr->addr1[5],
         /* ADDR2 */
         hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
         hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
         /* ADDR3 */
         hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
         hdr->addr3[3], hdr->addr3[4], hdr->addr3[5],
         /* ADDR4 */
         hdr->addr4[0], hdr->addr4[1], hdr->addr4[2],
         hdr->addr4[3], hdr->addr4[4], hdr->addr4[5],
         ssid
        );
}

// the setup function runs once when you press reset or power the board
void setup() {
  Serial.begin(115200);
  delay(10);
  wifi_sniffer_init();
}

// the loop function runs over and over again forever
void loop() {
  delay(WIFI_CHANNEL_SWITCH_INTERVAL);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
}
