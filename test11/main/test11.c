#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <stdint.h>
// Wi-Fiフレームヘッダー構造体定義
typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6];  // 宛先MACアドレス
    uint8_t addr2[6];  // 送信元MACアドレス
    uint8_t addr3[6];  // フィルタリングアドレス
    unsigned sequence_ctrl:16;
    uint8_t addr4[6];  // オプション（アドホックなどの場合）
} wifi_ieee80211_mac_hdr_t;
typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];  // フレームデータ部分
} wifi_ieee80211_packet_t;
// IPヘッダー構造体定義
typedef struct {
    uint8_t version_ihl; // バージョンとヘッダー長
    uint8_t tos;         // サービス種別
    uint16_t total_length; // パケット全体の長さ
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;         // 生存時間
    uint8_t protocol;    // プロトコル
    uint16_t header_checksum;
    uint8_t src_ip[4];   // 送信元IPアドレス
    uint8_t dest_ip[4];  // 宛先IPアドレス
} ip_header_t;
// IPアドレスを表示する関数
void print_ip(const uint8_t *ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
// Wi-Fiパケットを処理するコールバック関数
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)pkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
    printf("\n--- Wi-Fi Packet Captured ---\n");
    printf("Destination MAC: ");
    print_mac(hdr->addr1);
    printf("\n");
    printf("Source MAC: ");
    print_mac(hdr->addr2);
    printf("\n");
    printf("BSSID: ");
    print_mac(hdr->addr3);
    printf("\n");
    // IPアドレスを取得（データフレームの場合のみ）
    if (type == WIFI_PKT_DATA) {
        const uint8_t *payload = ipkt->payload;
        const ip_header_t *ip_hdr = (ip_header_t *)(payload + sizeof(wifi_ieee80211_mac_hdr_t));
        printf("Source IP: ");
        print_ip(ip_hdr->src_ip);
        printf("\n");
        printf("Destination IP: ");
        print_ip(ip_hdr->dest_ip);
        printf("\n");
    }
}
// アプリケーションのエントリーポイント
void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    printf("Wi-Fi Sniffer Initialized.\n");
}
