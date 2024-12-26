#include <stdio.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
// ログレベル制御
#define DEBUG 0
#if DEBUG
    #define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
    #define LOG(fmt, ...)
#endif
// Wi-Fiフレームヘッダー構造体定義
typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    unsigned sequence_ctrl:16;
    uint8_t addr1[6];  // 宛先MACアドレス
    uint8_t addr2[6];  // 送信元MACアドレス
    uint8_t addr3[6];  // BSSID
} wifi_ieee80211_mac_hdr_t;
// MACアドレスを表示する関数
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
// フレームコントロールフィールド解析関数
void parse_frame_control(unsigned frame_ctrl) {
    unsigned frame_type = (frame_ctrl & 0x000C) >> 2;
    unsigned frame_subtype = (frame_ctrl & 0x00F0) >> 4;
    if (frame_type == 0 && frame_subtype == 8) { // ビーコンフレーム
        printf("Beacon Frame Captured\n");
    }
}
// パケット処理コールバック関数
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *raw_data = pkt->payload;
    //const wifi_ieee80211_mac_hdr_t *hdr = (wifi_ieee80211_mac_hdr_t *)raw_data;
    // フレームコントロール解析
    //parse_frame_control(hdr->frame_ctrl);
    // MACアドレス表示
    //printf("Destination MAC: ");
    //print_mac(hdr->addr1);
    //printf("\n");
    //printf("Source MAC: ");
    //print_mac(hdr->addr2);
    //printf("\n");
    //printf("BSSID: ");
    //print_mac(hdr->addr3);
    //printf("\n");
    const uint8_t *dest_mac = &raw_data[4];  // Address1 (宛先)
    const uint8_t *src_mac = &raw_data[10]; // Address2 (送信元)
    const uint8_t *bssid = &raw_data[16];   // Address3 (BSSID)
    printf("Destination MAC: ");
    print_mac(dest_mac);
    printf("\n");
    printf("Source MAC: ");
    print_mac(src_mac);
    printf("\n");
    printf("BSSID: ");
    print_mac(bssid);
    printf("\n");
}
// アプリケーションエントリーポイント
void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    // Wi-FiをNULLモードに設定
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    // プロミスキャスモードのフィルタ設定
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT // 管理フレームのみ
    };
    esp_wifi_set_promiscuous_filter(&filter);
    // プロミスキャスモードを有効化
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    esp_wifi_set_channel(5, WIFI_SECOND_CHAN_NONE);
    printf("Wi-Fi Sniffer Initialized with Optimizations.\n");
}
