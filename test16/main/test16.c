#include <stdio.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
// パケットダンプ関数
void dump_packet(const uint8_t *data, uint16_t length) {
    printf("Raw Packet Dump (%d bytes):\n", length);
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); // 16バイトごとに改行
        }
    }
    printf("\n");
}
// Wi-Fiパケット処理コールバック関数
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *raw_data = pkt->payload;
    // パケットデータのダンプ
    dump_packet(raw_data, pkt->rx_ctrl.sig_len);
}
// アプリケーションのエントリーポイント
void app_main(void) {
    // 必要な初期化
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    // Wi-Fi初期化
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    // Wi-FiをNULLモードに設定
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    // プロミスキャスモードを有効化
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL // すべてのフレームをキャプチャ
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    // チャネルの設定
    uint8_t channel = 6; // 必要なチャネルに変更可能
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    printf("Wi-Fi Sniffer Initialized on Channel %d.\n", channel);
}
