#include <stdio.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <stdint.h>
void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void print_ipv4(const uint8_t *ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}
void print_ipv6(const uint8_t *ip) {
    for (int i = 0; i < 16; i += 2) {
        printf("%02x%02x", ip[i], ip[i + 1]);
        if (i < 14) printf(":");
    }
}
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *payload = pkt->payload;
    uint16_t length = pkt->rx_ctrl.sig_len;
    printf("Packet Length: %d\n", length);
    if (length >= 14) { // Ethernetフレームの基本長
        const uint8_t *dest_mac = payload;        // 宛先MACアドレス
        const uint8_t *src_mac = payload + 6;    // 送信元MACアドレス
        printf("Destination MAC: ");
        print_mac(dest_mac);
        printf("\n");
        printf("Source MAC: ");
        print_mac(src_mac);
        printf("\n");
    }
    if (length >= 34 && payload[12] == 0x08 && payload[13] == 0x00) { // IPv4を示す0x0800
        const uint8_t *src_ip = payload + 26; // 送信元IPアドレス (IPv4ヘッダー内)
        const uint8_t *dest_ip = payload + 30; // 宛先IPアドレス (IPv4ヘッダー内)
        printf("Source IPv4: ");
        print_ipv4(src_ip);
        printf("\n");
        printf("Destination IPv4: ");
        print_ipv4(dest_ip);
        printf("\n");
    } else if (length >= 54 && payload[12] == 0x86 && payload[13] == 0xDD) { // IPv6を示す0x86DD
        const uint8_t *src_ip = payload + 22; // 送信元IPアドレス (IPv6ヘッダー内)
        const uint8_t *dest_ip = payload + 38; // 宛先IPアドレス (IPv6ヘッダー内)
        printf("Source IPv6: ");
        print_ipv6(src_ip);
        printf("\n");
        printf("Destination IPv6: ");
        print_ipv6(dest_ip);
        printf("\n");
    }
    printf("\n");
}
void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
}

