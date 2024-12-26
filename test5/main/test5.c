#include <stdio.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <stdint.h>
#include <string.h>
#define MAX_IPS 100
uint8_t src_ips[MAX_IPS][16] = {0};
uint8_t dest_ips[MAX_IPS][16] = {0};
int ip_count = 0;
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
void store_ip(const uint8_t *src_ip, const uint8_t *dest_ip, int is_ipv6) {
    if (ip_count >= MAX_IPS) return;
    int ip_size = is_ipv6 ? 16 : 4;
    memcpy(src_ips[ip_count], src_ip, ip_size);
    memcpy(dest_ips[ip_count], dest_ip, ip_size);
    ip_count++;
}
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *payload = pkt->payload;
    uint16_t length = pkt->rx_ctrl.sig_len;
    printf("Packet Length: %d\n", length);
    if (length >= 14) {
        const uint8_t *dest_mac = payload;
        const uint8_t *src_mac = payload + 6;
        printf("Destination MAC: ");
        print_mac(dest_mac);
        printf("\n");
        printf("Source MAC: ");
        print_mac(src_mac);
        printf("\n");
    }
    if (length >= 34 && payload[12] == 0x08 && payload[13] == 0x00) {
        const uint8_t *src_ip = payload + 26;
        const uint8_t *dest_ip = payload + 30;
        printf("Source IPv4: ");
        print_ipv4(src_ip);
        printf("\n");
        printf("Destination IPv4: ");
        print_ipv4(dest_ip);
        printf("\n");
        store_ip(src_ip, dest_ip, 0);
    } else if (length >= 54 && payload[12] == 0x86 && payload[13] == 0xDD) {
        const uint8_t *src_ip = payload + 22;
        const uint8_t *dest_ip = payload + 38;
        printf("Source IPv6: ");
        print_ipv6(src_ip);
        printf("\n");
        printf("Destination IPv6: ");
        print_ipv6(dest_ip);
        printf("\n");
        store_ip(src_ip, dest_ip, 1);
    }
    printf("\n");
}
void display_stored_ips() {
    printf("\nRecorded IP Addresses:\n");
    for (int i = 0; i < ip_count; i++) {
        printf("Source IP %d: ", i + 1);
        if (i < MAX_IPS && memcmp(src_ips[i] + 4, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) == 0) {
            print_ipv4(src_ips[i]);
        } else {
            print_ipv6(src_ips[i]);
        }
        printf("\n");
        printf("Destination IP %d: ", i + 1);
        if (i < MAX_IPS && memcmp(dest_ips[i] + 4, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) == 0) {
            print_ipv4(dest_ips[i]);
        } else {
            print_ipv6(dest_ips[i]);
        }
        printf("\n");
    }
}
void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    display_stored_ips();
}

