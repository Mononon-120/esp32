#include <stdio.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
    const uint8_t *payload = pkt->payload;
    uint16_t length = pkt->rx_ctrl.sig_len;

    printf("Packet Length: %d\n", length);
    printf("Raw Packet: ");
    for (int i = 0; i < length; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n\n");
}

void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_wifi_init(&(wifi_init_config_t){.event_handler = &esp_event_send});

    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
}

