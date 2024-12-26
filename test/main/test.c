#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "Wi-Fi Sniffer";

// Callback function for received packets
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;

    // Parse packet details
    const uint8_t *data = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    // Log packet information
    ESP_LOGI(TAG, "Packet received: length=%d", len);

    // Display MAC addresses if a management frame
    ESP_LOGI(TAG, "frame detected");
    ESP_LOGI(TAG, "Source MAC: %02x:%02x:%02x:%02x:%02x:%02x", data[10], data[11], data[12], data[13], data[14], data[15]);
    ESP_LOGI(TAG, "Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x", data[4], data[5], data[6], data[7], data[8], data[9]);
}

void app_main() {
    // Initialize NVS flash
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Initialize Wi-Fi
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Set Wi-Fi promiscuous mode
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));

    ESP_LOGI(TAG, "Wi-Fi Sniffer started!");

    // Continuous sniffing loop
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));  // Wait for 1 second (optional)
    }
}

