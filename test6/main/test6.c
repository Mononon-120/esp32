#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#define UART_NUM UART_NUM_0 // 標準UART
#define BUF_SIZE (1024)
#define EXIT_KEY '}'
#define MAX_IPS 100
uint8_t src_ips[MAX_IPS][256];
uint8_t dest_ips[MAX_IPS][256];
int ip_count = 0;
void display_stored_ips() {
    printf("\nRecorded IP Addresses:\n");
    for (int i = 0; i < ip_count; i++) {
        printf("Source IP %d: ", i + 1);
        if (memcmp(src_ips[i] + 4, "\0\0\0", 3) == 0) {
            print_ipv4(src_ips[i]); // IPv4の場合
        } else {
            print_ipv6(src_ips[i]); // IPv6の場合
        }
        printf("\n");
        printf("Destination IP %d: ", i + 1);
        if (memcmp(dest_ips[i] + 4, "\0\0\0", 3) == 0) {
            print_ipv4(dest_ips[i]); // IPv4の場合
        } else {
            print_ipv6(dest_ips[i]); // IPv6の場合
        }
        printf("\n");
    }
}
void exit_monitor_task(void *arg) {
    uint8_t data[BUF_SIZE];
    while (1) {
        int len = uart_read_bytes(UART_NUM, data, BUF_SIZE, 20 / portTICK_RATE_MS);
        if (len > 0) {
            for (int i = 0; i < len; i++) {
                if (data[i] == EXIT_KEY) {
                    printf("Exit signal received. Displaying stored IP addresses...\n");
                    display_stored_ips();
                    printf("Exiting program...\n");
                    vTaskDelete(NULL); // タスク削除（終了処理）
                }
            }
        }
    }
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
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(UART_NUM, &uart_config);
    uart_driver_install(UART_NUM, BUF_SIZE * 2, 0, 0, NULL, 0);
    xTaskCreate(exit_monitor_task, "exit_monitor_task", 2048, NULL, 10, NULL);
    printf("Program running. Press 'Ctrl + }' to exit.\n");
}

