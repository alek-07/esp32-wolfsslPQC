/* main.c
 *
 *  project PQC testbed
 */

/* Espressif */
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "wolfssl/ssl.h"
#include "lwip/sockets.h"

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif


/* project */
#include "main.h"


#define WIFI_SSID      "MyPublicWiFi"
#define WIFI_PASSWORD  "12345678"
#define SERVER_IP    "192.168.137.213"
#define SERVER_PORT    11111

static const char *TAG = "ESP-PQC";

static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Disconnected! Reconnecting...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Connected! IP Address: " IPSTR, IP2STR(&event->ip_info.ip));
        
    }
}

void wifi_init(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}


void wolfssl_client(void *pvParameters) {

    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");
    
    // Wait until Wi-Fi is connected
    while (esp_wifi_connect() != ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 1 second before retrying
    }

    ESP_LOGI(TAG, "Ready to try TLS PQC handshake");
        ESP_LOGI(TAG, "---------------- wolfSSL TLS Client PQC ----------------");
        ESP_LOGI(TAG, "--------------------------------------------------------");
        ESP_LOGI(TAG, "--------------------------------------------------------");
        ESP_LOGI(TAG, "---------------------- BEGIN MAIN ----------------------");
        ESP_LOGI(TAG, "--------------------------------------------------------");
        ESP_LOGI(TAG, "--------------------------------------------------------");
    ESP_LOGI(TAG, "Starting WolfSSL client...");

    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int sock;
    struct sockaddr_in server_addr;

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()); // Use TLS 1.3
    if (!ctx) {
        ESP_LOGE(TAG, "Failed to create WolfSSL context");
        vTaskDelete(NULL);
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        ESP_LOGE(TAG, "Failed to create WolfSSL session");
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "Socket creation failed");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    

    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        ESP_LOGE(TAG, "Failed to connect to server");
        close(sock);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
    }

    wolfSSL_set_fd(ssl, sock);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "TLS 1.3 handshake failed");
        close(sock);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "Connected to server using WolfSSL TLS 1.3");
    char request[] = "GET / HTTP/1.1\r\nHost: " SERVER_IP "\r\nConnection: close\r\n\r\n";
    wolfSSL_write(ssl, request, sizeof(request));

    char buffer[512];
    int len = wolfSSL_read(ssl, buffer, sizeof(buffer)-1);
    if (len > 0) {
        buffer[len] = '\0';
        ESP_LOGI(TAG, "Received: %s", buffer);
    }

    wolfSSL_shutdown(ssl);
    close(sock);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    vTaskDelete(NULL);

}
void app_main(void) {
    ESP_LOGI(TAG, "Starting Wi-Fi...");
    xTaskCreate(&wolfssl_client, "wolfssl_client", 8192, NULL, 5, NULL);
    // start wifi connection
    wifi_init();

    



    
}
