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

const char * TIME_ZONE = "PST-8";

/* project */
#include "main.h"

/* wolfSSL */
//#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#include "embedded_CERT_FILE.h"
#include "embedded_CA_FILE.h"
#include "embedded_KEY_FILE.h"

#define CUSTSUCCESS 0

#define WIFI_SSID      "WiFIDPGS38"
#define WIFI_PASSWORD  "s8kNpGN9Pr"
#define SERVER_IP    "192.168.8.7"
// #define WIFI_SSID      "MyPublicWiFi"
// #define WIFI_PASSWORD  "12345678"
// #define SERVER_IP    "192.168.137.79"

#define SERVER_PORT    1111

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

int set_time() {
    /* we'll also return a result code of zero */
    int res = 0;

    /* ideally, we'd like to set time from network,
    ** but let's set a default time, just in case
    */
    struct tm timeinfo;
    timeinfo.tm_year = 2025 - 1900;
    timeinfo.tm_mon = 3;
    timeinfo.tm_mday = 15;
    timeinfo.tm_hour = 8;
    timeinfo.tm_min = 03;
    timeinfo.tm_sec = 10;
    time_t t;
    t = mktime(&timeinfo);

    struct timeval now = { .tv_sec = t };
    settimeofday(&now, NULL);

    /* set timezone */
    setenv("TZ", TIME_ZONE, 1);
    tzset();

    return res;

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

    int ret = WOLFSSL_SUCCESS; /* assume success until proven wrong */

    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");
    
    // Wait until Wi-Fi is connected
    while (esp_wifi_connect() != ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 5 second before retrying
    }

    printf("Hello world!\n");
    
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
  

    wolfSSL_Debugging_ON();

    int sock;
    struct sockaddr_in server_addr;

    wolfSSL_Init();
    
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()); // Use TLS 1.3


    if (!ctx) {
        ESP_LOGE(TAG, "Failed to create WolfSSL context");
        vTaskDelete(NULL);
    }

        /*
        ***************************************************************************
        *  load CERT_FILE
        *
        *
        *  WOLFSSL_API int wolfSSL_use_certificate_buffer (WOLFSSL * ,
        *                                                  const unsigned char * ,
        *                                                  long,
        *                                                  int
        *                                                  )
        *
        *  The wolfSSL_use_certificate_buffer() function loads a certificate buffer
        *  into the WOLFSSL object. It behaves like the non-buffered version, only
        *  differing in its ability to be called with a buffer as input instead of
        *  a file. The buffer is provided by the in argument of size sz.
        *
        *  format specifies the format type of the buffer; SSL_FILETYPE_ASN1 or
        *  SSL_FILETYPE_PEM. Please see the examples for proper usage.
        *
        *  Returns
        *    SSL_SUCCESS      upon success.
        *    SSL_BAD_FILETYPE will be returned if the file is the wrong format.
        *    SSL_BAD_FILE     will be returned if the file doesn’t exist, can’t be read, or is corrupted.
        *    MEMORY_E         will be returned if an out of memory condition occurs.
        *    ASN_INPUT_E      will be returned if Base16 decoding fails on the file.
        *
        *  Parameters
        *    ssl    pointer to the SSL session, created with wolfSSL_new().
        *    in     buffer containing certificate to load.
        *    sz     size of the certificate located in buffer.
        *    format format of the certificate to be loaded. Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
        *
        *
        *  Pay attention to expiration dates and the current date setting
        *
        *  see https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaf4e8d912f3fe2c37731863e1cad5c97e
        ***************************************************************************
        */
    if (ret == WOLFSSL_SUCCESS) {
        ESP_LOGI(TAG, "Loading cert");
        ret =  wolfSSL_CTX_load_verify_buffer(ctx,
            CERT_FILE,
            sizeof_CERT_FILE(),
            WOLFSSL_FILETYPE_PEM);

        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "wolfSSL_CTX_use_certificate_buffer successful\n");
        }
        else {
            ESP_LOGE(TAG, "ERROR: wolfSSL_CTX_use_certificate_buffer failed, err %d \n", ret);
        }
    }
    else {
        /* a prior error occurred */
        ESP_LOGE(TAG, "skipping wolfSSL_CTX_use_certificate_buffer\n");
    }


    /*
    ***************************************************************************
    *  Load client private key into WOLFSSL_CTX
    *
    *  wolfSSL_CTX_use_PrivateKey_buffer()
    *
    *  WOLFSSL_API int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX *,
    *                                                    const unsigned char *,
    *                                                    long,
    *                                                    int
    *                                                   )
    *
    *  This function loads a private key buffer into the SSL Context.
    *  It behaves like the non-buffered version, only differing in its
    *  ability to be called with a buffer as input instead of a file.
    *
    *  The buffer is provided by the in argument of size sz. format
    *  specifies the format type of the buffer;
    *  SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    *
    *  Please see the examples for proper usage.
    *
    *  Returns
    *    SSL_SUCCESS upon success
    *    SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    *    SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    *    MEMORY_E will be returned if an out of memory condition occurs.
    *    ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    *    NO_PASSWORD will be returned if the key file is encrypted but no password is provided.
    *
    *  Parameters
    *    ctx      pointer to the SSL context, created with wolfSSL_CTX_new().
    *             inthe input buffer containing the private key to be loaded.
    *
    *    sz          the size of the input buffer.
    *
    *    format  the format of the private key located in the input buffer(in).
    *            Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    *
    *  see: https://www.wolfssl.com/doxygen/group__CertsKeys.html#ga71850887b87138b7c2d794bf6b1eafab
    ***************************************************************************
    */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            KEY_FILE,
            sizeof_KEY_FILE(),
            WOLFSSL_FILETYPE_PEM);
        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "wolfSSL_CTX_use_PrivateKey_buffer successful\n");
        }
        else {
            /* TODO fetch and print expiration date since it is a common fail */
            ESP_LOGE(TAG, "ERROR: wolfSSL_CTX_use_PrivateKey_buffer failed\n");
        }
    }
    else {
        /* a prior error occurred */
        ESP_LOGE(TAG, "Skipping wolfSSL_CTX_use_PrivateKey_buffer\n");
    }


    // /*
    // ***************************************************************************
    // *  Load CA certificate into WOLFSSL_CTX
    // *
    // *  wolfSSL_CTX_load_verify_buffer()
    // *  WOLFSSL_API int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX *,
    // *                                                 const unsigned char *,
    // *                                                 long,
    // *                                                 int
    // *                                                )
    // *
    // *  This function loads a CA certificate buffer into the WOLFSSL Context.
    // *  It behaves like the non-buffered version, only differing in its ability
    // *  to be called with a buffer as input instead of a file. The buffer is
    // *  provided by the in argument of size sz. format specifies the format type
    // *  of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM. More than one
    // *  CA certificate may be loaded per buffer as long as the format is in PEM.
    // *
    // *  Please see the examples for proper usage.
    // *
    // *  Returns
    // *
    // *    SSL_SUCCESS upon success
    // *    SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    // *    SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be read, or is corrupted.
    // *    MEMORY_E will be returned if an out of memory condition occurs.
    // *    ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    // *    BUFFER_E will be returned if a chain buffer is bigger than the receiving buffer.
    // *
    // *  Parameters
    // *
    // *    ctx    pointer to the SSL context, created with wolfSSL_CTX_new().
    // *    in    pointer to the CA certificate buffer.
    // *    sz    size of the input CA certificate buffer, in.
    // *    format    format of the buffer certificate, either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    // *
    // * see https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaa37539cce3388c628ac4672cf5606785
    // ***************************************************************************
    // */

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_CTX_load_verify_buffer(ctx, 
                                            CA_FILE, 
                                            sizeof_CA_FILE(), 
                                            WOLFSSL_FILETYPE_PEM);
        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "wolfSSL_CTX_load_verify_buffer successful\n");
        }
        else {
            ESP_LOGE(TAG, "ERROR: wolfSSL_CTX_load_verify_buffer failed, ret = %d \n", ret);
        }
    }
    else {
         // a prior error occurred 
        ESP_LOGE(TAG, "skipping wolfSSL_CTX_load_verify_buffer\n");
    } 
    
    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL object\n");
        
    }
   

    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_P256_ML_KEM_512);
    if (ret < 0) {
        ESP_LOGE(TAG, "ERROR: failed to set the requested group to WOLFSSL_P521_ML_KEM_1024. ERR %d \n", ret);
        
    }

   
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
        WOLFSSL_TIME(1);
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
    
    if(set_time()==CUSTSUCCESS) {ESP_LOGI(TAG, "Set time done!");}
    xTaskCreate(&wolfssl_client, "wolfssl_client", 12288, NULL, 5, NULL);
    // start wifi connection
    wifi_init();
    

    



    
}
