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
#include "esp_heap_caps.h"
#include "esp_heap_task_info.h"


#include "driver/gpio.h"


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


//#include "embedded_CERT_FILE.h"
//#include "embedded_CA_FILE.h"
//#include "embedded_KEY_FILE.h"

#define CUSTSUCCESS 0

// #define WIFI_SSID      "WiFIDPGS38"
// #define WIFI_PASSWORD  "s8kNpGN9Pr"
// #define SERVER_IP    "192.168.8.7"
#define WIFI_SSID      "MyPublicWiFi"
#define WIFI_PASSWORD  "12345678"
#define SERVER_IP    "192.168.137.225"

#define SERVER_PORT    1111

static const char *TAG = "ESP-PQC";
size_t payload_size = 83; // Define payload size in bytes
static const int con_users = 50;

static bool connectedIP = false;
TickType_t DelayTicks = 5000 / portTICK_PERIOD_MS;


void *custom_malloc(size_t size){

     return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

}

void* custom_realloc(void* ptr, size_t size){

    return heap_caps_realloc(ptr, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

void custom_free(void *ptr){
    heap_caps_free(ptr);
}



static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Disconnected! Reconnecting...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        connectedIP = true;
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
    ESP_ERROR_CHECK(esp_wifi_connect());
}

void print_task_mem_stats(int i) {
    // Heap (internal RAM)
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    ESP_LOGI("TASK", "#%d Internal Heap: free=%d, largest_block=%d", i, free_heap, largest_block);

    // Stack (for current task)
    uint32_t stack_watermark = uxTaskGetStackHighWaterMark(NULL);
    ESP_LOGI("TASK", "#%d Stack High Water Mark: %lu bytes", i, (uint32_t)(stack_watermark * sizeof(StackType_t)));
}

static int is_any_halted = 0;
void my_halt(int i) {
    is_any_halted = 1;
    ESP_LOGE(TAG, "Halt #%d", i);
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
void wolfssl_client(void *pvParameters) {

    int ret = WOLFSSL_SUCCESS; /* assume success until proven wrong */
    ESP_LOGI(TAG, "Ready to try TLS PQC handshake");

    int sock = 0; /* the socket that will carry our secure connection */
    struct sockaddr_in server_addr;

    WOLFSSL_CTX *ctx = NULL; /* the wolfSSL context object*/
    WOLFSSL *ssl = NULL; /* although called "ssl" is is the secure object for reading and writings data*/



    wolfSSL_Debugging_ON();  // start debugging process

    int param = *((int *)pvParameters);
    ESP_LOGI("HEAP", "Before SSL init: free heap = %lu, for task %u", esp_get_free_heap_size(), param);
    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()); // Use TLS 1.3
    if (!ctx) {
        ESP_LOGE(TAG, "Failed to create WolfSSL context");
        my_halt(param);
        vTaskDelete(NULL);
    }


    /* Do not Require mutual authentication */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);


    /* Set our preference for verification to be for both the native and
     * alternative chains. Ultimately, its the server's choice. This will be
     * used in the call to wolfSSL_UseCKS(). */
    byte cks_order[3] = {
        WOLFSSL_CKS_SIGSPEC_BOTH,
        WOLFSSL_CKS_SIGSPEC_ALTERNATIVE,
        WOLFSSL_CKS_SIGSPEC_NATIVE,
    };


    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        ESP_LOGE(TAG, "ERROR: failed to create WOLFSSL object\n");
        wolfSSL_CTX_free(ctx);
        my_halt(param);
        vTaskDelete(NULL);
    }



    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_ML_KEM_1024);
    if (ret < 0) {
        ESP_LOGE(TAG, "ERROR: failed to set the requested group to WOLFSSL_P521_ML_KEM_1024. ERR %d \n", ret);
        my_halt(param);
    }


    /*verification to be for both the native and
     * alternative chains.*/
    if (!wolfSSL_UseCKS(ssl, cks_order, sizeof(cks_order))) {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx); ctx = NULL;
        ESP_LOGE(TAG,"unable to set the CKS order.");
        my_halt(param);
    }


    /* Initialize the server address struct with zeros */
    memset(&server_addr, 0, sizeof(server_addr));

    print_task_mem_stats(param);
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            ESP_LOGE(TAG, "Socket creation failed");
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            my_halt(param);
            vTaskDelete(NULL);
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

        vTaskDelay(DelayTicks ? DelayTicks : 2); /* Minimum delay = 1 tick */

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
            ESP_LOGE(TAG, "Failed to connect to server");
            close(sock);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            my_halt(param);
            vTaskDelete(NULL);
        }
    }
    print_task_mem_stats(param);

    wolfSSL_set_fd(ssl, sock);
    ESP_LOGI("HEAP", "After accept socket: free heap = %lu, for task %u", esp_get_free_heap_size(), param);
    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "TLS 1.3 handshake failed");
        close(sock);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        my_halt(param);
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "Connected to server using WolfSSL TLS 1.3");
    // char request[] = "GET / HTTP/1.1\r\nHost: " SERVER_IP "\r\nConnection: close\r\n\r\n";

    unsigned char* buffer = malloc(payload_size);
    if (!buffer) {
       ESP_LOGE(TAG, "malloc failed");
       close(sock);
       wolfSSL_free(ssl);
       wolfSSL_CTX_free(ctx);
       my_halt(param);
       vTaskDelete(NULL);
    }


    // Fill buffer with random bytes
    for (size_t i = 0; i < payload_size; ++i) {
        buffer[i] = rand() % 256;
    }

    wolfSSL_write(ssl, buffer, payload_size);
    ESP_LOGI(TAG, "Size of send info: %u bytes", payload_size);


    // char request[] = "shutdown";
    // wolfSSL_write(ssl, request, sizeof(request));

    //char buffer[512];
    int len = wolfSSL_read(ssl, buffer, payload_size);
    if (len > 0) {
        buffer[len] = '\0';
        ESP_LOGI(TAG, "Received: %s, Size of receive info: %zu bytes", buffer, len);
    }

    int ret_i;
    ret_i = wolfSSL_shutdown(ssl);
        while (ret_i == WOLFSSL_SHUTDOWN_NOT_DONE) {
            ret_i = wolfSSL_shutdown(ssl); /* bidirectional shutdown */
            if (ret_i == WOLFSSL_SUCCESS) {
                ESP_LOGI(TAG, "Bidirectional shutdown complete #%d\n", param);
                break;
            }
            else if (ret_i != WOLFSSL_SHUTDOWN_NOT_DONE) {
                ESP_LOGE(TAG, "Bidirectional shutdown failed #%d\n", param);
                break;
            }
        }
        if (ret_i != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "Bidirectional shutdown failed #%d\n", param);
        }

    free(buffer);
   // WOLFSSL_TIME(1);
    close(sock);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    free(pvParameters);
    vTaskDelete(NULL);
}

void failed_print_caps(uint32_t caps) {
    if (caps & MALLOC_CAP_INTERNAL) {
        ESP_LOGE("HOOK", "Failed: [INTERNAL]");
        my_halt(0);
    }
    if (caps & MALLOC_CAP_SPIRAM)
        ESP_LOGE("HOOK", " [SPIRAM]");
    if (caps & MALLOC_CAP_8BIT)
        ESP_LOGE("HOOK", " [8BIT]");
    if (caps & MALLOC_CAP_DMA)
        ESP_LOGE("HOOK", " [DMA]");
    if (caps & MALLOC_CAP_EXEC)
        ESP_LOGE("HOOK", " [EXEC]");
    if (caps & MALLOC_CAP_DEFAULT)
        ESP_LOGE("HOOK", " [DEFAULT]");
}

void heap_caps_alloc_failed_hook(size_t requested_size, uint32_t caps, const char *function_name)
{
  ESP_LOGE(TAG, "%s was called but failed to allocate %d bytes with 0x%lu capabilities. \n",function_name, requested_size, caps);
  failed_print_caps(caps);
}


void app_main(void) {

    char taskName[16];

    gpio_reset_pin(GPIO_NUM_48);
    gpio_set_direction(GPIO_NUM_48, GPIO_MODE_OUTPUT);
    wolfSSL_SetAllocators(custom_malloc, custom_free, custom_realloc);

    esp_err_t error = heap_caps_register_failed_alloc_callback(heap_caps_alloc_failed_hook);
    if (error == ESP_OK) {
        ESP_LOGE(TAG, "Success: heap_caps_register_failed_alloc_callback");
    }
    else {
        ESP_LOGE(TAG, "FAILED: heap_caps_register_failed_alloc_callback");
    }

    // heap_caps_malloc_extmem_enable(0);

    // heap_caps_check_integrity_all(true);

    ESP_LOGI(TAG, "Starting Wi-Fi...");

    if(set_time()==CUSTSUCCESS) {ESP_LOGI(TAG, "Set time done!");}

     // start wifi connection
    wifi_init();
    // Wait until Wi-Fi is connected with IP assign
    while (esp_wifi_connect() != ESP_OK && !connectedIP) {
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 5 second before retrying
    }



    ESP_LOGI(TAG, "[Heap] Before client threads: %lu bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "[Heap] test: %u bytes", MALLOC_CAP_INTERNAL);

    //heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);
    wolfSSL_Init();

    for (int i = 0; i < con_users; i++) {
        if (is_any_halted) {
            break;
        }

        int *user_id = malloc(sizeof(int));
        *user_id = i;

        const int stack_size = 12288; // same size as your original
        size_t before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        ESP_LOGI(TAG, "-- Size before: %d", before);
        void *stack_mem = heap_caps_malloc(stack_size, MALLOC_CAP_SPIRAM);
        ESP_LOGI(TAG, "-- Allocated:   %d", stack_size);
        size_t after = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        ESP_LOGI(TAG, "-- Size after:  %d", after);
        ESP_LOGI(TAG, "-- Size diff:   %d", before - after);

        if (stack_mem == NULL) {
            ESP_LOGE("APP", "Failed to allocate memory SPIRAM");
            return;
        }

        //TaskHandle_t task_handle;
        StaticTask_t *task_buffer = heap_caps_malloc(sizeof(StaticTask_t), MALLOC_CAP_INTERNAL);
        if (task_buffer == NULL) {
            ESP_LOGE("APP", "Failed to allocate task control block");
            free(stack_mem);
            return;
        }


        snprintf(taskName, sizeof(taskName), "Task%02d", i); // e.g. Task00, Ta

        xTaskCreateStaticPinnedToCore(
            &wolfssl_client,
            taskName,
            stack_size / sizeof(StackType_t),
            user_id,
            5,
            stack_mem,
            task_buffer,
            0
        );

    }

    ESP_LOGI(TAG, "[Heap] After client threads: %lu bytes", esp_get_free_heap_size());


    //heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);

    for (;;)
        {
            vTaskDelay(DelayTicks ? DelayTicks : 1); /* Minimum delay = 1 tick */
        }



}
