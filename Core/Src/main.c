/* USER CODE BEGIN Header */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "mbedtls.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/sha256.h"


/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

//Aproxmately  5KB size of the certificate
const unsigned char ca_cert[] = {
    "2d, 2d, 2d, 2d, 2d, 42, 45, 47, 49, 4e, 20, 43, 45, 52, 54, 49,46, 49, 43, 41, 54, 45, 2d, 2d, 2d, 2d, 2d, 0a, 4d, 49, 49, 44,73, 44, 43, 43, 41, 31, 61, 67, 41, 77, 49, 42, 41, 67, 49, 55,45, 52, 2f, 32, 33, 49, 42, 6a, 45, 49, 6c, 73, 73, 54, 4c, 2b,5a, 5a, 2f, 4c, 77, 35, 50, 69, 31, 70, 38, 77, 43, 67, 59, 49,4b, 6f, 5a, 49, 7a, 6a, 30, 45, 41, 77, 49, 77, 0a, 67, 62, 51,78, 43, 7a, 41, 4a, 42, 67, 4e, 56, 42, 41, 59, 54, 41, 6b, 6c,4f, 4d, 52, 4d, 77, 45, 51, 59, 44, 56, 51, 51, 49, 44, 41, 70,55, 59, 57, 31, 70, 62, 43, 42, 4f, 59, 57, 52, 31, 4d, 52, 41,77, 44, 67, 59, 44, 56, 51, 51, 48, 44, 41, 64, 44, 0a, 61, 47,56, 75, 62, 6d, 46, 70, 4d, 54, 6b, 77, 4e, 77, 59, 44, 56, 51,51, 4b, 44, 44, 42, 54, 62, 32, 4e, 70, 5a, 58, 52, 35, 49, 47,5a, 76, 63, 69, 42, 46, 62, 47, 56, 6a, 64, 48, 4a, 76, 62, 6d,6c, 6a, 49, 46, 52, 79, 59, 57, 35, 7a, 59, 57, 4e, 30, 0a, 61,57, 39, 75, 63, 79, 42, 68, 62, 6d, 51, 67, 55, 32, 56, 6a, 64,58, 4a, 70, 64, 48, 6b, 78, 4b, 44, 41, 6d, 42, 67, 4e, 56, 42,41, 73, 4d, 48, 30, 35, 6c, 64, 48, 64, 76, 63, 6d, 73, 67, 55,32, 56, 6a, 64, 58, 4a, 70, 64, 48, 6b, 67, 55, 6d, 56, 7a, 0a,5a, 57, 46, 79, 59, 32, 67, 67, 52, 33, 4a, 76, 64, 58, 41, 78,47, 54, 41, 58, 42, 67, 4e, 56, 42, 41, 4d, 4d, 45, 47, 56, 68,59, 6d, 68, 6c, 5a, 48, 6c, 68, 49, 48, 4a, 76, 62, 33, 51, 67,59, 32, 45, 77, 49, 42, 63, 4e, 4d, 6a, 49, 78, 4d, 54, 41, 7a,0a, 4d, 44, 59, 79, 4e, 6a, 49, 31, 57, 68, 67, 50, 4d, 6a, 41,31, 4d, 6a, 45, 78, 4d, 6a, 55, 77, 4e, 6a, 49, 32, 4d, 6a, 56,61, 4d, 49, 47, 30, 4d, 51, 73, 77, 43, 51, 59, 44, 56, 51, 51,47, 45, 77, 4a, 4a, 54, 6a, 45, 54, 4d, 42, 45, 47, 41, 31, 55,45, 0a, 43, 41, 77, 4b, 56, 47, 46, 74, 61, 57, 77, 67, 54, 6d,46, 6b, 64, 54, 45, 51, 4d, 41, 34, 47, 41, 31, 55, 45, 42, 77,77, 48, 51, 32, 68, 6c, 62, 6d, 35, 68, 61, 54, 45, 35, 4d, 44,63, 47, 41, 31, 55, 45, 43, 67, 77, 77, 55, 32, 39, 6a, 61, 57,56, 30, 0a, 65, 53, 42, 6d, 62, 33, 49, 67, 52, 57, 78, 6c, 59,33, 52, 79, 62, 32, 35, 70, 59, 79, 42, 55, 63, 6d, 46, 75, 63,32, 46, 6a, 64, 47, 6c, 76, 62, 6e, 4d, 67, 59, 57, 35, 6b, 49,46, 4e, 6c, 59, 33, 56, 79, 61, 58, 52, 35, 4d, 53, 67, 77, 4a,67, 59, 44, 0a, 56, 51, 51, 4c, 44, 42, 39, 4f, 5a, 58, 52, 33,62, 33, 4a, 72, 49, 46, 4e, 6c, 59, 33, 56, 79, 61, 58, 52, 35,49, 46, 4a, 6c, 63, 32, 56, 68, 63, 6d, 4e, 6f, 49, 45, 64, 79,62, 33, 56, 77, 4d, 52, 6b, 77, 46, 77, 59, 44, 56, 51, 51, 44,44, 42, 42, 6c, 0a, 59, 57, 4a, 6f, 5a, 57, 52, 35, 59, 53, 42,79, 62, 32, 39, 30, 49, 47, 4e, 68, 4d, 46, 6b, 77, 45, 77, 59,48, 4b, 6f, 5a, 49, 7a, 6a, 30, 43, 41, 51, 59, 49, 4b, 6f, 5a,49, 7a, 6a, 30, 44, 41, 51, 63, 44, 51, 67, 41, 45, 6f, 6f, 43,65, 42, 45, 4a, 76, 0a, 54, 64, 48, 6a, 71, 5a, 6e, 38, 63, 2b,54, 47, 46, 78, 53, 73, 62, 4f, 31, 76, 79, 79, 4f, 44, 58, 4d,37, 5a, 31, 77, 51, 52, 65, 37, 54, 59, 46, 50, 33, 4e, 32, 53,62, 58, 4d, 6e, 4e, 6a, 71, 65, 35, 45, 67, 67, 43, 68, 5a, 59,2b, 43, 61, 69, 79, 7a, 0a, 42, 49, 30, 70, 6c, 4a, 4f, 61, 65,37, 32, 35, 76, 61, 4f, 43, 41, 55, 41, 77, 67, 67, 45, 38, 4d,42, 30, 47, 41, 31, 55, 64, 44, 67, 51, 57, 42, 42, 52, 6c, 4d,49, 58, 45, 6b, 57, 6c, 57, 46, 59, 52, 43, 4f, 71, 58, 53, 4c,68, 48, 55, 41, 57, 49, 64, 0a, 65, 6a, 41, 4d, 42, 67, 4e, 56,48, 52, 4d, 45, 42, 54, 41, 44, 41, 51, 48, 2f, 4d, 41, 73, 47,41, 31, 55, 64, 44, 77, 51, 45, 41, 77, 49, 42, 39, 6a, 43, 42,39, 41, 59, 44, 56, 52, 30, 6a, 42, 49, 48, 73, 4d, 49, 48, 70,67, 42, 52, 6c, 4d, 49, 58, 45, 0a, 6b, 57, 6c, 57, 46, 59, 52,43, 4f, 71, 58, 53, 4c, 68, 48, 55, 41, 57, 49, 64, 65, 71, 47,42, 75, 71, 53, 42, 74, 7a, 43, 42, 74, 44, 45, 4c, 4d, 41, 6b,47, 41, 31, 55, 45, 42, 68, 4d, 43, 53, 55, 34, 78, 45, 7a, 41,52, 42, 67, 4e, 56, 42, 41, 67, 4d, 0a, 43, 6c, 52, 68, 62, 57,6c, 73, 49, 45, 35, 68, 5a, 48, 55, 78, 45, 44, 41, 4f, 42, 67,4e, 56, 42, 41, 63, 4d, 42, 30, 4e, 6f, 5a, 57, 35, 75, 59, 57,6b, 78, 4f, 54, 41, 33, 42, 67, 4e, 56, 42, 41, 6f, 4d, 4d, 46,4e, 76, 59, 32, 6c, 6c, 64, 48, 6b, 67, 0a, 5a, 6d, 39, 79, 49,45, 56, 73, 5a, 57, 4e, 30, 63, 6d, 39, 75, 61, 57, 4d, 67, 56,48, 4a, 68, 62, 6e, 4e, 68, 59, 33, 52, 70, 62, 32, 35, 7a, 49,47, 46, 75, 5a, 43, 42, 54, 5a, 57, 4e, 31, 63, 6d, 6c, 30, 65,54, 45, 6f, 4d, 43, 59, 47, 41, 31, 55, 45, 0a, 43, 77, 77, 66,54, 6d, 56, 30, 64, 32, 39, 79, 61, 79, 42, 54, 5a, 57, 4e, 31,63, 6d, 6c, 30, 65, 53, 42, 53, 5a, 58, 4e, 6c, 59, 58, 4a, 6a,61, 43, 42, 48, 63, 6d, 39, 31, 63, 44, 45, 5a, 4d, 42, 63, 47,41, 31, 55, 45, 41, 77, 77, 51, 5a, 57, 46, 69, 0a, 61, 47, 56,6b, 65, 57, 45, 67, 63, 6d, 39, 76, 64, 43, 42, 6a, 59, 59, 49,55, 45, 52, 2f, 32, 33, 49, 42, 6a, 45, 49, 6c, 73, 73, 54, 4c,2b, 5a, 5a, 2f, 4c, 77, 35, 50, 69, 31, 70, 38, 77, 43, 51, 59,44, 56, 52, 30, 52, 42, 41, 49, 77, 41, 44, 41, 4b, 0a, 42, 67,67, 71, 68, 6b, 6a, 4f, 50, 51, 51, 44, 41, 67, 4e, 49, 41, 44,42, 46, 41, 69, 45, 41, 32, 48, 57, 52, 30, 65, 62, 48, 39, 75,70, 6b, 73, 50, 75, 30, 47, 51, 51, 6a, 50, 4c, 43, 37, 4d, 4d,73, 39, 4f, 46, 65, 76, 7a, 71, 36, 51, 6f, 64, 79, 49, 0a, 48,6d, 6b, 43, 49, 41, 5a, 77, 75, 6c, 4a, 42, 2b, 47, 59, 55, 72,4e, 77, 36, 35, 59, 67, 48, 51, 42, 67, 59, 2b, 77, 32, 78, 55,74, 41, 75, 50, 31, 32, 56, 6d, 4b, 6a, 51, 34, 47, 35, 77, 0a,2d, 2d, 2d, 2d, 2d, 45, 4e, 44, 20, 43, 45, 52, 54, 49, 46, 49,43, 41, 54, 45, 2d, 2d, 2d, 2d, 2d, 0a"
  };

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

#define CURVE MBEDTLS_ECP_DP_SECP256R1 // ECC curve to generate key-pairs (prime256V1)
#define CERT_FLASH_MEMORY 0x08040000;  //11th sector memory in flash (nothg is there)
#define CERTIFICATE_SIZE  (sizeof(ca_cert)) // Size of the certificate data
#define DCERT_FLASH_MEMORY 0x08020000  // 5th sector Memory location to flash the CA certificate
#define DCERTIFICATE_SIZE  1024        // Define based on the expected size of the CA certificate
#define UART_RECEIVE_BUFFER_SIZE 1024  // Buffer size for receiving data via UART
#define STM32_UID_BASE ((uint32_t*)0x1FFF7A10)
#define OTP_mem ((uint32_t*)0x1FFF7800)
#define PRIVATE_KEY_LOCATION  0x08041740

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
RNG_HandleTypeDef hrng;

UART_HandleTypeDef huart4;
UART_HandleTypeDef huart5;

/* USER CODE BEGIN PV */

uint8_t uart_receive_buffer[UART_RECEIVE_BUFFER_SIZE];
uint8_t certificate_data[DCERTIFICATE_SIZE];
char Device_cert_buffer[DCERTIFICATE_SIZE];
uint32_t certificate_index = 0;
char chip_model[64] = "STM DISCOVERY Kit - STM32F407VGT6 chip"; //my device model name
char confirm_msg[17] = "\nSTATUS:Cert_recv\n";
char uid_str[25]; //UID Buffer
// Buffers for receiving commands from UI and sending responses
char uart_rx_buffer[8];
char uart_tx_buffer[256];
static unsigned char output_buf[1024]; //CSR Buffer
static unsigned char final_output_buf[1024]; //CSR Buffer to send esp8266




/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_RNG_Init(void);
static void MX_UART4_Init(void);
static void MX_UART5_Init(void);
/* USER CODE BEGIN PFP */

void esp8266_connect_to_wifi(char*,char*,char*,char*);

void esp8266_get_device_info(void);

// Function to get STM32 UID as a string
void get_stm32_uid(char *uid_str, size_t uid_str_len) {
    uint32_t uid[3];
    uid[0] = STM32_UID_BASE[0];
    uid[1] = STM32_UID_BASE[1];
    uid[2] = STM32_UID_BASE[2];

    // Format UID as a hex string
    //snprintf(uid_str, uid_str_len, "%08X%08X%08X", uid[0], uid[1], uid[2]);
    //snprintf(uid_str, uid_str_len, "  (unsigned long)uid[0], (unsigned long)uid[1], (unsigned long)uid[2]);"
    snprintf(uid_str, uid_str_len, "%lu%lu%lu", (unsigned long)uid[0], (unsigned long)uid[1], (unsigned long)uid[2]);
    printf("UID: %s\n",uid_str);


}


//To flash the Device Certificate in flash memory(sector 11 128Kbytes)
int flash_certificate(uint8_t* data, uint32_t size)  //ret = 0,1 or -1.-2 ;
{
	int ret = 0;
	char msg_UI[] = "\nCSDS:Certificate Stored in Device Successfully\n" ;
    HAL_FLASH_Unlock();

   // Step 2: Erase the sector where the certificate will be written
     FLASH_EraseInitTypeDef EraseInitStruct;   // To setup the particular sector in flash memory for to write the device certificate!
     uint32_t SectorError = 0;

       EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
       EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3; // Voltage range for STM32F4
       EraseInitStruct.Sector = FLASH_SECTOR_5; // Adjust the sector based on your address
       EraseInitStruct.NbSectors = 1;

    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK)
    {
        printf("Error erasing flash memory?  \n");  // comment this line once it is online
        ret = -1;

    }
    else if(HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) == HAL_OK)
    {
        int count = 0;
    	for (uint32_t i = 0; i < size; i += 4)
    	    {
    	        uint32_t data_to_write = *(uint32_t*)(data + i); // why uint32_t ? cuz word size of board is 32byte
    	        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, DCERT_FLASH_MEMORY + i, data_to_write) == HAL_OK)
    	        {
                  count+=1;
    	        }
    	        else
    	        {
    	        	printf("Error programming flash memory____\n"); //// comment this line once it is online
    	        	ret = -2;
    	        }
    	    }
    	if(HAL_UART_Transmit(&huart4, (uint8_t*)msg_UI, sizeof(msg_UI), HAL_MAX_DELAY) == HAL_OK)
    	 {
    	   printf("certificate stored status send to UI 4X:%d",count); //// comment this line once it is online
    	   ret = 1;
    	 }
    }

    HAL_FLASH_Lock();
	//Retriveving the Device_certificate from flash memory and sending it to UI through UART
	for (uint32_t i = 0; i < size; i++)
	    {
		Device_cert_buffer[i] = *(char*)(DCERT_FLASH_MEMORY + i);  // Read byte by byte (character)
	    }
    return ret;
}


//Task to write(store) Private key in Flash memory

void Flash_Write_PrivateKey(uint8_t *privateKeyData, uint32_t keySize) {
    HAL_StatusTypeDef status;

    // Step 1: Unlock the flash memory for writing
    HAL_FLASH_Unlock();

    // Step 2: Erase the sector where the private key will be written
    FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError = 0;

    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;  // Voltage range for STM32F4
    EraseInitStruct.Sector = FLASH_SECTOR_11;              // Sector 11 of flash memory
    EraseInitStruct.NbSectors = 1;

    status = HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError);
    if (status != HAL_OK) {
        // Handle error
        while(1);
    }

    // Step 3: Write the private key data to the specific flash memory address
    uint32_t address = PRIVATE_KEY_LOCATION;
    for (uint32_t i = 0; i < keySize; i++) {
        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address, privateKeyData[i]);
        if (status != HAL_OK) {
            // Handle error
            while(1);
        }
        address++;
    }

    printf("Private key written into flash memory sector 11 at address: 0x08045268\n");

    // Step 4: Lock the flash memory again
    HAL_FLASH_Lock();
}


//get device information

void esp8266_get_device_info(void)
{
	char ip_mac_reqbuffer[4] = "GI\n"; //"GI:MAC_ADDRESS: IP_ADDRESS:";
	char ip_mac_recbuffer[200];
	char ip_buffer[50];
	char mac_buffer[50];
	char chipmodel_uid_mac_ip[135]; // buffer that gonna send to UI

	//Function to get the UID from my MCU
	get_stm32_uid(uid_str, sizeof(uid_str));
	HAL_UART_Transmit(&huart5, (uint8_t*)ip_mac_reqbuffer, sizeof(ip_mac_reqbuffer), HAL_MAX_DELAY); // requesting ip anad mac address from esp8266 wifi module

	while(1)
	{
	  //ff:ff:ff:ff:ff:ff 172.24.18.40  ip =
	  if( (HAL_UART_Receive(&huart5, (uint8_t*)ip_mac_recbuffer,sizeof(ip_mac_recbuffer),3000) == HAL_OK) ||   (HAL_UART_Receive(&huart5, (uint8_t*)ip_mac_recbuffer,sizeof(ip_mac_recbuffer),3000) == HAL_TIMEOUT) )
	  {

		strncpy(mac_buffer,ip_mac_recbuffer,18);
		mac_buffer[19] = '\0';

		strncpy(ip_buffer, ip_mac_recbuffer+18,12);
		ip_buffer[13] = '\0' ;

	    snprintf(chipmodel_uid_mac_ip,sizeof(chipmodel_uid_mac_ip),"Chip Model:%s,MAC Address:%s,IP Address:%s,UID:%s", chip_model,mac_buffer,ip_buffer,uid_str); //mac_buffer

		if(HAL_UART_Transmit(&huart4,(uint8_t*)chipmodel_uid_mac_ip,sizeof(chipmodel_uid_mac_ip),100) == HAL_OK) //stm32 to UI
		{
			break;
		}
		else
		{
			printf("i am in else block of esp8266_get_device_info uart transmit\n");
		}

		//(HAL_UART_Receive(&huart5,ip_mac_buffer,sizeof(ip_mac_buffer),0)
	  }
	  else
	  {
		  printf("i am in else block of esp8266_get_device_info uart receive itself\n");
	  }
  }
}

	//to connect wifi and server
void esp8266_connect_to_wifi(char* ssid, char* password, char* server_ip, char* server_port)
	{
		uint8_t connection[44]; // "wifi connected,(14)server connected()"
		uint8_t wifi_conn_status[60];
		uint8_t wifi_conn_status_1[60];
		char status_ok[30] = "STATUS:WiFi Connected";
	    char status_not_ok[30] = "STATUS:Failed to connect WiFi";
		char status_waiting[40] = "STATUS:Waiting for connection...";
		uint32_t start_time, end_time = 2000;

		snprintf((char*)connection,sizeof(connection),"CONNECT:%s,%s,%s,%s",ssid,password,server_ip,server_port);
		//stm to esp
		if(HAL_UART_Transmit(&huart5, (uint8_t*)connection, sizeof(connection), HAL_MAX_DELAY ) == HAL_OK)
		{
			printf("connect cmd data(network parameter send to esp8266)\n");
		}
		 // sending network data to esp8266 boarto connect wifi

		while(1)
		{

		  //from ESP to STM
		  if ( (HAL_UART_Receive(&huart5,(uint8_t*)wifi_conn_status,sizeof(wifi_conn_status),1000)==HAL_OK) || (HAL_UART_Receive(&huart5,(uint8_t*)wifi_conn_status,sizeof(wifi_conn_status),1000)==HAL_TIMEOUT) )
		  {
		   start_time = HAL_GetTick();
		   strncpy((char*)wifi_conn_status_1, (char*)wifi_conn_status, 33); //"wifi_connected\0" \\"Wifi Connected"  (last one is the standadrd)

		   wifi_conn_status_1[33] = '\0';

		  //strncpy(wifi_conn_status, connection+wifi_end_len, 16); //"server_connected\0"
		  //wifi_conn_status[16] = '\0'

		  if (strncmp((char*)wifi_conn_status_1, status_ok, strlen(status_ok)) == 0)
		  {
			  //from STM to UI serial monitor
			  if( (HAL_UART_Transmit(&huart4, (uint8_t*)status_ok, sizeof(status_ok), 2000)== HAL_OK ) || (HAL_UART_Transmit(&huart4, (uint8_t*)status_ok, sizeof(status_ok), 2000)== HAL_TIMEOUT))

			  {
				  memset(wifi_conn_status_1, 0, sizeof(wifi_conn_status_1));
				  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_SET);  //BLUE LED
				  HAL_Delay(500);
				  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_RESET);
				  HAL_Delay(500);
				  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_SET);
				  HAL_Delay(500);
				  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_RESET);


				  printf("wifi status received from esp8266 and send to UI");
			  } // sending network status to UI from stm32
			  break;
		  }
		  else if(strncmp((char*)wifi_conn_status_1, status_not_ok, strlen(status_not_ok) ) == 0 )
		  {
			  //from STM to UI serial monitor
			  if(HAL_UART_Transmit(&huart4, (uint8_t*)status_not_ok, sizeof(status_not_ok), HAL_MAX_DELAY)==HAL_OK || (HAL_UART_Transmit(&huart4, (uint8_t*)status_not_ok, sizeof(status_not_ok), 1000)== HAL_TIMEOUT) ) // sending network status to UI from stm32
			  {
				  //memset(wifi_conn_status_1, 0, sizeof(wifi_conn_status_1));
				  printf("wifi status received from esp8266 and send to UI");
			  }
			  memset(wifi_conn_status_1, 0, sizeof(wifi_conn_status_1));
			  //break;
		  }

		  else if( strncmp((char*)wifi_conn_status_1, status_waiting, strlen(status_not_ok) ) == 0 && start_time >= end_time )
		  {

			  HAL_UART_Transmit(&huart4, (uint8_t*)status_waiting, sizeof(status_waiting), HAL_MAX_DELAY);// sending network status to UI from stm32
			  memset(wifi_conn_status_1, 0, sizeof(wifi_conn_status_1));
			  //break;
		  }

		}

		  else
		  {
			  printf("i havent received anything from serial connection ");
		  }

		}

	}

//To generate CSR
void generate_csr(const char* organization)
{
  int ret = 0;
  uint32_t start_time, end_time, time_taken;
  const char *pers = "csr_generation";
  //static unsigned char output_buf[4096];  // Buffer for CSR output
  unsigned char Prkey_buf[250];   // Buffer for keys (sufficient size for PEM format)
  unsigned char Pubkey_buf[250];
  char subject_name[256];
  char uid_str[25];

  // Initialize the entropy context used for randomness
  mbedtls_entropy_context entropy;

  // Initialize the CTR_DRBG context, a deterministic random bit generator
  mbedtls_ctr_drbg_context ctr_drbg;

  // Initialize the public and pri keys key context
  mbedtls_pk_context key;

  // Initialize the CSR context
  mbedtls_x509write_csr csr;

  /* USER CODE BEGIN generate_csr_Init */
  //size_t olen = 0;



  // Record the start time before CSR generation


  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_pk_init(&key);
  mbedtls_x509write_csr_init(&csr);

  // Get STM32 UID for to add as CN to the certificate
    get_stm32_uid(uid_str, sizeof(uid_str));

 // Seed the CTR_DRBG with entropy to ensure randomness
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
  {
    printf("Failed in mbedtls_ctr_drbg_seed, returned -0x%04x\n", -ret);
    goto cleanup;
  }


  // Set up the public and pri keys context to use Elliptic Curve Key (EC Key)
  if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
  {
    printf("Failed in mbedtls_pk_setup, returned -0x%04x\n", -ret);
    goto cleanup;
  }

  // Generate an ECC key pair for the specified curve

  start_time = HAL_GetTick();


  //KEY pair generation
  if ((ret = mbedtls_ecp_gen_key(CURVE, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
  {
    printf("Failed in mbedtls_ecp_gen_key, returned -0x%04x\n", -ret);
    goto cleanup;
  }

  end_time = HAL_GetTick();

  time_taken = end_time - start_time ;

  printf("Key pair Generation time: %ld\n",time_taken);


  // Export and print the private key in PEM format
      if ((ret = mbedtls_pk_write_key_pem(&key, Prkey_buf, sizeof(Prkey_buf))) != 0)
      {
          printf("Failed to export private key, returned -0x%04x\n", -ret);
          goto cleanup;
      }

      Flash_Write_PrivateKey(Prkey_buf,strlen(Prkey_buf) );

      printf("Private Key:\n%s\n%d\n", Prkey_buf,strlen(Prkey_buf));


      // Export and print the public key in PEM format
      if ((ret = mbedtls_pk_write_pubkey_pem(&key, Pubkey_buf, sizeof(Pubkey_buf))) != 0)
      {
          printf("Failed to export public key, returned -0x%04x\n", -ret);
          goto cleanup;
      }
      printf("Public Key:\n%s\n", Pubkey_buf);


      start_time = HAL_GetTick();

  // Set the message digest algorithm to SHA-256 for the CSR
  mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

  // Set the key to be used for signing the CSR
  mbedtls_x509write_csr_set_key(&csr, &key);

  // Set subject name with UID as CN
  snprintf(subject_name, sizeof(subject_name), "CN=%s,O=%s,C=IN", uid_str, organization);

  // Set the subject name of the CSR (e.g., CN=Common Name, O=Organization, C=Country)
  mbedtls_x509write_csr_set_subject_name(&csr,subject_name);

  if ((ret = mbedtls_x509write_csr_pem(&csr, output_buf, sizeof(output_buf), mbedtls_ctr_drbg_random, &ctr_drbg)) < 0)
  {
    printf("Failed in mbedtls_x509write_csr_pem, returned -0x%04x\n", -ret);
    goto cleanup;
  }

  end_time = HAL_GetTick();

  time_taken = end_time - start_time;

  printf("time taken for CSR generation: %ld\n", time_taken);
  printf("CSR generated successfully:\n%s\n", output_buf);

 // HAL_UART_Transmit(&huart4, output_buf, sizeof(output_buf),0);  // To send CSR to UI
  HAL_UART_Transmit(&huart4, output_buf, sizeof(output_buf),0);  // To send CSR to ESP8266 wifi module

  strcpy(final_output_buf,output_buf);



cleanup:
  mbedtls_pk_free(&key);
  mbedtls_x509write_csr_free(&csr);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  /* USER CODE END generate_csr_Init */
  return ;
  //return output_buf;
}


//To Flash Root CA certificate (e_ahbedheya CA certificate)
void Flash_Write_Certificate(void) {
    HAL_StatusTypeDef status;

    // Step 1: Unlock the flash memory for writing
    HAL_FLASH_Unlock();

    // Step 2: Erase the sector where the certificate will be written
    FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError = 0;

    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3; // Voltage range for STM32F4
    EraseInitStruct.Sector = FLASH_SECTOR_6; // Adjust the sector based on your address
    EraseInitStruct.NbSectors = 1;

    status = HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError);
    if (status != HAL_OK) {
        // Handle error
        while(1);
    }

    // Step 3: Write the certificate data to flash memory
    uint32_t address = CERT_FLASH_MEMORY;
    for (uint32_t i = 0; i < CERTIFICATE_SIZE; i++) {
        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address, ca_cert[i]);
        if (status != HAL_OK) {
            // Handle error
            while(1);
        }
        address++;
    }

    printf("Root CA certificate got flashed into flsh memory sector 5: 0x08020000 \n");

    // Step 4: Lock the flash memory again
    HAL_FLASH_Lock();
}


//To Receive Server CA certificate(AKA Device certificate) According to my device CSR
int receive_certificate()
{
    int ret = 0;
    char cmd_CSR[1024];
    memset(cmd_CSR, 0, sizeof(cmd_CSR));
    strcpy(cmd_CSR,"GDC\n");
    strcat(cmd_CSR,output_buf);

    // Sending CSR to ESP8266 to get Device Certificate (Dcert)
    if (HAL_UART_Transmit(&huart5, (uint8_t*)cmd_CSR, sizeof(cmd_CSR), HAL_MAX_DELAY) == HAL_OK)
    {
        ret = 1;  //checking weather CSR send first to my server to get the dcerti back
    }

    // Listening for the Dcert from ESP8266
    while (1)
    {
        if (ret == 1)
        {
            // Receiving the certificate from ESP8266
            if ((HAL_UART_Receive(&huart5, certificate_data, DCERTIFICATE_SIZE, HAL_MAX_DELAY) == HAL_OK) || (HAL_UART_Receive(&huart5, certificate_data, DCERTIFICATE_SIZE, HAL_MAX_DELAY) == HAL_TIMEOUT))
            {
                // Check if certificate begins and ends with the correct delimiters
                if (strncmp((char *)certificate_data, "-----BEGIN CERTIFICATE-----", 27) == 0 &&
                    strstr((char *)certificate_data, "-----END CERTIFICATE-----") != NULL)
                {
                    printf("Certificate received successfully.\n");

                    // Flash the certificate to memory
                    int flash_result = flash_certificate(certificate_data, strlen((char *)certificate_data));

                    if (flash_result == 1)
                    {
                        printf("Certificate flashed successfully in 11th sector of flash memory.\n");
                    }
                    else if (flash_result == -1)
                    {
                        printf("Error in erasing flash memory before writing certificate.\n");
                    }
                    else if (flash_result == -2)
                    {
                        printf("Error! Cannot write the certificate into the 11th sector of flash memory.\n");
                    }

                    // Transmit the complete certificate to the UI through UART4
                    if (HAL_UART_Transmit(&huart4, (uint8_t *)Device_cert_buffer, DCERTIFICATE_SIZE, HAL_MAX_DELAY) == HAL_OK)
                    {
                        // Blink LEDs to indicate success
                        HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_SET);  // Red LED
                        HAL_Delay(500);
                        HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_RESET);
                        HAL_Delay(500);
                        HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_SET);  // Blue LED
                        HAL_Delay(500);
                        HAL_GPIO_WritePin(GPIOD, GPIO_PIN_15, GPIO_PIN_RESET);

                        printf("\nCertificate sent to UI successfully.\n");

                        // Send confirmation message to ESP8266
                        if (HAL_UART_Transmit(&huart5, (uint8_t *)confirm_msg, strlen(confirm_msg), HAL_MAX_DELAY) == HAL_OK)
                        {
                            printf("\nConfirmation message sent to ESP8266: Certificate received.\n");
                            break;  // Exit the loop once the process is complete
                        }
                        else
                        {
                            printf("Failed to send confirmation message to ESP8266. Retrying...\n");
                        }
                    }
                    else
                    {
                        printf("Failed to send certificate to UI. Retrying...\n");
                    }
                }
                else
                {
                    printf("Failed to receive certificate. Retrying...\n");
                }
            }
        }
    }

    return ret;
}




/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */
  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_RNG_Init();
  MX_UART4_Init();
  MX_UART5_Init();
  MX_MBEDTLS_Init();
  /* USER CODE BEGIN 2 */
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
    {

      /* USER CODE END WHILE */
  	  if(HAL_UART_Receive(&huart4, (uint8_t*)uart_rx_buffer, sizeof(uart_rx_buffer), 1000) == HAL_OK || HAL_UART_Receive(&huart4, (uint8_t*)uart_rx_buffer, sizeof(uart_rx_buffer), 50) == HAL_TIMEOUT )
  	  {

  	 if( strstr( (char*)uart_rx_buffer,"GKC" ) != NULL )
  	 {
  		 generate_csr("SETS");
  		 HAL_UART_Transmit(&huart4, final_output_buf, sizeof(final_output_buf),HAL_MAX_DELAY);
  		 memset(uart_rx_buffer, 0, sizeof(uart_rx_buffer));
  	 }
  	 else if (strstr((char*)uart_rx_buffer, "GI") != NULL )
       {
  		 // Transmit acknowledgment back to the PC
  		 // Fetch device information (Chip Model, MAC Address, IP Address, UID)
  		 esp8266_get_device_info();
  		 //HAL_UART_Transmit_IT(&huart5, (uint8_t*)msg_1, strlen(msg_1));
  		 memset(uart_rx_buffer, 0, sizeof(uart_rx_buffer));
        }
  	 else if (strstr((char*)uart_rx_buffer, "CONNECT") != NULL)
       {
         // Transmit acknowledgment back to the PC
  		 esp8266_connect_to_wifi("TP_LINK", "1122334455", "172.24.18.40", "443");
  		 printf("esp8266_connect_to_wifi called");
  	   //HAL_UART_Transmit_IT(&huart5, (uint8_t*)msg_2, strlen(msg_2));
  	   memset(uart_rx_buffer, 0, sizeof(uart_rx_buffer));
       }
      else if (strstr((char*)uart_rx_buffer, "GDC") != NULL)
       {
  	   // Transmit acknowledgment back to the PC
         receive_certificate();
  	   memset(uart_rx_buffer, 0, sizeof(uart_rx_buffer));
       }
      else{printf("i am in main while loop\n");}
      /* USER CODE BEGIN 3 */
    }
    /* USER CODE END 3 */
  }


    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 120;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 5;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */
  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */
  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */
  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief UART4 Initialization Function
  * @param None
  * @retval None
  */
static void MX_UART4_Init(void)
{

  /* USER CODE BEGIN UART4_Init 0 */
  /* USER CODE END UART4_Init 0 */

  /* USER CODE BEGIN UART4_Init 1 */
  /* USER CODE END UART4_Init 1 */
  huart4.Instance = UART4;
  huart4.Init.BaudRate = 115200;
  huart4.Init.WordLength = UART_WORDLENGTH_8B;
  huart4.Init.StopBits = UART_STOPBITS_1;
  huart4.Init.Parity = UART_PARITY_NONE;
  huart4.Init.Mode = UART_MODE_TX_RX;
  huart4.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart4.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart4) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN UART4_Init 2 */
  /* USER CODE END UART4_Init 2 */

}

/**
  * @brief UART5 Initialization Function
  * @param None
  * @retval None
  */
static void MX_UART5_Init(void)
{

  /* USER CODE BEGIN UART5_Init 0 */
  /* USER CODE END UART5_Init 0 */

  /* USER CODE BEGIN UART5_Init 1 */
  /* USER CODE END UART5_Init 1 */
  huart5.Instance = UART5;
  huart5.Init.BaudRate = 115200;
  huart5.Init.WordLength = UART_WORDLENGTH_8B;
  huart5.Init.StopBits = UART_STOPBITS_1;
  huart5.Init.Parity = UART_PARITY_NONE;
  huart5.Init.Mode = UART_MODE_TX_RX;
  huart5.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart5.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart5) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN UART5_Init 2 */
  /* USER CODE END UART5_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14, GPIO_PIN_RESET);

  /*Configure GPIO pins : PD11 PD12 PD13 PD14 */
  GPIO_InitStruct.Pin = GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
