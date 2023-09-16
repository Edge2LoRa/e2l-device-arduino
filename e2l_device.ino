#include <Crypto.h>
#include <SHA256.h>
#include <string.h>
#include "Arduino.h"
#include "LoRaWan_APP.h"
#include "uECC.h"

#define HASH_SIZE 32

//
//  E2LORA DEVICE
//

/*
 * set LoraWan_RGB to Active,the RGB active in loraWan
 * RGB red means sending;
 * RGB purple means joined done;
 * RGB blue means RxWindow1;
 * RGB yellow means RxWindow2;
 * RGB green means received done;
 */

/* OTAA para*/
uint8_t devEui[] = {0x00, 0x27, 0x2A, 0x49, 0x19, 0x3A, 0x3A, 0x6A};
uint8_t appEui[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t appKey[] = {0x75, 0xF4, 0x21, 0x25, 0xC6, 0xCD, 0x29, 0xA7, 0x74, 0x3C, 0xB4, 0xBA, 0x95, 0xD6, 0x08, 0xB9};

/* ABP para*/
uint8_t nwkSKey[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t appSKey[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint32_t devAddr = (uint32_t)0x00000000;

/* E2L keys */
#define AES_KEY_SIZE 16
uint8_t edgeSIntKey[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t edgeSEncKey[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*LoraWan channelsmask, default channels 0-7*/
uint16_t userChannelsMask[6] = {0x00FF, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

/*LoraWan region, select in arduino IDE tools*/
LoRaMacRegion_t loraWanRegion = ACTIVE_REGION;

/*LoraWan Class, Class A and Class C are supported*/
DeviceClass_t loraWanClass = LORAWAN_CLASS;

/*the application data transmission duty cycle.  value in [ms].*/
uint32_t appTxDutyCycle = 10000;

/*OTAA or ABP*/
bool overTheAirActivation = LORAWAN_NETMODE;

/*ADR enable*/
bool loraWanAdr = LORAWAN_ADR;

/* set LORAWAN_Net_Reserve ON, the node could save the network info to flash,
 * when node reset not need to join again */
bool keepNet = LORAWAN_NET_RESERVE;

/* Indicates if the node is sending confirmed or unconfirmed messages */
bool isTxConfirmed = LORAWAN_UPLINKMODE;

/* Application port */
#define DEFAULT_APP_PORT 2
#define DEFAULT_E2L_JOIN_PORT 3
#define DEFAULT_E2L_APP_PORT 4
uint8_t appPort;
/*!
 * Number of trials to transmit the frame, if the LoRaMAC layer did not
 * receive an acknowledgment. The MAC performs a datarate adaptation,
 * according to the LoRaWAN Specification V1.0.2, chapter 18.4, according
 * to the following table:
 *
 * Transmission nb | Data Rate
 * ----------------|-----------
 * 1 (first)       | DR
 * 2               | DR
 * 3               | max(DR-1,0)
 * 4               | max(DR-1,0)
 * 5               | max(DR-2,0)
 * 6               | max(DR-2,0)
 * 7               | max(DR-3,0)
 * 8               | max(DR-3,0)
 *
 * Note, that if NbTrials is set to 1 or 2, the MAC will not decrease
 * the datarate, in case the LoRaMAC layer did not receive an acknowledgment
 */
uint8_t confirmedNbTrials = 4;

/*
 *  EDGE2LoRa Support
 */
static int RNG(uint8_t* dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or
  // connected to a source of random noise). This can take a long time to
  // generate random data if the result of analogRead(0) doesn't change very
  // frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }

      if (count == 0) {
        val = (val << 1) | (init & 0x01);
      } else {
        val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using
  // SHA-256 or similar.
  return 1;
}

void print_bytes_array(uint8_t* bytes, int bytes_len) {
  int i;
  Serial.printf("[");
  for (i = 0; i < bytes_len; i++) {
    Serial.printf("%d", bytes[i]);
    if (i < bytes_len - 1) {
      Serial.printf(", ");
    }
  }
  Serial.printf("]\n");
}

void print_bytes(uint8_t* bytes, int bytes_len) {
  int i;
  for (i = 0; i < bytes_len; i++) {
    if (i != 0 && i % 5 == 0) {
      printf("\n");
    }
    printf("0x%2X", bytes[i]);
    if (i != bytes_len - 1) {
      printf(",\t");
    }
  }
  printf("\n\n");
}

// Edge2LoRa State
#define E2L_INIT 0
#define E2L_REQUESTED 1
#define E2L_ENABLED 2
uint8_t e2l_state = E2L_INIT;

// ECC utils
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
const struct uECC_Curve_t* curve = uECC_secp256r1();
uint8_t private_key[PRIVATE_KEY_SIZE] = {0x00};
uint8_t public_key[PUBLIC_KEY_SIZE] = {0x00};
uint8_t compressed_public_key[PRIVATE_KEY_SIZE + 1] = {0x00};

/*
 *  Prepares the payload of the frame
 */
static void prepareTxFrame(uint8_t port) {
  // uint8_t test[] = "test";
  long randNumber = random(15, 30);
  switch (port) {
    case DEFAULT_APP_PORT:
    case DEFAULT_E2L_APP_PORT:
      appDataSize = 1;
      appData[0] = (uint8_t) randNumber;
      // appData[0] = 0;
      // appData[1] = 1;
      // appData[2] = 2;
      // appData[3] = 3;
      // appData[4] = 4;
      // memcpy(appData, test, 5);
      Serial.printf("Send: %d", appData[0]);
      break;
    case DEFAULT_E2L_JOIN_PORT:
      uECC_make_key(public_key, private_key, curve);
      uECC_compress((const uint8_t*)public_key, compressed_public_key, curve);
      appDataSize = PRIVATE_KEY_SIZE + 1;
      memcpy(appData, compressed_public_key, appDataSize);
      break;
  }
  appPort = port;
}

void setup() {
  Serial.begin(115200);
  deviceState = DEVICE_STATE_INIT;
  LoRaWAN.ifskipjoin();
  // E2L Support
  uECC_set_rng(&RNG);
}

void loop() {
  switch (deviceState) {
    case DEVICE_STATE_INIT:
      printDevParam();
      LoRaWAN.init(loraWanClass, loraWanRegion);
      deviceState = DEVICE_STATE_JOIN;
      break;
    case DEVICE_STATE_JOIN:
      LoRaWAN.join();
      break;
    case DEVICE_STATE_SEND:
      switch (e2l_state) {
        case E2L_INIT:
          prepareTxFrame(DEFAULT_E2L_JOIN_PORT);
          e2l_state = E2L_REQUESTED;
          break;
        case E2L_REQUESTED:
          prepareTxFrame(DEFAULT_APP_PORT);
          break;
        case E2L_ENABLED:
          prepareTxFrame(DEFAULT_E2L_APP_PORT);
          break;
      }
      LoRaWAN.send();
      // overTheAirActivation = true;
      deviceState = DEVICE_STATE_CYCLE;
      break;
    case DEVICE_STATE_CYCLE:
      // Schedule next packet transmission
      txDutyCycleTime = appTxDutyCycle + randr(0, APP_TX_DUTYCYCLE_RND);
      LoRaWAN.cycle(txDutyCycleTime);
      deviceState = DEVICE_STATE_SLEEP;
      break;
    case DEVICE_STATE_SLEEP:
      LoRaWAN.sleep();
      break;
    default:
      deviceState = DEVICE_STATE_INIT;
      break;
  }
}

/*
 *  HANDLE DOWNLINK FRAMES
 */
void downLinkDataHandle(McpsIndication_t* mcpsIndication) {
  // Serial.printf("Received downlink: %s, RXSIZE %d, PORT %d, DATA:
  // \n",mcpsIndication->RxSlot?"RXWIN2":"RXWIN1",mcpsIndication->BufferSize,mcpsIndication->Port);
  uint8_t buffer_size = mcpsIndication->BufferSize;
  uint8_t buffer[buffer_size];
  uint8_t g_as_gw[PUBLIC_KEY_SIZE];
  uint8_t edge_s_key[PRIVATE_KEY_SIZE];

  SHA256 hash_context;
  uint8_t hash_buffer_int[PRIVATE_KEY_SIZE + 1] = {0x00};
  uint8_t hash_buffer_enc[PRIVATE_KEY_SIZE + 1] = {0x01};
  uint8_t hash_result_int[HASH_SIZE];
  uint8_t hash_result_enc[HASH_SIZE];
  memcpy(buffer, mcpsIndication->Buffer, buffer_size);

  switch (mcpsIndication->Port) {
    case DEFAULT_E2L_JOIN_PORT:
      uECC_decompress((const uint8_t*)buffer, g_as_gw, curve);
      uECC_shared_secret((const uint8_t*)g_as_gw, (const uint8_t*)private_key,
                         edge_s_key, curve);

      memcpy(hash_buffer_int + 1, edge_s_key, PRIVATE_KEY_SIZE);
      memcpy(hash_buffer_enc + 1, edge_s_key, PRIVATE_KEY_SIZE);

      hash_context.update(hash_buffer_int, PRIVATE_KEY_SIZE + 1);
      hash_context.finalize(edgeSIntKey, AES_KEY_SIZE);
      hash_context.reset();
      hash_context.update(hash_buffer_enc, PRIVATE_KEY_SIZE + 1);
      hash_context.finalize(edgeSEncKey, AES_KEY_SIZE);
      hash_context.clear();

      Serial.print("EdgeSIntKey");
      print_bytes_array(edgeSIntKey, AES_KEY_SIZE);

      Serial.print("EdgeSEncKey");
      print_bytes_array(edgeSEncKey, AES_KEY_SIZE);
      LoRaWAN.enableEdge2LoRa(edgeSIntKey, edgeSEncKey);
      e2l_state = E2L_ENABLED;
      break;
    default:
      break;
  }
}