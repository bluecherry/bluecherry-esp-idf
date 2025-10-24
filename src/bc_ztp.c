/**
 * @file BlueCherryZTP.cpp
 * @author Daan Pape <daan@dptechnics.com>
 * @author Thibo Verheyde <thibo@dptechnics.com>
 * @date 14 Jan 2025
 * @copyright DPTechnics bv
 * @brief BlueCherry ZTP (Zero Touch Provisioning) library.
 *
 * @section LICENSE
 *
 * Copyright (C) 2025, DPTechnics bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of DPTechnics bv nor the names of its contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *   4. This software, with or without modification, must only be used with a
 *      Walter board from DPTechnics bv.
 *
 *   5. Any software provided in binary form under this license must not be
 *      reverse engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY DPTECHNICS BV “AS IS” AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DPTECHNICS BV OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the implementation of the BlueCherry ZTP (Zero Touch
 * Provisioning) library.
 */

#include <bootloader_random.h>
#include <esp_random.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <stdio.h>
#include <stdbool.h>
#include <esp_log.h>
#include <string.h>
#include <sys/types.h>
#include <lwip/sockets.h>
#include <netdb.h>

#include "bc_ztp.h"
#include "bc_ztp_cbor.h"

#define ZTP_SERV_ADDR "coap.bluecherry.io"
#define ZTP_SERV_PORT "5688"
#define ZTP_SERV_API_VERSION "v1"
#define ZTP_SERV_DEVID_PATH "devid"
#define ZTP_SERV_CSR_PATH "sign"

int ztp_hardware_random_entropy_func(void* data, unsigned char* output, size_t len)
{
  esp_fill_random(output, len);
  return 0;
}

bool ztp_finish_csr_gen(bool result)
{
  mbedtls_pk_free(&ztp_mbKey);
  mbedtls_entropy_free(&ztp_mbEntropy);
  mbedtls_ctr_drbg_free(&ztp_mbCtrDrbg);
  mbedtls_x509write_csr_free(&ztp_mbCsr);

  if(!result) {
    ztp_pkeyBuf[0] = '\0';
    ztp_certBuf[0] = '\0';
  }

  return result;
}

bool ztp_seed_random(bool rfEnabled)
{
  if(!rfEnabled) {
    bootloader_random_enable();
  }

  int ret = mbedtls_ctr_drbg_seed(&ztp_mbCtrDrbg, ztp_hardware_random_entropy_func, &ztp_mbEntropy,
                                  NULL, 0);

  if(!rfEnabled) {
    bootloader_random_disable();
  }
  return ret == 0;
}

bool ztp_begin(const char* typeId, const char* caCert, uint8_t* mac)
{
  if(typeId == NULL || strlen(typeId) != BLUECHERRY_ZTP_ID_LEN || caCert == NULL) {
    return false;
  }

  ztp_bcTypeId = typeId;

  mbedtls_ssl_init(&ztp_ssl_ctx);
  mbedtls_ssl_config_init(&ztp_ssl_conf);
  mbedtls_ctr_drbg_init(&ztp_mbCtrDrbg);
  mbedtls_entropy_init(&ztp_mbEntropy);
  mbedtls_x509_crt_init(&ztp_cacert);

  int ret = mbedtls_ctr_drbg_seed(&ztp_mbCtrDrbg, mbedtls_entropy_func, &ztp_mbEntropy, mac, 6);
  if(ret != 0) {
    ESP_LOGE("ZTP", "Could not seed RNG: -%04X", -ret);
    return false;
  }

  ret = mbedtls_x509_crt_parse(&ztp_cacert, (const uint8_t*) caCert, strlen(caCert) + 1);
  if(ret != 0) {
    return false;
  }

  ret = mbedtls_ssl_config_defaults(&ztp_ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if(ret != 0) {
    return false;
  }

  mbedtls_ssl_conf_read_timeout(&ztp_ssl_conf, 100);
  mbedtls_ssl_conf_authmode(&ztp_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&ztp_ssl_conf, &ztp_cacert, NULL);
  mbedtls_ssl_conf_rng(&ztp_ssl_conf, mbedtls_ctr_drbg_random, &ztp_mbCtrDrbg);

  ret = mbedtls_ssl_setup(&ztp_ssl_ctx, &ztp_ssl_conf);
  if(ret != 0) {
    ESP_LOGE("ZTP", "Could not setup the SSL context for use: -%04X", -ret);
    return false;
  }

  mbedtls_ssl_set_timer_cb(&ztp_ssl_ctx, &ztp_timing_ctx, mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  ret = mbedtls_ssl_set_hostname(&ztp_ssl_ctx, ZTP_SERV_ADDR);
  if(ret != 0) {
    ESP_LOGE("ZTP", "Could not set the hostname in the SSL context: -%04X", -ret);
    return false;
  }

  return true;
}

const char* ztp_get_priv_key()
{
  return ztp_pkeyBuf;
}

const unsigned char* ztp_get_csr()
{
  return ztp_csr.buffer;
}

size_t ztp_get_csr_len()
{
  return ztp_csr.length;
}

const char* ztp_get_cert()
{
  return ztp_certBuf;
}

void ztp_reset_device_id()
{
  ztp_devIdParams.count = 0;
}

bool ztp_add_device_id_parameter_string(BlueCherryZtpDeviceIdType type, const char* str)
{
  if(str == NULL || ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI:
    ztp_devIdParams.param[ztp_devIdParams.count].type = BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI;
    strncpy(ztp_devIdParams.param[ztp_devIdParams.count].value.imei, str, BLUECHERRY_ZTP_IMEI_LEN);
    ztp_devIdParams.param[ztp_devIdParams.count].value.imei[BLUECHERRY_ZTP_IMEI_LEN] = '\0';
    ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

bool ztp_add_device_id_parameter_blob(BlueCherryZtpDeviceIdType type, const unsigned char* blob)
{
  if(blob == NULL || ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC:
    ztp_devIdParams.param[ztp_devIdParams.count].type = BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC;
    memcpy(ztp_devIdParams.param[ztp_devIdParams.count].value.mac, blob, BLUECHERRY_ZTP_MAC_LEN);
    ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

bool ztp_add_device_id_parameter_number(BlueCherryZtpDeviceIdType type, unsigned long long number)
{
  if(ztp_devIdParams.count >= BLUECHERRY_ZTP_MAX_DEVICE_ID_PARAMS) {
    return false;
  }

  switch(type) {
  case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE:
    ztp_devIdParams.param[ztp_devIdParams.count].type = BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE;
    ztp_devIdParams.param[ztp_devIdParams.count].value.oobChallenge = number;
    ztp_devIdParams.count += 1;
    break;

  default:
    return false;
  }

  return true;
}

int bluecherry_ztp_mbed_dtls_read(unsigned char* buf, size_t len)
{
  int ret;

  while(true) {
    ret = mbedtls_ssl_read(&ztp_ssl_ctx, buf, len);
    if(ret > 0) {
      return ret;
    }

    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    if(ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      return ret;
    }

    ESP_LOGE("ZTP", "Could not read from the BlueCherry ZTP server: -%04X", -ret);
    return ret;
  }
}

int bluecherry_ztp_mbed_dtls_write(const unsigned char* buf, size_t len)
{
  int ret;

  do {
    ret = mbedtls_ssl_write(&ztp_ssl_ctx, buf, len);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    if(ret < 0) {
      ESP_LOGE("ZTP", "Could not write to the BlueCherry ZTP server: -%04X", -ret);
      return ret;
    }

    return ret;
  } while(true);
}

int bluecherry_ztp_dtls_send(void* ctx, const unsigned char* buf, size_t len)
{
  int sock = *(int*) ctx;
  int ret = send(sock, buf, len, 0);

  if(ret < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }

  return ret;
}

int bluecherry_ztp_dtls_recv(void* ctx, unsigned char* buf, size_t len)
{
  int sock = *(int*) ctx;
  int ret = recv(sock, buf, len, 0);

  if(ret < 0) {
    if(errno == EWOULDBLOCK || errno == EAGAIN) {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if(errno == ETIMEDOUT) {
      return MBEDTLS_ERR_SSL_TIMEOUT;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }

  return ret;
}

bool bluecherry_ztp_rxtx(uint8_t* tx_buf, uint16_t tx_len, uint8_t* rx_buf, uint16_t* rx_len)
{
  uint8_t no_payload_hdr[14];
  uint8_t* data = tx_len == 0 ? no_payload_hdr : tx_buf;
  size_t data_len = tx_len == 0 ? 14 : tx_len;

  static uint32_t cur_message_id = 0;
  static uint32_t last_acked_message_id = 0;
  static time_t last_tx_time = 0;

  if(data_len < 14) {
    ESP_LOGE("ZTP", "Cannot send CoAP message smaller than %dB", 14);
    return false;
  }

  if(last_acked_message_id > cur_message_id) {
    last_acked_message_id -= 0xffff;
  }

  data[0] = 0x40;
  data[1] = 0x01;
  data[2] = cur_message_id >> 8;
  data[3] = cur_message_id & 0xFF;
  data[4] = 0xB2;
  data[5] = 0x76;
  data[6] = 0x31;
  data[7] = 0x05;
  data[8] = 0x64;
  data[9] = 0x65;
  data[10] = 0x76;
  data[11] = 0x69;
  data[12] = 0x64;
  data[13] = 0xFF;

  double timeout = 2.0 * (1 + (rand() / (RAND_MAX + 1.0)) * (1.5 - 1));

  for(uint8_t attempt = 1; attempt <= 4; ++attempt) {
    last_tx_time = time(NULL);

    if(bluecherry_ztp_mbed_dtls_write(data, data_len) < 0) {
      return false;
    }

    while(true) {
      int ret = bluecherry_ztp_mbed_dtls_read(rx_buf, 1024);
      if(ret > 0) {
        *rx_len = (uint16_t) ret;
        return true;
      } else if(ret != MBEDTLS_ERR_SSL_TIMEOUT) {
        return false;
      }

      if(difftime(time(NULL), last_tx_time) >= timeout) {
        break;
      }
    }

    timeout *= 2;
  }

  return false;
}

bool ztp_request_device_id()
{
  int ret;
  uint8_t cborBuf[256];
  uint8_t coapData[16];
  ZTP_CBOR cbor;

  if(ztp_cbor_init(&cbor, cborBuf, sizeof(cborBuf)) < 0) {
    printf("Failed to init CBOR buffer\n");
    return false;
  };

  // Start the CBOR array
  if(ztp_cbor_start_array(&cbor, 2) < 0) {
    printf("Failed to start CBOR array\n");
    return false;
  }

  // Encode type ID value
  if(ztp_cbor_encode_string(&cbor, ztp_bcTypeId) < 0) {
    printf("Failed to encode typeId value\n");
    return false;
  }

  // Start the CBOR map (key-value pairs)
  if(ztp_cbor_start_map(&cbor, ztp_devIdParams.count) < 0) {
    printf("Failed to start CBOR map\n");
    return false;
  }

  for(size_t i = 0; i < ztp_devIdParams.count; i++) {

    int type = (int) ztp_devIdParams.param[i].type;
    if(ztp_cbor_encode_int(&cbor, type) < 0) {
      printf("Failed to encode param type (%u)\n", type);
      return false;
    }

    switch(ztp_devIdParams.param[i].type) {
    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_IMEI: {
      // Encode IMEI number (15 characters)
      uint64_t imei = strtoull(ztp_devIdParams.param[i].value.imei, NULL, 10);
      if(ztp_cbor_encode_uint64(&cbor, imei) < 0) {
        printf("Failed to encode IMEI number\n");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_MAC: {
      // Encode MAC address (6 bytes)
      if(ztp_cbor_encode_bytes(&cbor, (uint8_t*) ztp_devIdParams.param[i].value.mac, 6) < 0) {
        printf("Failed to encode MAC address\n");
        return false;
      }
    } break;

    case BLUECHERRY_ZTP_DEVICE_ID_TYPE_OOB_CHALLENGE: {
      // Encode OOB challenge (64 bit unsigned int)
      uint64_t oobChallenge = ztp_devIdParams.param[0].value.oobChallenge;
      if(ztp_cbor_encode_uint64(&cbor, oobChallenge) < 0) {
        printf("Failed to encode OOB challenge\n");
        return false;
      }
    } break;

    default:
      break;
    }
  }

  struct addrinfo hints = { 0 };
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo* res = NULL;
  ret = getaddrinfo(ZTP_SERV_ADDR, ZTP_SERV_PORT, &hints, &res);
  if(ret != 0 || res == NULL) {
    ESP_LOGE("ZTP", "DNS lookup failed: %d", ret);
    if(res)
      freeaddrinfo(res);
    return false;
  }

  int socket_num = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(socket_num < 0) {
    ESP_LOGE("ZTP", "socket() failed: %s", strerror(errno));
    freeaddrinfo(res);
    return false;
  }

  struct timeval timeout;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  setsockopt(socket_num, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  ret = connect(socket_num, res->ai_addr, res->ai_addrlen);
  if(ret != 0) {
    ESP_LOGE("ZTP", "connect() failed: %s", strerror(errno));
    close(socket_num);
    freeaddrinfo(res);
    return false;
  }
  freeaddrinfo(res);

  mbedtls_ssl_session_reset(&ztp_ssl_ctx);
  mbedtls_ssl_set_bio(&ztp_ssl_ctx, &socket_num, bluecherry_ztp_dtls_send, bluecherry_ztp_dtls_recv,
                      NULL);

  time_t t_start = time(NULL);
  while((ret = mbedtls_ssl_handshake(&ztp_ssl_ctx)) != 0) {
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
       ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      if(difftime(time(NULL), t_start) >= 30) {
        ESP_LOGE("ZTP", "DTLS handshake timed out");
        return false;
      }

      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    ESP_LOGE("ZTP", "DTLS handshake failed: -0x%04X", -ret);
    return false;
  }

  uint8_t in_buf[1024];
  uint16_t in_len = 0;
  ret = bluecherry_ztp_rxtx(cborBuf, ztp_cbor_size(&cbor), in_buf, &in_len);
  if(ret < 1) {
    ESP_LOGE("ZTP", "Failed to receive response from ZTP COAP server");
    return false;
  }

  // Print received CoAP data in hex and halt
  printf("Received CoAP response (%d bytes):\n", ret);
  for(int i = 0; i < ret; i++) {
    printf("%02X ", in_buf[i]);
    if((i + 1) % 16 == 0)
      printf("\n"); // nice 16-byte formatting
  }
  printf("\n");
  fflush(stdout);

  ESP_LOGI("ZTP", "Halting before device ID decode.");
  while(1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  } // infinite loop to halt

  // ret =
  //     ztp_cbor_decode_device_id(coapData, rsp.data.coapResponse.length, _bcDevId,
  //     sizeof(_bcDevId));
  // if(ret < 0) {
  //   printf("Failed to decode device id: %d\n", ret);
  //   return false;
  // }

  return true;
}

// bool ztp_generate_key_and_csr(bool rfEnabled)
// {
//   int ret;
//   uint8_t csrBuf[BLUECHERRY_ZTP_CERT_BUF_SIZE];

//   if(ztp_bcTypeId == NULL || strlen(ztp_bcTypeId) != BLUECHERRY_ZTP_ID_LEN ||
//      strlen(ztp_bcDevId) != BLUECHERRY_ZTP_ID_LEN) {
//     return false;
//   }

//   mbedtls_pk_init(&ztp_mbKey);
//   mbedtls_entropy_init(&ztp_mbEntropy);
//   mbedtls_ctr_drbg_init(&ztp_mbCtrDrbg);
//   mbedtls_x509write_csr_init(&ztp_mbCsr);

//   if(!_seedRandom(rfEnabled)) {
//     return _finishCsrGen(false);
//   }

//   if(mbedtls_pk_setup(&ztp_mbKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
//     return _finishCsrGen(false);
//   }

//   if(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(ztp_mbKey),
//                          mbedtls_ctr_drbg_random, &ztp_mbCtrDrbg) != 0) {
//     return _finishCsrGen(false);
//   }

//   if(mbedtls_pk_write_key_pem(&ztp_mbKey, (unsigned char*) ztp_pkeyBuf,
//                               BLUECHERRY_ZTP_PKEY_BUF_SIZE) != 0) {
//     return _finishCsrGen(false);
//   }

//   mbedtls_x509write_csr_set_md_alg(&ztp_mbCsr, MBEDTLS_MD_SHA256);
//   mbedtls_x509write_csr_set_key(&ztp_mbCsr, &ztp_mbKey);

//   snprintf(ztp_subjBuf, BLUECHERRY_ZTP_SUBJ_BUF_SIZE, "C=BE,CN=%s.%s", ztp_bcTypeId,
//   ztp_bcDevId); if(mbedtls_x509write_csr_set_subject_name(&ztp_mbCsr, ztp_subjBuf) != 0) {
//     return _finishCsrGen(false);
//   }

//   ret = mbedtls_x509write_csr_der(&ztp_mbCsr, csrBuf, BLUECHERRY_ZTP_CERT_BUF_SIZE,
//                                   mbedtls_ctr_drbg_random, &ztp_mbCtrDrbg);
//   if(ret < 0) {
//     printf("Failed to write CSR: -0x%04X\n", -ret);
//     return _finishCsrGen(false);
//   }

//   size_t offset = BLUECHERRY_ZTP_CERT_BUF_SIZE - ret;
//   _csr.length = ret;
//   memcpy(_csr.buffer, csrBuf + offset, _csr.length);

//   return _finishCsrGen(true);
// }

// bool ztp_request_signed_certificate()
// {
//   int ret;
//   uint8_t buf[BLUECHERRY_ZTP_CERT_BUF_SIZE];
//   uint8_t coapData[BLUECHERRY_ZTP_CERT_BUF_SIZE];
//   ZTP_CBOR cbor;

//   ztp_cbor_init(&cbor, buf, BLUECHERRY_ZTP_CERT_BUF_SIZE);
//   mbedtls_x509_crt_init(&ztp_mbCrt);

//   if(ztp_cbor_encode_bytes(&cbor, _csr.buffer, _csr.length) < 0) {
//     printf("Failed to encode CSR\n");
//     return false;
//   }

//   // Send second CoAP
//   if(!_modem->coapSetOptions(COAP_PROFILE, WALTER_MODEM_COAP_OPT_SET,
//                              WALTER_MODEM_COAP_OPT_CODE_URI_PATH, ZTP_SERV_API_VERSION)) {
//     printf("Failed to configure ZTP CoAP URI path for API version\n");
//   }

//   if(!_modem->coapSetOptions(COAP_PROFILE, WALTER_MODEM_COAP_OPT_EXTEND,
//                              WALTER_MODEM_COAP_OPT_CODE_URI_PATH, ZTP_SERV_CSR_PATH)) {
//     printf("Failed to configure ZTP CoAP URI path for CSR signing\n");
//   }

//   if(!_modem->coapSendData(COAP_PROFILE, WALTER_MODEM_COAP_SEND_TYPE_CON,
//                            WALTER_MODEM_COAP_SEND_METHOD_GET, ztp_cbor_size(&cbor), buf)) {
//     printf("Failed to send ZTP CoAP datagram\n");
//     return false;
//   }

//   int i = BLUECHERRY_ZTP_COAP_TIMEOUT;
//   printf("Awaiting ZTP CoAP ring.");
//   while(i && !_modem->coapDidRing(COAP_PROFILE, coapData, sizeof(coapData), &rsp)) {
//     printf(".");
//     DELAY(1000);
//     i--;
//   }
//   printf("\n");

//   if(i < 1) {
//     printf("Failed to receive response from ZTP COAP server\n");
//     return false;
//   }

//   size_t decodedSize;
//   ret = ztp_cbor_decode_certificate(coapData, rsp.data.coapResponse.length, buf, &decodedSize);
//   if(ret < 0) {
//     printf("Failed to decode certificate: %d\n", ret);
//     return false;
//   }

//   // Parse the DER-encoded certificate
//   ret = mbedtls_x509_crt_parse_der(&ztp_mbCrt, buf, decodedSize);
//   if(ret < 0) {
//     printf("Failed to parse DER certificate, error code: -0x%x\n", -ret);
//     mbedtls_x509_crt_free(&ztp_mbCrt);
//     return false;
//   }

//   // Convert the certificate to PEM format
//   size_t pemLen;
//   ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
//                                  ztp_mbCrt.raw.p, ztp_mbCrt.raw.len, buf,
//                                  BLUECHERRY_ZTP_CERT_BUF_SIZE, &pemLen);
//   if(ret < 0) {
//     printf("Failed to write PEM: -0x%04X\n", -ret);
//     mbedtls_x509_crt_free(&ztp_mbCrt);
//     return false;
//   }

//   memcpy(ztp_certBuf, buf, pemLen);
//   ztp_certBuf[pemLen] = '\0';

//   mbedtls_x509_crt_free(&ztp_mbCrt);
//   return true;
// }
