#ifndef SALINA_H
#define SALINA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

# define PIN_SALINA_RESET    16
# define PIN_SALINA_UART_TX  12
# define PIN_SALINA_UART_RX  13
# define UART_SALINA         uart0

typedef enum SalineErr : uint32_t{
  kSalineErrSuccess = 0,
  kSalineErrRxInputTooLong = 0xE0000002,
  kSalineErrRxInvalidChar = 0xE0000003,
  kSalineErrRxInvalidCsum = 0xE0000004,
  kSalineErrUcmdEINVAL = 0xF0000001,
  kSalineErrUcmdUnknownCmd = 0xF0000006,
} t_SalineErr;

typedef struct{
  int err;         //salina error code
  bool isOK;       //salina responds with "OK" or "NG"
  t_SalineErr res; // if > 0, then size of response, else error inside cmd_send_recv function
} t_SalinaRes;

typedef struct {
  size_t filler_multiplier;
  uint64_t pwn_delay_us;
  uint32_t post_process_ms;
} SalinaHWExploitConf;

typedef struct {
  const char *version;
  uint32_t ucmd_ua_buf_addr;
  uint8_t *shellcode;
  size_t shellcodeLen;
} SalinaExploitConf;

int salina_init (void);
void salina_cleanup(void);

bool salina_reset();
bool salina_is_exploited();
int salina_exploit();

void salina_cmd_send(const char *cmd);

void salina_tunnel_uart_tx();
void salina_tunnel_uart_rx();

#ifdef __cplusplus
}
#endif

#endif // SALINA_H