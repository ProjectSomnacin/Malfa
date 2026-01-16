#include <pico.h>
#include <stdio.h>
#include <string.h>

#include <pico/stdlib.h>
#include <pico/multicore.h>
#include <hardware/clocks.h>

#include "macros.h"

#include "../include/salina.h"

void injectToAddr(uint8_t dev, uint8_t addr, uint8_t isRead){
  uint32_t data = (uint32_t)dev | ((uint32_t)addr << 8) | ((uint32_t)isRead << 16);
  multicore_fifo_push_blocking(data);
}

void core2(){
  // debug("launching rx listener!");
  salina_tunnel_uart_rx();
}

int main(){
  int err = 0;
  int res = 0;
  
  set_sys_clock_khz(198e3, true);

  stdio_init_all();
  // Wait for a while. Otherwise, USB CDC doesn't print all printfs.
  sleep_ms(2000);
  info("Hello from Malfa build: %s",BUILD_TYPE);

  cretassure(!(res = salina_init()),"Failed to init salina with err=%d",res);

  if (salina_reset()){
    debug("reset ok!");
  }else{
    debug("reset fail");
  }

  while (!salina_exploit()){
    error("exploit failed, retrying!");
    salina_reset();
  }

  cretassure(salina_is_exploited(),"exploit failed wtf!?");
  info("Salina is exploited now!");

  multicore_launch_core1(core2);

  {
    debug("dropping into shell");
    salina_tunnel_uart_tx();
  }


  info("Done");
  while (1){
    tight_loop_contents();
  } 
error:
  info("Failed with err=%d",err);
  while (1){
   tight_loop_contents();
  }
  return 0;
}
