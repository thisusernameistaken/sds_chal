
#include "can.h"
#include "protected.h"
#include "uart_pl011.h"

__attribute__((section(".protected_data"))) SESSION_LEVEL CURRENT_SESSION = DEFAULT;
__attribute__((section(".protected_data"))) int ACCESS_LEVEL = 0;
__attribute__((section(".protected_data"))) int MEM_READ_ADDRESS = 0;
__attribute__((section(".protected_data"))) int MEM_READ_LENGTH = 0;
__attribute__((section(".protected_data"))) int KEY_ATTEMPTS = 0;
__attribute__((section(".protected_data"))) int PROGRAMMING_MODE_ENABLED = 0;
__attribute__((section(".protected_data"))) int DOWNLOAD_SIZE = 0;
__attribute__((section(".protected_data"))) int DOWNLOAD_ADDR = 0;
__attribute__((section(".protected_data"))) int DATA_READ_BYTES = 0;
__attribute__((section(".protected_data"))) int SHOULD_EXEC = 0;
__attribute__((section(".protected_data"))) char SEED[5];
__attribute__((section(".protected_data"))) char KEY[5];
__attribute__((section(".protected_data"))) char DID[5][0x20] = {
                                                "PLAYOFF-RONDO",
                                                "BATTELLE",
                                                "2024",
                                                "1RITBPR58593R2024",
                                                "ritsec{FAKE_FLAG_WRONG_DID}"
                                            };

