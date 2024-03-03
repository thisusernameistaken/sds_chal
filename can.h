#ifndef CAN_H
#define CAN_H

typedef enum 
{
    SERVICE_NOT_SUPPORTED=0x11,
    SUBFUNCTION_NOT_SUPPORTED=0x12,
    CONDITIONS_NOT_CORRECT=0x13,
    REQUEST_OF_OF_RANGE=0x14,
    INVALID_KEY=0x15,
    EXCEED_NUM_ATTEMPTS=0x16
} NEGATIVE_RESPONSE_CODE;

typedef enum
{
    INIT_DIAGNOSTIC_SESSION = 0x20, // DEFAULT
    RETURN_TO_NORMAL = 0x21, // DEFAULT
    SECURITY_ACCESS = 0x22, // DIAGNOSTIC
    READ_MEMORY_BY_ADDRESS = 0x23, //DIAGNOSTIC
    READ_DID_BY_ID = 0x24, //DIAGNOSTIC
    PROGRAMMING_MODE = 0x25, // DEVICE CONTROL
    REQUEST_DOWNLOAD = 0x26, //DEVICE CONTROL
    TRANSFER_DATA = 0x27, //DEVICE CONTROL
} SERVICE_ID;

void handle_can_packet(char* can_pkt);
void handle_init_packet(char* can_pkt);
void handle_return_to_normal(char* can_pkt);
void handle_read_memory_by_address(char* can_pkt);
void handle_security_access(char* can_pkt);
void handle_programming_mode(char* can_pkt);
void handle_request_download(char* can_pkt);
void handle_transfer_data(char* can_pkt);
void handle_read_did_by_id(char* can_pkt);
void send_nrc(NEGATIVE_RESPONSE_CODE nrc,SERVICE_ID service_id);
void can_send(const char* data);
void send_multi_frame(char* data, int length);
int convert_to_int(char* data);
int convert_to_short(char* data);
void gen_key();

#endif