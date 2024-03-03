#include <string.h>
#include "uart_pl011.h"
#include "can.h"
#include "protected.h"

void handle_can_packet(char* can_pkt){
    // char response[0x30];
    // memset(response,0,0x30);
    // strcpy(response,"Recieved PACKET: ");
    // strcat(response,can_pkt);
    // strcat(response,"\n");
    // uart_write(response);

    //multi-frame
    if (can_pkt[0] == 0x30){
        if (MEM_READ_ADDRESS!=0 && MEM_READ_LENGTH !=0){
            send_multi_frame((char*)MEM_READ_ADDRESS,MEM_READ_LENGTH);
            MEM_READ_ADDRESS = 0;
            MEM_READ_LENGTH = 0;
            return;
        }//todo
    }
    // recieve multi_frame
    else if ((can_pkt[0]&0xf0)==0x20){
        if (DOWNLOAD_SIZE!=0 && DATA_READ_BYTES< DOWNLOAD_SIZE && DOWNLOAD_ADDR != 0){
            if (DATA_READ_BYTES+7>DOWNLOAD_SIZE){
                memcpy((char*)(DOWNLOAD_ADDR+DATA_READ_BYTES),&can_pkt[1],DOWNLOAD_SIZE-DATA_READ_BYTES);
                DATA_READ_BYTES += DOWNLOAD_SIZE-DATA_READ_BYTES;
            }
            else{
                memcpy((char*)(DOWNLOAD_ADDR+DATA_READ_BYTES),&can_pkt[1],7);
                DATA_READ_BYTES += 7;
            }
        }
        if(DOWNLOAD_ADDR != 0 && DATA_READ_BYTES == DOWNLOAD_SIZE){
            if (SHOULD_EXEC){
                ((void (*)(void))DOWNLOAD_ADDR)();
                SHOULD_EXEC=0;
            }
            DATA_READ_BYTES=0;
            DOWNLOAD_SIZE=0;
        }
        return;
    }

    if (can_pkt[1] == INIT_DIAGNOSTIC_SESSION){
        handle_init_packet(can_pkt);
    }
    else if (can_pkt[1] == SECURITY_ACCESS){
        handle_security_access(can_pkt);
    }
    else if (can_pkt[1] == RETURN_TO_NORMAL){
        handle_return_to_normal(can_pkt);
    }
    else if (can_pkt[1] == READ_MEMORY_BY_ADDRESS){
        handle_read_memory_by_address(can_pkt);
    }
    else if (can_pkt[1] == READ_DID_BY_ID){
        handle_read_did_by_id(can_pkt);
    }
    else if (can_pkt[1] == PROGRAMMING_MODE){
        handle_programming_mode(can_pkt);
    }
    else if (can_pkt[1] == REQUEST_DOWNLOAD){
        handle_request_download(can_pkt);
    }
    else if (can_pkt[1] == TRANSFER_DATA){
        handle_transfer_data(can_pkt);
    }
    else {
        send_nrc(SERVICE_NOT_SUPPORTED,can_pkt[1]);
    }
}

void handle_init_packet(char* can_pkt){
    int length = can_pkt[0];
    int level = can_pkt[2];
    if (level>3||level<1){
        send_nrc(REQUEST_OF_OF_RANGE,INIT_DIAGNOSTIC_SESSION);
        return;
    }
    if (level==1){
        CURRENT_SESSION = DEFAULT;
    }
    else if (level == 2){
        CURRENT_SESSION = DIAGNOSTIC;
    }
    else if (level == 3){
        if (CURRENT_SESSION != DIAGNOSTIC || ACCESS_LEVEL != 1){
            send_nrc(CONDITIONS_NOT_CORRECT,INIT_DIAGNOSTIC_SESSION);
            return;
        }
        else{
            CURRENT_SESSION = DEVICE_CONTROL;
        }
    }
    char can_response[8];
    memset(can_response,0,8);
    can_response[0] = 2;
    can_response[1] = (char)INIT_DIAGNOSTIC_SESSION+0x40;
    can_response[2] = (char)CURRENT_SESSION;
    can_send(can_response);
    return;
}

void handle_return_to_normal(char* can_pkt){
    CURRENT_SESSION = DEFAULT;
    MEM_READ_ADDRESS = 0;
    MEM_READ_LENGTH = 0;
    ACCESS_LEVEL = 0;
    KEY_ATTEMPTS = 0;
    PROGRAMMING_MODE_ENABLED = 0;
    DOWNLOAD_SIZE = 0;
    DOWNLOAD_ADDR = 0;
    DATA_READ_BYTES = 0;
    SHOULD_EXEC = 0;

    char can_response[8];
    memset(can_response,0,8);
    can_response[0] = 1;
    can_response[1] = (char)RETURN_TO_NORMAL+0x40;
    can_send(can_response);
    return;
}

void handle_read_memory_by_address(char* can_pkt){
    char can_response[8];
    memset(can_response,0,8);
    if (CURRENT_SESSION != DIAGNOSTIC){
        send_nrc(CONDITIONS_NOT_CORRECT,READ_MEMORY_BY_ADDRESS);
        return;
    }
    int length = can_pkt[0];
    if (length<7){
        send_nrc(SUBFUNCTION_NOT_SUPPORTED,READ_MEMORY_BY_ADDRESS);
        return;
    }
    int mem_address = convert_to_int(&can_pkt[2]);
    int read_length = convert_to_short(&can_pkt[6]);

    if (mem_address<0x60010000){
        send_nrc(REQUEST_OF_OF_RANGE,READ_MEMORY_BY_ADDRESS);
        return;
    }
    if (mem_address>=0x61000000 && mem_address<0x70000000){
        send_nrc(REQUEST_OF_OF_RANGE,READ_MEMORY_BY_ADDRESS);
        return;
    }

    char* result = (char*)mem_address;
    
    if (read_length>6){
        can_response[0] = 0x10;
        can_response[1] = read_length;
        for (int i=0;i<6;i++){
            can_response[i+2] = result[i];
        }
        can_send(can_response);
        MEM_READ_ADDRESS = (int)mem_address+6;
        MEM_READ_LENGTH = read_length-6;
    }
    else{
        memset(can_response,0,8);
        can_response[0] = read_length+1;
        can_response[1] = (char)READ_MEMORY_BY_ADDRESS+0x40;
        for (int i=0;i<read_length;i++){
            can_response[i+2] = result[i];
        }
        can_send(can_response);
    }
    
}

void handle_read_did_by_id(char* can_pkt){
    char can_response[8];
    memset(can_response,0,8);
    if (CURRENT_SESSION != DIAGNOSTIC){
        send_nrc(CONDITIONS_NOT_CORRECT,READ_DID_BY_ID);
        return;
    }
    int did_index = can_pkt[2];
    if (did_index<0 || did_index>4){
        send_nrc(REQUEST_OF_OF_RANGE,READ_DID_BY_ID);
        return;
    }
    char* result_did = DID[did_index];
    int read_length = strlen(result_did);
    if (read_length>6){
        can_response[0] = 0x10;
        can_response[1] = read_length;
        for (int i=0;i<6;i++){
            can_response[i+2] = result_did[i];
        }
        can_send(can_response);
        MEM_READ_ADDRESS = (int)result_did+6;
        MEM_READ_LENGTH = read_length-6;
    }
    else{
        memset(can_response,0,8);
        can_response[0] = read_length+2;
        can_response[1] = (char)READ_DID_BY_ID+0x40;
        for (int i=0;i<read_length;i++){
            can_response[i+2] = result_did[i];
        }
        can_send(can_response);
    }
}
static unsigned int lcg_state = 0x3BADB015;
char lcg_next(){
    lcg_state = (1664525 * lcg_state + 1013904223) & 0xffffffff;
    return (char)lcg_state;
}

void gen_seed(){
    memset(SEED,0,8);
    for (int i=0;i<4;i++){
        SEED[i] = lcg_next();
    }
    SEED[4]=0xB0;
}

void gen_key(){
    char thing[4] = "GANG";
    int total=0;
    memcpy(KEY,"RONDO",5);
    for (int i =0; i<4;i++){
        for (int j=0;j<(uint8_t)thing[i];j++){
            char x = (int8_t)(SEED[i]*KEY[i]);
            if (x==0){
                KEY[i]=0x44;
            }
            else{
                KEY[i]=x;
            }
        }
        total += KEY[i];
    }
    KEY[4]=(char)(total);
}

void handle_security_access(char* can_pkt)
{
    char can_response[8];
    memset(can_response,0,8);
    if (CURRENT_SESSION != DIAGNOSTIC){
        send_nrc(CONDITIONS_NOT_CORRECT,SECURITY_ACCESS);
        return;
    }
    int subfunction = can_pkt[2];
    if (subfunction==1){
        gen_seed();
        can_response[0] = 6;
        can_response[1] = SECURITY_ACCESS+0x40;
        can_response[2] = 1;
        memcpy(&can_response[2],SEED,5);
        can_send(can_response);
        return;
    }
    else if(subfunction==2){
        int length = can_pkt[0];
        if (length!=6){
            send_nrc(SUBFUNCTION_NOT_SUPPORTED,SECURITY_ACCESS);
            return;
        }
        if (KEY_ATTEMPTS>2){
            send_nrc(EXCEED_NUM_ATTEMPTS,SECURITY_ACCESS);
            return;
        }
        char *attempt_key = &can_pkt[3];
        gen_key();
        if (memcmp(attempt_key,KEY,5)==0){
            ACCESS_LEVEL = 1;
            can_response[0] = 2;
            can_response[1] = SECURITY_ACCESS+0x40;
            can_response[2] = 2;
            can_send(can_response);
            return;
        }
        else {
            send_nrc(INVALID_KEY,SECURITY_ACCESS);
            gen_seed();
            KEY_ATTEMPTS +=1;
            return;
        }
    }
    else {
        send_nrc(SUBFUNCTION_NOT_SUPPORTED,SECURITY_ACCESS);
        return;
    }

}

void handle_programming_mode(char* can_pkt){
    char can_response[8];
    memset(can_response,0,8);
    if (CURRENT_SESSION != DEVICE_CONTROL || ACCESS_LEVEL != 1){
        send_nrc(CONDITIONS_NOT_CORRECT,PROGRAMMING_MODE);
        return;
    }
    else{
        PROGRAMMING_MODE_ENABLED = 1;
        can_response[0] = 2;
        can_response[1] = PROGRAMMING_MODE+0x40;
        can_response[2] = 1;
        can_send(can_response);
        return;
    }
}

void handle_request_download(char* can_pkt){
    char can_response[8];
    memset(can_response,0,8);
    int length = can_pkt[0];
    if (CURRENT_SESSION != DEVICE_CONTROL || ACCESS_LEVEL != 1 || PROGRAMMING_MODE_ENABLED != 1){
        send_nrc(CONDITIONS_NOT_CORRECT,REQUEST_DOWNLOAD);
        return;
    }
    else if(length !=3){
        send_nrc(SUBFUNCTION_NOT_SUPPORTED,REQUEST_DOWNLOAD);
        return;
    }
    else {
        DOWNLOAD_SIZE = convert_to_short(&can_pkt[2]);
        can_response[0] = 3;
        can_response[1] = REQUEST_DOWNLOAD+0x40;
        memcpy(&can_response[2],&can_pkt[2],2);
        can_send(can_response);
        return;
    }
}

void handle_transfer_data(char* can_pkt){
    char can_response[8];
    memset(can_response,0,8);
    int length = can_pkt[0];
    int subfunction = can_pkt[2];
    if (CURRENT_SESSION != DEVICE_CONTROL || ACCESS_LEVEL != 1 || PROGRAMMING_MODE_ENABLED != 1){
        send_nrc(CONDITIONS_NOT_CORRECT,TRANSFER_DATA);
        return;
    }
    if (length==3 && subfunction==0x80 && DOWNLOAD_ADDR!=0){
        ((void (*)(void))DOWNLOAD_ADDR)();
    }
    if (length <4 || !(subfunction == 0 || subfunction == 0x80)){
        send_nrc(SUBFUNCTION_NOT_SUPPORTED,TRANSFER_DATA);
        return;
    }
    int starting_address = convert_to_int(&can_pkt[3]);
    if (starting_address <0x70000000 || starting_address > 0x80000000){
        send_nrc(REQUEST_OF_OF_RANGE,TRANSFER_DATA);
        return;
    }
    DOWNLOAD_ADDR = starting_address;
    DATA_READ_BYTES=0;
    if (subfunction==0x80){
        SHOULD_EXEC = 1;
    }

    if (DOWNLOAD_SIZE==1){
        memcpy((char*)DOWNLOAD_ADDR,&can_pkt[7],DOWNLOAD_SIZE);
        if (SHOULD_EXEC){
            ((void (*)(void))DOWNLOAD_ADDR)();
            SHOULD_EXEC = 0;
        }
        DOWNLOAD_ADDR = 0;
        DOWNLOAD_SIZE = 0;
        
        can_response[0] = 1;
        can_response[1] = TRANSFER_DATA+0x40;
        can_send(can_response);
        return;
    }
    memcpy((char*)DOWNLOAD_ADDR,&can_pkt[7],1); //do that one byte
    DATA_READ_BYTES = 1;
    can_response[0] = 0x30;
    can_send(can_response);
}

void send_multi_frame(char* data,int length){
    int curr_addr = (int)data;
    int end_addr = (int)data+length;
    int frame_id = 0x21;
    char can_response[8];
    while (curr_addr<end_addr){
        memset(can_response,0,8);
        can_response[0] = frame_id;
        if ((end_addr-curr_addr)<7){
            memcpy(&can_response[1],(char*)curr_addr,end_addr-curr_addr);
        }
        else{
            memcpy(&can_response[1],(char*)curr_addr,7);
        }
        can_send(can_response);
        curr_addr+=7;
        frame_id+=1;
        if (frame_id>0x2f)
            frame_id = 0x21;
    }
}

int convert_to_int(char* data){
    int res=0;
    res |= data[0]<<(8*3);
    res |= data[1]<<(8*2);
    res |= data[2]<<(8*1);
    res |= data[3];
    return res;
}

int convert_to_short(char* data){
    int res=0;
    res |= data[0]<<(8*1);
    res |= data[1];
    return res;
}

void send_nrc(NEGATIVE_RESPONSE_CODE nrc,SERVICE_ID service_id){
    char can_response[8];
    memset(can_response,0,8);
    can_response[0] = 3;
    can_response[1] = 0x7f;
    can_response[2] = (char)service_id;
    can_response[3] = (char)nrc;
    can_send(can_response);
}

void can_send(const char* data){
    for (int i=0;i<8;i++){
        uart_putchar(data[i]);
    }
}