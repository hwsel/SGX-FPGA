// #define DATA_SIZE (128+44) //control vector size
#define MEM_SIZE 1//control vector size
#define INCR_VALUE 0

#include "xcl2.hpp"
#include <vector>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <iostream>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <time.h>

#define UNIXSTR_PATH "/tmp/unix.str"


int main(int argc, char** argv)
{

    size_t key_size_bytes = sizeof(uint8_t) * 256;
    size_t chal_size_bytes = sizeof(uint8_t) * 16;
    size_t msg_size_bytes = sizeof(uint8_t) * 256;
    size_t encryted_msg_size_bytes = sizeof(uint8_t) * 300;
    size_t encryted_msg_key_size_bytes = sizeof(uint8_t) * 316;

    uint8_t challenge_tmp[16]={0};

    std::vector<int, aligned_allocator<int>> challenge(256);
    std::vector<int, aligned_allocator<int>> response(16);
    std::vector<uint8_t,aligned_allocator<uint8_t>> encrypted_key(256);
    std::vector<uint8_t,aligned_allocator<uint8_t>> input_message(66000);
    std::vector<uint8_t,aligned_allocator<uint8_t>> output_message(66000);
    //std::vector<uint8_t,aligned_allocator<uint8_t>> encrypted_message(300);
    //std::vector<uint8_t,aligned_allocator<uint8_t>> generated_key(16);
    //std::vector<uint8_t,aligned_allocator<uint8_t>> encrypted_message_key(316);

    std::vector<cl::Device> devices = xcl::get_xil_devices();
    cl::Device device = devices[0];

    cl::Context context(device);
    cl::CommandQueue q(context, device,CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE | CL_QUEUE_PROFILING_ENABLE);
    cl::CommandQueue q_key(context, device,CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE | CL_QUEUE_PROFILING_ENABLE);
    cl::CommandQueue q_data(context, device,CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE | CL_QUEUE_PROFILING_ENABLE);
    std::string device_name = device.getInfo<CL_DEVICE_NAME>(); 

    std::string binaryFile = xcl::find_binary_file(device_name,"PUF");
    cl::Program::Binaries bins = xcl::import_binary_file(binaryFile);
    devices.resize(1);
    
    cl::Program program(context, devices, bins);
    cl::Kernel krnl_input_stage(program,"krnl_input");
    // cl::Kernel krnl_PUF_stage(program,"krnl_PUF_stage_rtl");
    cl::Kernel krnl_secure_monitor(program,"krnl_secure_monitor");
    cl::Kernel krnl_dummy(program,"krnl_dummy");
    cl::Kernel krnl_output_stage(program,"krnl_output");

    int sockfd = -1;
    struct sockaddr_un servaddr;
    int result;
    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    unlink(UNIXSTR_PATH);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, UNIXSTR_PATH);
    char ch = ' ';

    for(;;)
    {   //waiting for connection    
        result = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
        recv(sockfd, &ch, sizeof(ch), 0);
        if(ch=='o') { printf("receive info.\n"); break;}
    }

    recv(sockfd, challenge_tmp, sizeof(int)*16, 0);
    memcpy(&challenge[0], challenge_tmp, sizeof(int)*16);

    //memcpy(&input_message[0], input_message_encrypted, 300);
    //srand((unsigned)time(NULL));
    if(1)
    {
        int flag = 0;
        int chal_len = 16;
        int len = 1;
        int inc = 0;
        
        std::vector<cl::Memory> outBufVec;
        cl::Buffer buffer_input(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, chal_size_bytes, challenge.data());
        cl::Buffer buffer_input_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, chal_size_bytes, input_message.data());
        cl::Buffer buffer_output_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, chal_size_bytes, output_message.data());

        outBufVec.push_back(buffer_output_data);

        q.enqueueMigrateMemObjects({buffer_input, buffer_input_data},0);

        krnl_input_stage.setArg(0, buffer_input);
        krnl_input_stage.setArg(1, chal_len);
        // krnl_PUF_stage.setArg(0,inc);
        // krnl_PUF_stage.setArg(1,chal_len);
        krnl_secure_monitor.setArg(0,buffer_input_data);
        krnl_secure_monitor.setArg(1,chal_len);
        krnl_secure_monitor.setArg(2,len);
        krnl_secure_monitor.setArg(3,flag);
        krnl_dummy.setArg(0,chal_len);
        krnl_output_stage.setArg(0,buffer_output_data);
        krnl_output_stage.setArg(1,chal_len);
        krnl_output_stage.setArg(2,flag); 

        q.enqueueTask(krnl_input_stage);
        // q.enqueueTask(krnl_PUF_stage);
        q.enqueueTask(krnl_secure_monitor);
        q.enqueueTask(krnl_dummy);
        q.enqueueTask(krnl_output_stage);
        q.finish();
        //Copy Result from Device Global Memory to Host Local Memory
        q.enqueueMigrateMemObjects(outBufVec,CL_MIGRATE_MEM_OBJECT_HOST);
        q.finish();


        send(sockfd, &output_message[0], 16, 0);

    } 
    recv(sockfd, &challenge[0], 256*sizeof(int), 0);  

    if(1)
    {
        int flag = 1;
        int chal_len = 256;
        int len = 256;
        int inc = 0;
        
        std::vector<cl::Memory> outBufVec;
        cl::Buffer buffer_input(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, sizeof(uint8_t)*256, challenge.data());
        cl::Buffer buffer_input_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, encryted_msg_size_bytes, input_message.data());
        cl::Buffer buffer_output_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, encryted_msg_size_bytes, output_message.data());

        outBufVec.push_back(buffer_output_data);

        q_key.enqueueMigrateMemObjects({buffer_input, buffer_input_data},0);

        krnl_input_stage.setArg(0, buffer_input);
        krnl_input_stage.setArg(1, chal_len);
        // krnl_PUF_stage.setArg(0,inc);
        // krnl_PUF_stage.setArg(1,chal_len);
        //krnl_secure_monitor.setArg(0,buffer_output);
        krnl_secure_monitor.setArg(0,buffer_input_data);
        krnl_secure_monitor.setArg(1,chal_len);
        krnl_secure_monitor.setArg(2,len);
        krnl_secure_monitor.setArg(3,flag);
        krnl_dummy.setArg(0,len);
        krnl_output_stage.setArg(0,buffer_output_data);
        krnl_output_stage.setArg(1,len);
        krnl_output_stage.setArg(2,flag); 

        q_key.enqueueTask(krnl_input_stage);
        // q_key.enqueueTask(krnl_PUF_stage);
        q_key.enqueueTask(krnl_secure_monitor);
        q_key.enqueueTask(krnl_dummy);
        q_key.enqueueTask(krnl_output_stage);
        q_key.finish();
        q_key.enqueueMigrateMemObjects(outBufVec,CL_MIGRATE_MEM_OBJECT_HOST);
        q_key.finish();

    }   

    send(sockfd, &output_message[0], 256, 0);
//receive data
    //sleep(1);
    int length;
    
    if(recv(sockfd, &length, sizeof(length), 0)<0)
    {
        perror("\nServer Receive Data Length Failed.\n");
        return -1;
    }
    
    // printf("data length: %d\n", length);
    uint8_t* out_data = (uint8_t*)malloc(sizeof(uint8_t)*length);

    result = recv(sockfd, out_data, length, 0);
    memcpy(&input_message[0], out_data, length);
    
    timespec tv_1;
    clock_gettime(CLOCK_MONOTONIC,&tv_1);
    if(1)
    {
        int flag = 1;
        int chal_len = 256;
        int len = length;
        int inc = 0;
        int decrypted_len = len + 16;
        //int key_len = 256;
        //int encrypted_len = len - 12;
        
        std::vector<cl::Memory> outBufVec;
        cl::Buffer buffer_input(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, sizeof(uint8_t)*256, challenge.data());
        cl::Buffer buffer_input_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, sizeof(uint8_t)*length, input_message.data());
        cl::Buffer buffer_output_data(context,CL_MEM_USE_HOST_PTR | CL_MEM_WRITE_ONLY, sizeof(uint8_t)*length, output_message.data());

        outBufVec.push_back(buffer_output_data);

        q_data.enqueueMigrateMemObjects({buffer_input, buffer_input_data},0);

        krnl_input_stage.setArg(0, buffer_input);
        krnl_input_stage.setArg(1, chal_len);
        // krnl_PUF_stage.setArg(0,inc);
        // krnl_PUF_stage.setArg(1,chal_len);
        //krnl_secure_monitor.setArg(0,buffer_output);
        krnl_secure_monitor.setArg(0,buffer_input_data);
        krnl_secure_monitor.setArg(1,chal_len);
        krnl_secure_monitor.setArg(2,len);
        krnl_secure_monitor.setArg(3,flag);
        krnl_secure_monitor.setArg(4,buffer_output_data);
        krnl_dummy.setArg(0,buffer_output_data);
        krnl_dummy.setArg(1,len);
        
        krnl_output_stage.setArg(0,buffer_output_data);
        krnl_output_stage.setArg(1,len);
        krnl_output_stage.setArg(2,flag); 

        q_data.enqueueTask(krnl_input_stage);
        // q_data.enqueueTask(krnl_PUF_stage);
        q_data.enqueueTask(krnl_secure_monitor);
        q_data.enqueueTask(krnl_dummy);
        q_data.enqueueTask(krnl_output_stage);
        q_data.finish();
        q_data.enqueueMigrateMemObjects(outBufVec,CL_MIGRATE_MEM_OBJECT_HOST);
        q_data.finish();
       
    }  

    send(sockfd, &length, sizeof(length), 0);
    send(sockfd, &output_message[0], length, 0);

    return 0;

}    


