#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>
#include<sys/fcntl.h>
#include<sys/mman.h>
#include <sys/unistd.h>
#define SIZE (1<<20)

int set_tracked_pid(int pid)
{
	char buf[16];
	int fd = open("/sys/kernel/cs614hook/tracked_pid", O_RDWR);
	if(fd < 0){
		perror("open");
		return fd;
	}
        sprintf(buf, "%d", pid);
	if(write(fd, buf, 16) < 0){
		perror("open");
		return -1;
	}
	printf("Process %d is being tracked now\n", pid);
	close(fd);
	return 0;
}
int set_populate(int pop)
{
	char buf[16];
	int fd = open("/sys/kernel/map_populate_hook/populate", O_RDWR);
	if(fd < 0){
		perror("open");
		return fd;
	}
        sprintf(buf, "%d", pop);
	if(write(fd, buf, 16) < 0){
		perror("open");
		return -1;
	}
	printf("Process %d is being tracked now\n", pop);
	close(fd);
	return 0;
}

// void start_tracer()
// {	
// 	int fd1 = open("/sys/kernel/tracing/set_ftrace_pid", O_RDWR);
// 	if(fd1 < 0){
// 		perror("open");
// 		exit(-1);
// 	}
// 	char buf[16];
// 	sprintf(buf, "%d", getpid());
// 	write(fd1,buf,16);
// 	close(fd1);
// 	int fd = open("/sys/kernel/tracing/tracing_on", O_RDWR);
// 	if(fd < 0){
// 		perror("open");
// 		exit(-1);
// 	}
// 	write(fd, "1", 1);
// 	close(fd);
// }
// void stop_tracer()
// {
// 	int fd = open("/sys/kernel/tracing/tracing_on", O_RDWR);
// 	if(fd < 0){
// 		perror("open");
// 		exit(-1);
// 	}
// 	write(fd, "0", 1);
// 	close(fd);
// 	int fd1 = open("/sys/kernel/tracing/set_ftrace_pid", O_RDWR);
// 	if(fd1 < 0){
// 		perror("open");
// 		exit(-1);
// 	}
// 	write(fd1,"no pid",7);
// 	close(fd1);
// }
int query(char *buf, int len)
{
	int read_bytes = 0;
	
	int fd = open("/sys/kernel/cs614hook/query", O_RDONLY);
	
	if(fd < 0){
		perror("open");
		return fd;
	}

	read_bytes = read(fd, buf, len);

	if(read_bytes < 0){
		perror("read");
	        close(fd);
		return read_bytes;
	}
	close(fd);
        buf[read_bytes] = 0;
        return read_bytes;	
}

int main()
{
   char *ptr;
   char rbuf[4096];
   char x;

//    int fd = open ("100_page_file", O_RDWR|O_CREAT, 0666);
//    for(int i = 0; i < SIZE; i++){
// 	   write(fd, "ABCDEFG", 7);
//    }
//    assert(set_tracked_addr((unsigned long)ptr) == 0);
//   assert(set_populate(1) == 0);
   
   ptr = mmap(NULL, SIZE, PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
   assert(set_tracked_pid(getpid()) == 0);
   if(ptr == MAP_FAILED){
        perror("mmap");
        exit(-1);
   }
	// to check for read faults uncomment the following code
//    for(int k=0 ;k<4;k++){
//    for (int i =0 ; i< SIZE;i+= 4096){
// 	   x = ptr[i];
//    }
//    }
   for (int i =0 ; i< SIZE;i+= 4096){
	   ptr[i] = 'A';
   }
  munmap((void *)ptr, 4096);
//    assert(set_populate(0) == 0);
//    get_tracked_addr();
   return 0;
}
