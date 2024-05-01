#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>
#include<sys/fcntl.h>
#include<sys/mman.h>
#include <sys/unistd.h>
#include <time.h>
const int SIZE = 1024 * 1024;

int set_pid(int pid){
    char buf[16];
	int fd = open("/sys/kernel/debug/tracked_pid", O_RDWR);
	if(fd < 0){
		perror("open");
		return fd;
	}
        sprintf(buf, "%d", pid);
	if(write(fd, buf, 16) < 0){
		perror("write");
		return -1;
	}
	close(fd);
	return 0;
}

int set_nr_pages(int nr_pages){
    char buf[16];
	int fd = open("/sys/kernel/debug/nr_prefault_page", O_RDWR);
	if(fd < 0){
		perror("open");
		return fd;
	}
        sprintf(buf, "%d", nr_pages);
	if(write(fd, buf, 16) < 0){
		perror("write");
		return -1;
	}
	close(fd);
	return 0;
}

#define PAGE_SIZE (4*1024)    // 4KB
#define NUM_ITERATIONS 100 // Number of iterations for touching each page

int main(int argc, char*argv[]) {
    struct timeval start, end;
    int i, j;
    int num_mb = 1;
    int order = atoi(argv[1]);
    order = (1 << order) * 4096;
    int MEM_SIZE = atoi(argv[2]);

    // Touch each page multiple times to force it to be populated
    nice(-20);
    assert(set_pid(getpid()) == 0);
    assert(set_nr_pages(order) == 0);
    // printf("for order %d\n", order);
    double elapsed_time = 0;
    for (i = 0; i < NUM_ITERATIONS; i++) {
        char *mapped_mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapped_mem == MAP_FAILED) {
            perror("mmap");
            exit(EXIT_FAILURE);
        }
        // printf("memory allocated at %p\n", mapped_mem);

        // Start timer
        gettimeofday(&start, NULL);

        // Touch each page
        for (j = 0; j < MEM_SIZE/PAGE_SIZE; j += 1) {
            mapped_mem[(rand()%(MEM_SIZE/PAGE_SIZE)) * PAGE_SIZE] = 1;
        }

        // End timer
        gettimeofday(&end, NULL);

        // Calculate elapsed time and add to total
        elapsed_time += (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

        // Unmap memory
       
        if (munmap(mapped_mem, MEM_SIZE) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }
        // printf("memory deallocated\n");
    }

    // Calculate average elapsed time
    elapsed_time /= NUM_ITERATIONS;
    assert(set_nr_pages(0) == 0);
    assert(set_pid(0) == 0);

    printf("%.6f",elapsed_time);
    return 0;
}
/*int main(){
    char *temp = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(!temp){
        perror("mmap");
        exit(0);
    }
    
    for(int i=0;i<SIZE;i++){
        int j = rand() % SIZE;
        char x = temp[j];
    }

    for(int i=0;i<SIZE;i++){
        int j = rand() % SIZE;
        temp[j] = 'a';
    }

    munmap(temp, SIZE);
    return 0;
}
*/