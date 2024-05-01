obj-m = manalyze.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	# if you want to compile mmap_test.c, uncomment the following line
	# gcc mmap_test.c -o mmap_test

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	# if you have an executable mmap_test or a.out, uncomment the following line
	# rm -f mmap_test a.out
