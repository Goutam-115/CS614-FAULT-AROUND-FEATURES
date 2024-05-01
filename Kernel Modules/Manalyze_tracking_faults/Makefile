obj-m = manalyze.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	# gcc test.c -o test

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	# rm -f test a.out
