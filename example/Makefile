all: keyexp-test

keyexp-test: test.c
	gcc -g -Wall -o keyexp-test test.c

clean:
	rm -f keyexp-test

run:
	$(PIN_ROOT)/pin -t ../src/obj-intel64/CECTraceTool.so -f aes128_key_expansion -s summary.log -- ./keyexp-test
