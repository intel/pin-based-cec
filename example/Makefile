all: keyexp-test

keyexp-test: test.c
	gcc -g -Wall -o keyexp-test test.c

clean:
	rm -f keyexp-test

run: keyexp-test
	$(PIN_ROOT)/pin -t ../src/obj-intel64/CECTraceTool.so -f aes128_key_expansion -s summary.log -- ./keyexp-test

branch_example: keyexp-test
	$(PIN_ROOT)/pin -t ../src/obj-intel64/CECTraceTool.so -f aes128_key_checksum -s summary.log -- ./keyexp-test
	python ../src/post_process.py --branch results.txt
