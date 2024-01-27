
all: examples driver

.PHONY: examples driver

examples:
	make -C examples/

driver:
	make -C driver/

clean:
	make clean -C examples/
	make clean -C driver/

install:
	cp lib/libpiico_ccmu.so /lib/
	make install -C driver

uninstall:
	rm -f /lib/libpiico_ccmu.so
	make uninstall -C driver
