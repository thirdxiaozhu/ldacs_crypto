CC=gcc
CFLAGS = -g -O2 -fomit-frame-pointer 
LDFLAGS = -L../lib/ -lpiico_ccmu -lpthread -I ../include

all:
	$(CC) $(CFLAGS) piicoToolWP.c -lm $(LDFLAGS) -o piicoToolWP

	$(CC) $(CFLAGS) std_sm1.c $(LDFLAGS) -o std_sm1
	$(CC) $(CFLAGS) std_sm2.c $(LDFLAGS) -o std_sm2
	$(CC) $(CFLAGS) std_sm3.c $(LDFLAGS) -o std_sm3
	$(CC) $(CFLAGS) std_sm4.c $(LDFLAGS) -o std_sm4
	$(CC) $(CFLAGS) std_random.c $(LDFLAGS) -o std_random
	$(CC) $(CFLAGS) perf_sm14.c $(LDFLAGS) -o perf_sm14
	$(CC) $(CFLAGS) perf_sm2.c $(LDFLAGS) -o perf_sm2
	$(CC) $(CFLAGS) perf_sm3.c $(LDFLAGS) -o perf_sm3
	$(CC) $(CFLAGS) perf_random.c $(LDFLAGS) -o perf_random	
	$(CC) $(CFLAGS) menu.c $(LDFLAGS) -o menu

clean:
	rm -fr ./*.o
	rm -f piicoTool piicoToolWP
	rm -f std_sm1 std_sm2 std_sm3 std_sm4 std_random
	rm -f menu
	rm -f perf_sm14 perf_sm2 perf_sm3
	rm -f perf_random 
