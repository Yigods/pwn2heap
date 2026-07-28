CC ?= gcc
CFLAGS_COMMON := -O0 -g -fstack-protector-strong -fcf-protection=full -Wall -Wextra -Wno-unused-result -Wno-stringop-overflow -Wno-format-overflow
LDFLAGS_PARTIAL := -Wl,-z,relro -Wl,-z,lazy
LDFLAGS_FULL := -Wl,-z,relro -Wl,-z,now

.PHONY: all clean patch checksec
all: ezpz1/ezpz1 ezpz2/ezpz2 notezpz1-plus/notezpz notezpz2/notezpz2 applepie/applepie darklamp/darklamp patch

ezpz1/ezpz1: ezpz1/ezpz1.c
	$(CC) $(CFLAGS_COMMON) -no-pie $< -o $@ $(LDFLAGS_PARTIAL)

ezpz2/ezpz2: ezpz2/ezpz2.c
	$(CC) $(CFLAGS_COMMON) -no-pie $< -o $@ $(LDFLAGS_PARTIAL)

notezpz1-plus/notezpz: notezpz1-plus/notezpz.c
	$(CC) $(CFLAGS_COMMON) -fPIE -pie $< -o $@ $(LDFLAGS_FULL)

notezpz2/notezpz2: notezpz2/notezpz2.c
	$(CC) $(CFLAGS_COMMON) -fPIE -pie $< -o $@ $(LDFLAGS_FULL)

applepie/applepie: applepie/applepie.c
	$(CC) $(CFLAGS_COMMON) -fPIE -pie $< -o $@ $(LDFLAGS_FULL)

darklamp/darklamp: darklamp/darklamp.c
	$(CC) $(CFLAGS_COMMON) -fPIE -pie $< -o $@ $(LDFLAGS_FULL)

patch:
	cp ezpz1/ezpz1 ezpz1/ezpz1_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ezpz1/ezpz1_patched
	cp ezpz2/ezpz2 ezpz2/ezpz2_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ezpz2/ezpz2_patched
	cp notezpz1-plus/notezpz notezpz1-plus/notezpz_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . notezpz1-plus/notezpz_patched
	cp notezpz2/notezpz2 notezpz2/notezpz2_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . notezpz2/notezpz2_patched
	cp applepie/applepie applepie/applepie_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . applepie/applepie_patched
	cp darklamp/darklamp darklamp/darklamp_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . darklamp/darklamp_patched

checksec:
	pwn checksec --file=ezpz1/ezpz1_patched || true
	pwn checksec --file=ezpz2/ezpz2_patched || true
	pwn checksec --file=notezpz1/notezpz_patched || true
	pwn checksec --file=notezpz1-plus/notezpz_patched || true
	pwn checksec --file=notezpz2/notezpz2_patched || true
	pwn checksec --file=applepie/applepie_patched || true
	pwn checksec --file=darklamp/darklamp_patched || true

clean:
	rm -f ezpz1/ezpz1 ezpz1/ezpz1_patched ezpz2/ezpz2 ezpz2/ezpz2_patched notezpz1-plus/notezpz notezpz1-plus/notezpz_patched notezpz2/notezpz2 notezpz2/notezpz2_patched applepie/applepie applepie/applepie_patched darklamp/darklamp darklamp/darklamp_patched
