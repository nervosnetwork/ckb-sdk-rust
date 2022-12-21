# how to build cycle test scripts
1. download ckb-production-scripts repository.
The cycle test script is built from [https://github.com/nervosnetwork/ckb-production-scripts.git](ckb-production-scripts), so it can save lots of effort to build the environment.
so download the repository, and checkout e848f4feca47c03800d3822eb519c7f5fd26f191,

2. patch the different
   save the following file to cycle.path
```diff
diff --git a/Makefile b/Makefile
index 777c931..4b7fe1e 100644
--- a/Makefile
+++ b/Makefile
@@ -27,11 +27,16 @@ PASSED_MBEDTLS_CFLAGS := -O3 -fPIC -nostdinc -nostdlib -DCKB_DECLARATION_ONLY -I
 # docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
 BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

-all: build/simple_udt build/anyone_can_pay build/always_success build/validate_signature_rsa build/xudt_rce build/rce_validator build/omni_lock
+all: build/simple_udt build/anyone_can_pay build/always_success build/validate_signature_rsa build/xudt_rce build/rce_validator build/omni_lock build/cycle

 all-via-docker: ${PROTOCOL_HEADER}
        docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

+build/cycle: c/cycle.c
+       $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
+       $(OBJCOPY) --only-keep-debug $@ $@.debug
+       $(OBJCOPY) --strip-debug --strip-all $@
+
 build/simple_udt: c/simple_udt.c
        $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
        $(OBJCOPY) --only-keep-debug $@ $@.debug
```
if you want to use log information, add `-D CKB_C_STDLIB_PRINTF` to CC command in `build/cycle` section, add add `ckb_debug` function call in c code.

3. save `cycle.c` to `c/cycle.c` into project `ckb-production-scripts`
4. compile the project `ckb-production-scripts`
```sh
make all-via-docker
```
5. copy the script from build to test-data directory
