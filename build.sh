#!/bin/bash
set -e
cd "$(dirname "$0")"
SRC_DIR="$(pwd)"

# Find sysbrain directory - try multiple locations
SYSBRAIN=""
for candidate in \
    "$HOME/hellox/v190/ishell/sysbrain0.0.3" \
    "$HOME/hellox/v190/sysbrain0.0.3" \
    "$HOME/hellox/archive/sysbrain0.0.3" \
    "$HOME/hellox/archive/hxosv190/app/sysbrain0.0.3" \
    "$SRC_DIR/../ishell/sysbrain0.0.3" \
    "$SRC_DIR/../sysbrain0.0.3"; do
    if [ -f "$candidate/main.o" ]; then
        SYSBRAIN="$candidate"
        break
    fi
done

if [ -z "$SYSBRAIN" ]; then
    echo "ERROR: sysbrain0.0.3 not found! Tried:" >&2
    for candidate in \
        "$HOME/hellox/v190/ishell/sysbrain0.0.3" \
        "$HOME/hellox/v190/sysbrain0.0.3"; do
        echo "  $candidate" >&2
    done
    echo ""
    echo "Please set SYSBRAIN_DIR env var to your sysbrain0.0.3 path and retry." >&2
    exit 1
fi

echo "=== Build Sendmail ==="
echo "SYSBRAIN: $SYSBRAIN"

CFLAGS="-m32 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector"
CFLAGS="$CFLAGS -fno-pic -fno-PIE -fno-pie"
CFLAGS="$CFLAGS -D__GNUC__=4 -D__i386__ -D_POSIX_"
CFLAGS="$CFLAGS -DWOLFSSL_USER_SETTINGS -D__helloX__ -DUSE_WOLFSSL -DNDEBUG"
CFLAGS="$CFLAGS -I$SYSBRAIN -I$SYSBRAIN/sys -I$SYSBRAIN/ptmalloc -I$SYSBRAIN/cJSON"
CFLAGS="$CFLAGS -I$SYSBRAIN/sockets -I$SYSBRAIN/regexp -I$SYSBRAIN/wildcard"
CFLAGS="$CFLAGS -I$SYSBRAIN/gnutls -I$SYSBRAIN/wolfssl"
CFLAGS="$CFLAGS -I/usr/lib/llvm-18/lib/clang/18/include"
CFLAGS="$CFLAGS -I/usr/lib/llvm-19/lib/clang/19/include"

echo "Compiling sendmail.c..."
clang $CFLAGS -c src/sendmail.c -o src/sendmail.o

echo "Linking sendmail.exe..."

cd "$SYSBRAIN"

# Files that cause conflicts
EXCLUDE="email_stubs\.o\|curl_link_stubs\.o\|hx_timeval\.o"
# All files with their own hx_main (competing entry points)
EXCLUDE="$EXCLUDE\|email_main\.o\|email_send_src\.o\|email_usb_send\.o"
EXCLUDE="$EXCLUDE\|email_tls_new\.o\|email_tls\.o"
EXCLUDE="$EXCLUDE\|email_main_raw\.o\|smtp_mini\.o\|smtp_stubs\.o\|smtp_test\.o"
EXCLUDE="$EXCLUDE\|curl_test\.o\|minimal_test\.o\|tcp_test\.o\|wechat_api\.o"
EXCLUDE="$EXCLUDE\|deepseek_repl\.o\|test_wolfssl\.o\|test_wolfssl_main\.o"
EXCLUDE="$EXCLUDE\|test_in_main\.o\|smtp_test_new\.o"

# Link: main.o provides _hx_main, sendmail.o provides main()
ld -m i386pe --subsystem native:0 --entry _hx_main \
  --enable-reloc-section -T "$SRC_DIR/link.ld" \
  -o "$SRC_DIR/sendmail.exe" \
  --start-group \
  "$SRC_DIR/src/sendmail.o" \
  $(ls *.o | grep -v -e "$EXCLUDE" | tr '\n' ' ') \
  $(find sockets/ -name "*.o" 2>/dev/null | tr '\n' ' ') \
  $(find ptmalloc/ -name "*.o" 2>/dev/null | tr '\n' ' ') \
  $(find wolfssl/ -name "*.o" 2>/dev/null | tr '\n' ' ') \
  --end-group

cd "$SRC_DIR"

echo ""
echo "=== BUILD OK ==="
ls -lh sendmail.exe
file sendmail.exe
# Verify entry point is valid
ENTRY=$(objdump -x sendmail.exe 2>/dev/null | grep AddressOfEntryPoint | awk '{print $2}')
if [ "$ENTRY" = "00000000" ]; then
    echo "WARNING: Entry point is 0x00000000! Linker may have failed to find _hx_main."
    echo "Check that main.o is in the SYSBRAIN directory."
fi
