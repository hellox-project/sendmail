/* sendmail.c — SMTP email client for HelloX OS
 *
 * Sends MIME multipart messages with attachments over SMTP+TLS.
 * Uses wolfSSL for TLS 1.2, lwIP for TCP networking.
 *
 * Features:
 *   - Single or multiple TO recipients (comma-separated)
 *   - CC recipients
 *   - File attachments (at least 4, base64-encoded)
 *   - Dot-stuffing per RFC 5321
 *   - STARTTLS on port 25
 *
 * HelloX development task: github.com/hellox-project/sendmail
 */

#include "hellox.h"
#include "stdio.h"
#include "string.h"
#include "sockets.h"
#include <stdlib.h>

/* wolfSSL headers */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* wolfSSL platform I/O callbacks (from sysbrain wolfssl_platform.c) */
extern int HxIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
extern int HxIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);

/* ---------- Constants ---------- */
#define MAX_RESP      4096
#define MAX_ATTACH     8
#define MAX_ATT_SIZE  (512 * 1024L)
#define MAX_BODY_SIZE (512 * 1024L)
#define BOUNDARY_STR  "----=_HelloX_Sendmail_0001"
#define CHUNK_SIZE    16384    /* 16KB chunks for streaming sends */

#ifndef NULL
#define NULL ((void*)0)
#endif

/* ---------- Debug output ---------- */
extern void PrintChar(char);
static void putc(char c) { PrintChar(c); }
static void puts(const char *s) { while (*s) putc(*s++); }

static void putint(int v) {
    if (v < 0) { putc('-'); v = -v; }
    if (v >= 10) putint(v / 10);
    putc('0' + v % 10);
}

#define LOG(s)     puts(s)
#define LOGI(v)    putint(v)
#define LOGC(c)    putc(c)

/* ===================================================================
 * Base64 encoding
 * =================================================================== */
static const char b64tab[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Returns length of encoded output written to 'out' */
static int b64enc(const unsigned char *in, int inlen, char *out)
{
    int i = 0, o = 0;
    while (i < inlen) {
        int rem = inlen - i;
        unsigned int a = in[i++];
        unsigned int b = (i < inlen) ? in[i++] : 0;
        unsigned int c = (i < inlen) ? in[i++] : 0;
        unsigned int tri = (a << 16) | (b << 8) | c;
        out[o++] = b64tab[(tri >> 18) & 0x3F];
        out[o++] = b64tab[(tri >> 12) & 0x3F];
        out[o++] = (rem >= 2) ? b64tab[(tri >> 6) & 0x3F] : '=';
        out[o++] = (rem >= 3) ? b64tab[tri & 0x3F] : '=';
        /* Line break every 76 chars */
        if (o % 76 == 0 && i < inlen) { out[o++] = '\r'; out[o++] = '\n'; }
    }
    return o;
}

/* ===================================================================
 * Dot-stuffing: ".." for lines starting with '.'  (RFC 5321 §4.5.2)
 * =================================================================== */
static int dot_stuff(const char *in, int inlen, char *out, int outmax)
{
    int o = 0;
    int i = 0;
    while (i < inlen && o < outmax - 1) {
        int line_start = (i == 0 || (i > 0 && in[i-1] == '\n'));
        if (line_start && in[i] == '.') {
            if (o >= outmax - 2) break;
            out[o++] = '.';
            out[o++] = '.';
            i++;
        } else if (in[i] == '\r' && i+1 < inlen && in[i+1] == '\n') {
            if (o >= outmax - 2) break;
            out[o++] = '\r';
            out[o++] = '\n';
            i += 2;
        } else {
            if (o >= outmax - 1) break;
            out[o++] = in[i++];
        }
    }
    return o;
}

/* ===================================================================
 * File I/O via HelloX API — opens file for streamed reading
 * Returns a HANDLE that must be closed with CloseFile().
 * =================================================================== */
static HANDLE open_file(const char *path)
{
    if (!path) return NULL;
    return CreateFile((char*)path, FILE_ACCESS_READ, 0, NULL);
}

/* Read a small file into heap — only for files < 64KB (config files, small bodies) */
static char *read_file(const char *path, int *outlen)
{
    if (!path) { puts("  [FILE] null path\n");  return NULL; }
    HANDLE h = CreateFile((char*)path, FILE_ACCESS_READ, 0, NULL);
    if (!h) { puts("  [FILE] CreateFile fail\n"); return NULL; }

    DWORD sz = GetFileSize(h, NULL);
    if (sz <= 0) { puts("  [FILE] size <= 0\n"); CloseFile(h); return NULL; }
    if (sz > MAX_ATT_SIZE) {
        puts("  [FILE] too large: "); putint((int)sz);
        puts(" > "); putint((int)MAX_ATT_SIZE); putc('\n');
        CloseFile(h);
        return NULL;
    }

    /* Only use read_file() for small files; large files use streaming path */
    if (sz > 65536) {
        puts("  [FILE] large file ("); putint((int)sz);
        puts(" bytes), use streaming API instead\n");
        CloseFile(h);
        return NULL;
    }

    char *buf = (char*)malloc((size_t)(sz + 4));
    if (!buf) {
        puts("  [FILE] malloc("); putint((int)(sz + 4)); puts(") FAIL\n");
        CloseFile(h); return NULL;
    }

    DWORD read = 0;
    if (!ReadFile(h, sz, buf, &read)) {
        puts("  [FILE] ReadFile FAIL\n");
        free(buf); CloseFile(h); return NULL;
    }
    CloseFile(h);
    buf[(int)read] = 0;
    if (outlen) *outlen = (int)read;
    return buf;
}

/* ===================================================================
 * MIME type from file extension
 * =================================================================== */
static const char *mime_type(const char *path)
{
    const char *ext = path;
    while (*ext) ext++;
    while (ext > path && *ext != '.') ext--;
    if (*ext == '.') ext++;

    if (!strcasecmp(ext, "txt"))   return "text/plain";
    if (!strcasecmp(ext, "h"))     return "text/plain";
    if (!strcasecmp(ext, "c"))     return "text/plain";
    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html";
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "png"))   return "image/png";
    if (!strcasecmp(ext, "pdf"))   return "application/pdf";
    if (!strcasecmp(ext, "zip"))   return "application/zip";
    if (!strcasecmp(ext, "bin"))   return "application/octet-stream";
    if (!strcasecmp(ext, "exe"))   return "application/octet-stream";
    return "application/octet-stream";
}

/* ===================================================================
 * Network layer — TCP connect
 * =================================================================== */

/* Hardcoded IP for smtp.163.com = 111.124.203.45
 * Stored as little-endian dword for HelloX */
#define SMTP_163_IP  0x2DCB7C6Fu

/* Convert dotted IP to network-order dword */
static unsigned long ip_to_dword(const char *ip_str)
{
    if (!ip_str || !*ip_str) return SMTP_163_IP;
    unsigned int o[4] = {0,0,0,0};
    int n = 0;
    const char *p = ip_str;
    while (*p && n < 4) {
        while (*p >= '0' && *p <= '9') {
            o[n] = o[n] * 10 + (*p - '0');
            p++;
        }
        if (*p == '.') { p++; n++; }
        else break;
    }
    /* Return in host byte order (HelloX lwIP expects LE for the dword) */
    return (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0];
}

static int tcp_connect(const char *ip_str, int port)
{
    int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    unsigned long ip_dword = ip_to_dword(ip_str);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family  = AF_INET;
    addr.sin_port    = _hx_htons((unsigned short)(port & 0xFFFF));
    addr.sin_addr.s_addr = ip_dword;

    if (lwip_connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        lwip_close(fd);
        return -3;
    }
    return fd;
}

/* ===================================================================
 * SMTP protocol helpers
 * =================================================================== */

/* Read 1 line from plain TCP socket (strips \r) */
static int recvline(int fd, char *buf, int maxlen)
{
    int i = 0; char c;
    while (i < maxlen - 1) {
        int r = (int)lwip_read(fd, &c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = 0;
    return i;
}

/* Read 1 line from TLS socket (strips \r) */
static int recvline_tls(WOLFSSL *ssl, char *buf, int maxlen)
{
    int i = 0; char c;
    while (i < maxlen - 1) {
        int r = wolfSSL_read(ssl, &c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = 0;
    return i;
}

/* Extract 3-digit SMTP response code */
static int resp_code(const char *line)
{
    int code = 0;
    while (*line >= '0' && *line <= '9')
        code = code * 10 + (*line++ - '0');
    return code;
}

/* Send plain SMTP command and read multi-line response */
static int smtp_cmd_plain(int fd, const char *cmd, int expected,
                           char *resp, int resp_max)
{
    if (cmd) {
        char buf[1024];
        int n = 0;
        while (cmd[n] && n < 1018) { buf[n] = cmd[n]; n++; }
        buf[n++] = '\r'; buf[n++] = '\n';
        lwip_write(fd, buf, n);
        puts("C: "); puts(cmd); putc('\n');
    }
    int code;
    do {
        recvline(fd, resp, resp_max);
        puts("S: "); puts(resp); putc('\n');
        code = resp_code(resp);
    } while (resp[3] == '-');
    if (expected > 0 && code != expected) {
        puts("  [EXP "); putint(expected); puts(" GOT "); putint(code); puts("]\n");
        return -1;
    }
    return 0;
}

/* Send TLS SMTP command and read multi-line response */
static int smtp_cmd_tls(WOLFSSL *ssl, const char *cmd, int expected,
                         char *resp, int resp_max)
{
    if (cmd) {
        char buf[1024];
        int n = 0;
        while (cmd[n] && n < 1018) { buf[n] = cmd[n]; n++; }
        buf[n++] = '\r'; buf[n++] = '\n';
        wolfSSL_write(ssl, buf, n);
        puts("C: "); puts(cmd); putc('\n');
    }
    int code;
    do {
        recvline_tls(ssl, resp, resp_max);
        puts("S: "); puts(resp); putc('\n');
        code = resp_code(resp);
    } while (resp[3] == '-');
    if (expected > 0 && code != expected) {
        puts("  [EXP "); putint(expected); puts(" GOT "); putint(code); puts("]\n");
        return -1;
    }
    return 0;
}

/* Send raw data over TLS with loop until all sent */
static int send_payload_tls(WOLFSSL *ssl, const char *data, int len)
{
    int total = 0;
    while (total < len) {
        int sent = wolfSSL_write(ssl, data + total, len - total);
        if (sent <= 0) {
            int err = wolfSSL_get_error(ssl, sent);
            puts("  [SEND FAIL] sent="); putint(sent);
            puts(" total="); putint(total);
            puts(" err="); putint(err); putc('\n');
            return -1;
        }
        total += sent;
    }
    return 0;
}

/* ===================================================================
 * Usage
 * =================================================================== */
static void usage(void)
{
    puts("=== SENDMAIL - SMTP TLS Mail Client for HelloX OS ===\r\n");
    puts("\r\n");
    puts("Syntax:\r\n");
    puts("  loadapp c:\\\\sendmail.exe [server] [port] [user]\r\n");
    puts("         [password] [from] [to] [cc] [subject]\r\n");
    puts("         [-b bodyfile] [attachment ...]\r\n");
    puts("\r\n");
    puts("  (No args = reads sendmail.cfg from same directory)\r\n");
    puts("\r\n");
    puts("Positional (use '.' to skip):\r\n");
    puts("  1 server   IP address of SMTP server\r\n");
    puts("  2 port     TCP port (default 25)\r\n");
    puts("  3 user     Login username\r\n");
    puts("  4 password Auth code\r\n");
    puts("  5 from     Sender address\r\n");
    puts("  6 to       Recipients (comma-separated)\r\n");
    puts("  7 cc       CC recipients (comma-separated)\r\n");
    puts("  8 subject  Email subject\r\n");
    puts("\r\n");
    puts("Options:\r\n");
    puts("  -b <file>  Body text from file\r\n");
    puts("  <file>..   Attachments (max 8, max 512KB each)\r\n");
    puts("\r\n");
    puts("Config file (sendmail.cfg) format:\r\n");
    puts("  server=smtp.163.com (or IP)\r\n");
    puts("  port=25\r\n");
    puts("  username=xxx@163.com\r\n");
    puts("  password=xxx\r\n");
    puts("  from=xxx@163.com\r\n");
    puts("  to=recipient1@x,recipient2@y\r\n");
    puts("  cc=cc@example.com\r\n");
    puts("  subject=Test\r\n");
    puts("  body=c:\\body.txt\r\n");
    puts("  attach=c:\\file1.bin\r\n");
    puts("  attach=c:\\file2.bin\r\n");
    puts("  (lines starting with # are comments)\r\n");
    puts("\r\n");
    puts("Example:\r\n");
    puts("  loadapp c:\\\\sendmail.exe . . . . . \"a@b,c@d\" \"e@f\" \"Test\"\r\n");
    puts("====================================================\r\n");
}

/* ===================================================================
 * Config file parsing (fallback when no CLI args available)
 * =================================================================== */
#define CFG_LINE_MAX 512

/* Trim trailing whitespace including \r\n, and remove carriage returns */
static void chomp(char *s) {
    int len = (int)strlen(s);
    while (len > 0 && (s[len-1] == '\r' || s[len-1] == '\n' || s[len-1] == ' ' || s[len-1] == '\t'))
        s[--len] = 0;
    /* Remove any stray \r in the middle (e.g. from split lines) */
    int di = 0;
    for (int si = 0; si < len; si++) {
        if (s[si] != '\r') s[di++] = s[si];
    }
    s[di] = 0;
}

/* Read first token from a line after '=' , returns pointer or NULL */
static const char *cfg_val(char *line) {
    char *eq = strchr(line, '=');
    if (!eq) return NULL;
    /* skip past = and whitespace */
    char *v = eq + 1;
    while (*v == ' ' || *v == '\t') v++;
    return v;
}

/* Load config from path, storing string values into provided buffers */
typedef struct {
    char server[64];
    int  port;
    char username[128];
    char password[128];
    char from[128];
    char to[512];
    char cc[256];
    char subject[256];
    char body_file[256];
    char attachments[8][256];
    int  num_att;
    int  found; /* non-zero if config was read OK */
} SendmailConfig;

static int load_config(const char *path, SendmailConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = 25; /* default */

    HANDLE h = CreateFile((char*)path, FILE_ACCESS_READ, 0, NULL);
    if (!h) return 0;

    DWORD sz = GetFileSize(h, NULL);
    if (sz <= 0 || sz > 16384) { CloseFile(h); return 0; }

    char *buf = (char*)malloc((size_t)(sz + 4));
    if (!buf) { CloseFile(h); return 0; }

    DWORD read = 0;
    ReadFile(h, sz, buf, &read);
    CloseFile(h);
    buf[(int)read] = 0;

    /* Parse line by line */
    char line[CFG_LINE_MAX];
    int li = 0, bi = 0;
    while (bi < (int)read && buf[bi]) {
        int pi = 0;
        while (bi < (int)read && buf[bi] && buf[bi] != '\n' && pi < CFG_LINE_MAX - 1)
            line[pi++] = buf[bi++];
        if (buf[bi] == '\n') bi++;
        line[pi] = 0;
        chomp(line);

        /* Skip empty lines and comments */
        if (line[0] == 0 || line[0] == '#') continue;

        const char *val;
        if ((val = cfg_val(line))) {
            if      (strncmp(line, "server", 6) == 0)  { strncpy(cfg->server, val, sizeof(cfg->server)-1); }
            else if (strncmp(line, "port", 4) == 0)     { cfg->port = 0; while (*val >= '0' && *val <= '9') cfg->port = cfg->port * 10 + (*val++ - '0'); }
            else if (strncmp(line, "username", 8) == 0) { strncpy(cfg->username, val, sizeof(cfg->username)-1); }
            else if (strncmp(line, "password", 8) == 0) { strncpy(cfg->password, val, sizeof(cfg->password)-1); }
            else if (strncmp(line, "from", 4) == 0)     { strncpy(cfg->from, val, sizeof(cfg->from)-1); }
            else if (strncmp(line, "to", 2) == 0)       { strncpy(cfg->to, val, sizeof(cfg->to)-1); }
            else if (strncmp(line, "cc", 2) == 0)       { strncpy(cfg->cc, val, sizeof(cfg->cc)-1); }
            else if (strncmp(line, "subject", 7) == 0)  { strncpy(cfg->subject, val, sizeof(cfg->subject)-1); }
            else if (strncmp(line, "body", 4) == 0)     { strncpy(cfg->body_file, val, sizeof(cfg->body_file)-1); }
            else if (strncmp(line, "attach", 6) == 0) {
                if (cfg->num_att < 8) {
                    strncpy(cfg->attachments[cfg->num_att], val, sizeof(cfg->attachments[0])-1);
                    cfg->num_att++;
                }
            }
        }
    }

    free(buf);
    cfg->found = 1;

    puts("  Config loaded: "); puts(path); putc('\n');
    putint(cfg->num_att); puts(" attachment(s)\n");
    return 1;
}

/* Check if a path looks absolute (has a drive letter like c:\\ or c:/) */
static int is_absolute_path(const char *p) {
    if (!p || !*p) return 0;
    if ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
        if (p[1] == ':') return 1;
    }
    if (p[0] == '/' || p[0] == '\\') return 1;
    return 0;
}

/* Helper: read a file, trying multiple path formats.
 * 1. Path as-is
 * 2. If absolute (has drive letter like C:\...), also try without the drive letter (e.g. \FTP\FILE.TXT)
 * 3. If relative path, try prepending dir
 * 4. Also try forward-slash versions of all of the above
 * Returns NULL only if all attempts fail.
 */
static char *read_file_at(const char *dir, const char *fname, int *outlen)
{
    char alt[512];
    int tried;
    
    if (!fname) return NULL;

    /* 1. Try the path as-is first */
    {
        char *d = read_file(fname, outlen);
        if (d) return d;
        puts("  [FILE] \""); puts(fname); puts("\" not found\n");
    }

    /* 2. If path has a drive letter (C:\...), try stripping the drive letter (\FTP\FILE.TXT) */
    if ((fname[0] >= 'a' && fname[0] <= 'z') || (fname[0] >= 'A' && fname[0] <= 'Z')) {
        if (fname[1] == ':') {
            /* Skip "C:" part */
            tried = 0;
            const char *src = fname + 2;
            int di = 0;
            while (*src && di < 508) alt[di++] = *src++;
            alt[di] = 0;
            puts("  [FILE] trying (no drive): \""); puts(alt); puts("\"\n");
            char *d = read_file(alt, outlen);
            if (d) return d;
        }
    }

    /* 3. Try forward-slash conversion of the original path */
    {
        int di = 0;
        const char *src = fname;
        while (*src && di < 508) {
            alt[di++] = (*src == '\\') ? '/' : *src;
            src++;
        }
        alt[di] = 0;
        /* Only try if different from original */
        if (strcmp(alt, fname) != 0) {
            puts("  [FILE] trying (fwd slash): \""); puts(alt); puts("\"\n");
            char *d = read_file(alt, outlen);
            if (d) return d;
        }
    }

    /* 4. Try with cfg_dir prepended (for relative paths from config) */
    if (dir && dir[0]) {
        int di = 0;
        const char *dp = dir;
        while (*dp && di < 500) alt[di++] = *dp++;
        if (di > 0 && alt[di-1] != '\\' && alt[di-1] != '/') alt[di++] = '\\';
        dp = fname;
        while (*dp && di < 508) alt[di++] = *dp++;
        alt[di] = 0;
        puts("  [FILE] trying (with dir): \""); puts(alt); puts("\"\n");
        char *d = read_file(alt, outlen);
        if (d) return d;

        /* 5. Also try forward-slash of dir+... */
        {
            int ci = 0;
            while (ci < di) {
                if (alt[ci] == '\\') alt[ci] = '/';
                ci++;
            }
            puts("  [FILE] trying (with dir, fwd slash): \""); puts(alt); puts("\"\n");
            d = read_file(alt, outlen);
            if (d) return d;
        }
    }

    puts("  [FILE] ALL attempts failed for \""); puts(fname); puts("\"\n");
    return NULL;
}

/* ===================================================================
 * Main entry point
 * =================================================================== */
int main(int argc, char *argv[])
{
    int wolfSSL_inited = 0;
    char *resp = NULL;

    /* ---- Default Parameters ---- */
    const char *server   = "111.124.203.45"; /* smtp.163.com */
    int         port     = 25;
    const char *username = "13311286388@163.com";
    const char *password = "ASUYp5dLEtFHTPxu";
    const char *from     = "13311286388@163.com";
    const char *to_all   = "garryxin@qq.com";
    const char *cc_all   = NULL;
    const char *subject  = "AI News from HelloX OS (TLS)";
    const char *body_file = NULL;

    /* Detect config directory from argv[0] if possible */
    char cfg_dir[256];
    cfg_dir[0] = 0;
    if (argc > 0 && argv[0]) {
        int i = 0;
        const char *p = argv[0];
        const char *last_slash = NULL;
        while (*p) {
            if (*p == '\\' || *p == '/') last_slash = p;
            p++;
        }
        if (last_slash) {
            int n = (int)(last_slash - argv[0]);
            if (n > 255) n = 255;
            for (i = 0; i < n; i++) cfg_dir[i] = argv[0][i];
            cfg_dir[i] = 0;
        }
    }

    /* Try to load config file 'sendmail.cfg' from same directory as executable */
    char cfg_path[256];
    int cfg_loaded = 0;
    if (cfg_dir[0]) {
        int wi = 0;
        const char *dp = cfg_dir;
        while (*dp && wi < 244) cfg_path[wi++] = *dp++;
        cfg_path[wi++] = '\\';
        const char *cfgn = "sendmail.cfg";
        while (*cfgn && wi < 252) cfg_path[wi++] = *cfgn++;
        cfg_path[wi] = 0;
    } else {
        strncpy(cfg_path, "sendmail.cfg", sizeof(cfg_path)-1);
    }

    SendmailConfig *cfg_buf = (SendmailConfig*)malloc(sizeof(SendmailConfig));
    if (!cfg_buf) { puts("[MALLOC FAIL]\n"); goto cleanup; }
    cfg_loaded = load_config(cfg_path, cfg_buf);

    /* ---- Parse Arguments (override config if present) ---- */
    if (argc > 1 && argv[1][0] == '?' && argv[1][1] == 0) {
        usage();
        return 0;
    }

    /* Use CLI args if available; otherwise fall back to config file, then defaults */
    if (argc > 1) {
        /* CLI args available — parse them */
        if (argv[1][0] != '.') server = argv[1];
        if (argc > 2 && argv[2][0] != '.') {
            port = 0;
            const char *p = argv[2];
            while (*p) port = port * 10 + (*p++ - '0');
        }
        if (argc > 3 && argv[3][0] != '.') username = argv[3];
        if (argc > 4 && argv[4][0] != '.') password = argv[4];
        if (argc > 5 && argv[5][0] != '.') from = argv[5];
        if (argc > 6 && argv[6][0] != '.') to_all = argv[6];
        if (argc > 7 && argv[7][0] != '.') cc_all = argv[7];
        if (argc > 8 && argv[8][0] != '.') subject = argv[8];
    } else if (cfg_loaded) {
        /* No CLI args — use config file */
        server   = cfg_buf->server;
        port     = cfg_buf->port;
        username = cfg_buf->username;
        password = cfg_buf->password;
        from     = cfg_buf->from;
        to_all   = cfg_buf->to;
        if (cfg_buf->cc[0]) cc_all = cfg_buf->cc;
        subject  = cfg_buf->subject;
        if (cfg_buf->body_file[0]) body_file = cfg_buf->body_file;
    }
    /* else: use defaults */

    /* Parse attachments and body_file */
    const char *att_paths[MAX_ATTACH];
    int num_att = 0;

    if (argc > 1) {
        /* CLI: parse from argv[9]+ */
        for (int i = 9; i < argc; i++) {
            if (argv[i][0] == '-' && argv[i][1] == 'b' && argv[i][2] == 0) {
                if (i + 1 < argc) { body_file = argv[++i]; continue; }
            }
            if (num_att < MAX_ATTACH)
                att_paths[num_att++] = argv[i];
        }
    } else if (cfg_loaded) {
        /* Config file: use attachment paths from config */
        for (int i = 0; i < cfg_buf->num_att && i < MAX_ATTACH; i++) {
            att_paths[num_att++] = cfg_buf->attachments[i];
        }
        /* body_file already set above */
    }

    /* ---- Open Body File (streamed — no large heap alloc) ---- */
    HANDLE body_h = NULL;
    int    body_sz = 0;
    if (body_file) {
        /* Try open with read_file_at path resolution */
        body_h = open_file(body_file);
        if (!body_h && cfg_dir[0]) {
            char alt[512];
            int di = 0;
            const char *dp = cfg_dir;
            while (*dp && di < 500) alt[di++] = *dp++;
            if (di > 0 && alt[di-1] != '\\' && alt[di-1] != '/') alt[di++] = '\\';
            dp = body_file;
            while (*dp && di < 508) alt[di++] = *dp++;
            alt[di] = 0;
            body_h = open_file(alt);
        }
        if (body_h) {
            DWORD bsz = GetFileSize(body_h, NULL);
            if (bsz <= 0 || bsz > MAX_BODY_SIZE) {
                if (bsz > MAX_BODY_SIZE) {
                    puts("  [BODY SKIP] too large: "); putint((int)bsz);
                    puts(" > "); putint((int)MAX_BODY_SIZE); putc('\n');
                }
                CloseFile(body_h);
                body_h = NULL;
            } else {
                body_sz = (int)bsz;
                puts("  BODY OPENED: "); putint(body_sz); puts(" bytes (streamed)\n");
            }
        }
        if (!body_h) {
            puts("  BODY SKIP (not found)\n");
        }
    }

    /* ---- Read Attachments — streamed data struct (holds file handles) ---- */
    struct {
        HANDLE h;
        int sz;
        const char *fname;
        const char *mime;
    } atts[MAX_ATTACH];
    int att_cnt = 0;

    for (int i = 0; i < num_att; i++) {
        /* Try to open the attachment file via read_file_at path resolution */
        /* We use a separate open_file_at that returns a HANDLE */
        const char *ap = att_paths[i];
        /* Try as-is first */
        HANDLE ah = CreateFile((char*)ap, FILE_ACCESS_READ, 0, NULL);
        if (!ah) {
            /* Try with cfg_dir prefix */
            if (cfg_dir[0]) {
                char alt[512];
                int di = 0;
                const char *dp = cfg_dir;
                while (*dp && di < 500) alt[di++] = *dp++;
                if (di > 0 && alt[di-1] != '\\' && alt[di-1] != '/') alt[di++] = '\\';
                dp = ap;
                while (*dp && di < 508) alt[di++] = *dp++;
                alt[di] = 0;
                ah = CreateFile((char*)alt, FILE_ACCESS_READ, 0, NULL);
            }
        }
        if (!ah) {
            puts("  [ATT SKIP] cannot open: "); puts(ap); putc('\n');
            continue;
        }

        DWORD asz = GetFileSize(ah, NULL);
        if (asz <= 0 || asz > MAX_ATT_SIZE) {
            if (asz > MAX_ATT_SIZE) {
                puts("  [ATT SKIP] too large: "); putint((int)asz);
                puts(" > "); putint((int)MAX_ATT_SIZE); putc('\n');
            }
            CloseFile(ah); continue;
        }

        /* Extract filename from path */
        const char *fn = ap;
        const char *p = ap;
        while (*p) {
            if (*p == '\\' || *p == '/') fn = p + 1;
            p++;
        }

        atts[att_cnt].h = ah;
        atts[att_cnt].sz = (int)asz;
        atts[att_cnt].fname = fn;
        atts[att_cnt].mime  = mime_type(fn);
        att_cnt++;
    }

    puts("Attachments: "); putint(att_cnt); putc('\n');

    /* ---- TCP Connect ---- */
    resp = (char*)malloc(MAX_RESP);
    if (!resp) { puts("  [MALLOC FAIL]\n"); goto cleanup; }
    puts("[CONNECT] "); puts(server); putc(':'); putint(port); puts("...\n");
    int fd = tcp_connect(server, port);
    if (fd < 0) { puts("  [FAIL] err="); putint(fd); putc('\n'); fd = -1; goto cleanup; }
    puts("  [OK] fd="); putint(fd); putc('\n');

    /* ---- Phase 1: Plain SMTP ---- */
    if (smtp_cmd_plain(fd, NULL, 220, resp, MAX_RESP)) goto closefd;
    if (smtp_cmd_plain(fd, "EHLO HelloX-OS", 250, resp, MAX_RESP)) goto closefd;
    if (smtp_cmd_plain(fd, "STARTTLS", 220, resp, MAX_RESP)) {
        puts("[NO STARTTLS]\n"); goto closefd;
    }

    /* ---- Phase 2: TLS Handshake ---- */
    puts("[TLS] wolfSSL init...\n");
    wolfSSL_Init();
    wolfSSL_inited = 1;

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) { puts("  [CTX FAIL]\n"); goto closefd; }
    wolfSSL_CTX_SetIORecv(ctx, HxIORecv);
    wolfSSL_CTX_SetIOSend(ctx, HxIOSend);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) { puts("  [SSL FAIL]\n"); goto free_ctx; }
    wolfSSL_set_fd(ssl, fd);

    puts("[TLS] Handshaking...\n");
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        puts("  [HANDSHAKE FAIL] err="); putint(err); putc('\n');
        goto free_ssl;
    }
    puts("  [TLS OK] "); puts(wolfSSL_get_cipher(ssl)); putc('\n');

    /* ---- Phase 3: SMTP over TLS ---- */
    if (smtp_cmd_tls(ssl, "EHLO HelloX-OS", 250, resp, MAX_RESP)) goto free_ssl;
    if (smtp_cmd_tls(ssl, "AUTH LOGIN", 334, resp, MAX_RESP)) goto free_ssl;

    /* AUTH LOGIN - send base64 username and password */
    {
        char b64buf[512];
        int n;
        n = b64enc((const unsigned char*)username, (int)strlen(username), b64buf);
        b64buf[n] = 0;
        if (smtp_cmd_tls(ssl, b64buf, 334, resp, MAX_RESP)) goto free_ssl;

        n = b64enc((const unsigned char*)password, (int)strlen(password), b64buf);
        b64buf[n] = 0;
        if (smtp_cmd_tls(ssl, b64buf, 235, resp, MAX_RESP)) {
            puts("  [AUTH FAIL]\n"); goto free_ssl;
        }
    }

    /* ---- MAIL FROM ---- */
    {
        char cmd[300];
        sprintf(cmd, "MAIL FROM:<%s>", from);
        if (smtp_cmd_tls(ssl, cmd, 250, resp, MAX_RESP)) goto free_ssl;
    }

    /* ---- RCPT TO (support comma-separated recipients) ---- */
    {
        char *copy = (char*)malloc(2048);
        if (!copy) goto free_ssl;
        int ci = 0;
        const char *tp = to_all;
        while (*tp && ci < 2044) copy[ci++] = *tp++;
        copy[ci] = 0;

        char *tok = copy;
        while (1) {
            char *comma = strchr(tok, ',');
            if (comma) *comma = 0;
            while (*tok == ' ') tok++;
            if (*tok) {
                char cmd[300];
                sprintf(cmd, "RCPT TO:<%s>", tok);
                smtp_cmd_tls(ssl, cmd, 250, resp, MAX_RESP);
            }
            if (!comma) break;
            tok = comma + 1;
        }
        free(copy);
    }

    /* ---- CC Recipients ---- */
    if (cc_all) {
        char *copy = (char*)malloc(2048);
        if (!copy) goto free_ssl;
        int ci = 0;
        const char *cp = cc_all;
        while (*cp && ci < 2044) copy[ci++] = *cp++;
        copy[ci] = 0;

        char *tok = copy;
        while (1) {
            char *comma = strchr(tok, ',');
            if (comma) *comma = 0;
            while (*tok == ' ') tok++;
            if (*tok) {
                char cmd[300];
                sprintf(cmd, "RCPT TO:<%s>", tok);
                smtp_cmd_tls(ssl, cmd, 250, resp, MAX_RESP);
            }
            if (!comma) break;
            tok = comma + 1;
        }
    }

    /* ---- DATA ---- */
    if (smtp_cmd_tls(ssl, "DATA", 354, resp, MAX_RESP)) goto free_ssl;

    /* =============================================================
     * Send MIME payload — streamed (no large heap alloc for payload)
     * ============================================================= */
    const char *boundary = BOUNDARY_STR;
    int has_att = (att_cnt > 0);

#define STREAM(s) do { \
    const char *_sp = (s); \
    int _slen = 0; while (_sp[_slen]) _slen++; \
    if (send_payload_tls(ssl, _sp, _slen)) goto free_ssl; \
    total_sent += _slen; \
} while(0)

#define STREAMN(d, n) do { \
    if ((n) > 0 && send_payload_tls(ssl, (d), (n))) goto free_ssl; \
    total_sent += (n); \
} while(0)

    {
        int total_sent = 0;
        char sbuf[CHUNK_SIZE];

        /* Email Headers */
        STREAM("From: "); STREAM(from); STREAM("\r\n");
        STREAM("To: "); STREAM(to_all); STREAM("\r\n");
        if (cc_all) { STREAM("Cc: "); STREAM(cc_all); STREAM("\r\n"); }
        STREAM("Subject: "); STREAM(subject); STREAM("\r\n");
        STREAM("Date: Mon, 25 May 2026 10:00:00 +0800\r\n");
        STREAM("MIME-Version: 1.0\r\n");
        STREAM("X-Mailer: HelloX OS Sendmail\r\n");

        /* Content-Type header */
        if (has_att) {
            STREAM("Content-Type: multipart/mixed; boundary=\"");
            STREAM(boundary); STREAM("\"\r\n");
            STREAM("\r\n");
            /* Start first MIME part for body */
            STREAM("--"); STREAM(boundary); STREAM("\r\n");
            STREAM("Content-Type: text/plain; charset=\"utf-8\"\r\n");
            STREAM("Content-Transfer-Encoding: 7bit\r\n");
            STREAM("\r\n");
        } else {
            STREAM("Content-Type: text/plain; charset=\"utf-8\"\r\n");
        }

        STREAM("\r\n");

        /* Body with dot-stuffing — streamed in chunks from file handle */
        if (body_h) {
            unsigned char inchunk[CHUNK_SIZE / 2];
            while (1) {
                DWORD just_read = 0;
                if (!ReadFile(body_h, sizeof(inchunk), inchunk, &just_read))
                    break;
                if (just_read == 0) break;
                int slen = dot_stuff((const char*)inchunk, (int)just_read, sbuf, CHUNK_SIZE - 2);
                if (slen > 0) STREAMN(sbuf, slen);
            }
        } else {
            STREAM("This is a TLS-encrypted email from HelloX OS.\r\n");
        }

        /* Ensure body ends with \r\n */
        STREAM("\r\n");

        /* Attachments — streamed: read-chunk → base64-encode-chunk → send-loop */
        for (int i = 0; i < att_cnt; i++) {
            STREAM("--"); STREAM(boundary); STREAM("\r\n");
            STREAM("Content-Type: "); STREAM(atts[i].mime); STREAM("\r\n");
            STREAM("Content-Transfer-Encoding: base64\r\n");
            STREAM("Content-Disposition: attachment; filename=\"");
            STREAM(atts[i].fname); STREAM("\"\r\n");
            STREAM("\r\n");

            /* Read attachment in chunks, encode each chunk to base64, send */
            unsigned char in_chunk[48];  /* 48 bytes -> 64 chars base64 per group */
            int remaining = atts[i].sz;
            int col = 0;  /* current column in base64 output line */
            while (remaining > 0) {
                int to_read = (remaining > 48) ? 48 : remaining;
                DWORD just_read = 0;
                if (!ReadFile(atts[i].h, to_read, in_chunk, &just_read)) {
                    puts("  [ATT READ FAIL]\n");
                    break;
                }
                if (just_read == 0) break;
                remaining -= (int)just_read;

                /* Encode this chunk to base64 */
                int b64n = b64enc(in_chunk, (int)just_read, sbuf);
                if (b64n <= 0) continue;

                /* Break base64 into 76-char lines */
                int bo = 0;
                while (bo < b64n) {
                    int line_room = 76 - col;
                    int take = (b64n - bo > line_room) ? line_room : b64n - bo;
                    if (send_payload_tls(ssl, sbuf + bo, take)) {
                        puts("  [ATT SEND FAIL]\n");
                        goto free_ssl;
                    }
                    total_sent += take;
                    bo += take;
                    col += take;
                    if (col >= 76) {
                        STREAM("\r\n");
                        col = 0;
                    }
                }
            }

            /* Ensure attachment ends with newline */
            if (col > 0) STREAM("\r\n");
            col = 0;

            CloseFile(atts[i].h);
            atts[i].h = NULL;
        }

        /* Close MIME boundary */
        if (has_att) {
            STREAM("--"); STREAM(boundary); STREAM("--\r\n");
        }

        /* End SMTP DATA */
        STREAM("\r\n.\r\n");
        STREAM(""); /* flush */

        puts("Payload: "); putint(total_sent); puts(" bytes (encrypted, streamed)\n");
    }

#undef STREAM
#undef STREAMN

    /* Check response */
    recvline_tls(ssl, resp, MAX_RESP);
    puts("S: "); puts(resp); putc('\n');
    if (resp_code(resp) == 250) {
        puts("[EMAIL SENT SUCCESSFULLY]\n");
    } else {
        puts("  [EXP 250 GOT "); putint(resp_code(resp)); puts("]\n");
    }

    /* QUIT */
    smtp_cmd_tls(ssl, "QUIT", 221, resp, MAX_RESP);

free_ssl:
    if (ssl) wolfSSL_free(ssl);
free_ctx:
    if (ctx) wolfSSL_CTX_free(ctx);
closefd:
    if (fd >= 0) lwip_close(fd);
cleanup:
    if (wolfSSL_inited) wolfSSL_Cleanup();
    free(resp);
    free(cfg_buf);
    if (body_h) CloseFile(body_h);
    for (int i = 0; i < att_cnt; i++)
        if (atts[i].h) CloseFile(atts[i].h);
    puts("[SENDMAIL] Done\n");
    return 0;
}
