#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PACKAGE_NAME "com.catsbit.oxidesurvivalisland"
#define OUTPUT_DIR  "/sdcard/oxcide_dump"

static int find_pid(const char *pkg) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char cmdline[256];
        if (fgets(cmdline, sizeof(cmdline), fp)) {
            if (strncmp(cmdline, pkg, strlen(pkg)) == 0) {
                fclose(fp); closedir(dir); return pid;
            }
        }
        fclose(fp);
    }
    closedir(dir);
    return -1;
}

static void dump_libil2cpp(int pid, int *found) {
    *found = 0;
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) return;

    char line[512];
    char lib_path[256] = {0};
    while (fgets(line, sizeof(line), maps)) {
        char *p = strchr(line, '/');
        if (!p) continue;
        if (!strstr(p, "libil2cpp.so")) continue;
        if (strstr(p, "arm64")) { strncpy(lib_path, p, sizeof(lib_path)-1); break; }
        if (lib_path[0] == 0) strncpy(lib_path, p, sizeof(lib_path)-1);
    }
    fclose(maps);
    if (lib_path[0] == 0) return;

    size_t len = strlen(lib_path);
    while (len > 0 && (lib_path[len-1] == '\n' || lib_path[len-1] == '\r')) lib_path[--len] = 0;
    fprintf(stderr, "[+] libil2cpp: %s\n", lib_path);

    char out[256];
    snprintf(out, sizeof(out), "%s/libil2cpp.so", OUTPUT_DIR);
    int src = open(lib_path, O_RDONLY);
    if (src < 0) return;
    int dst = open(out, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (dst < 0) { close(src); return; }
    char buf[65536]; ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) write(dst, buf, n);
    close(src); close(dst);
    fprintf(stderr, "[+] libil2cpp saved\n");
    *found = 1;
}

static void dump_all_rwp(int pid, int *count) {
    *count = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) { fprintf(stderr, "[-] open maps failed\n"); return; }

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int mem = open(path, O_RDONLY);
    if (mem < 0) { fclose(maps); fprintf(stderr, "[-] open mem failed\n"); return; }

    char line[512];
    int saved = 0;
    int rwp = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, "rw-p")) continue;
        rwp++;

        unsigned long s, e;
        char p[8]={0}, o[32]={0}, d[32]={0};
        sscanf(line, "%lx-%lx %s %s %s", &s, &e, p, o, d);
        size_t sz = e - s;
        if (sz == 0) continue;

        char *map = (char*)mmap(NULL, sz, PROT_READ, MAP_PRIVATE, mem, s);
        if (map == MAP_FAILED) { fprintf(stderr, "  mmap fail 0x%lx\n", s); continue; }

        char out[384];
        snprintf(out, sizeof(out), "%s/rwp_%03d_0x%lx.bin", OUTPUT_DIR, saved, s);
        FILE *f = fopen(out, "wb");
        if (f) {
            size_t w = fwrite(map, 1, sz, f);
            fclose(f);
            char unit = 'B';
            double val = (double)w;
            if (val > 1073741824) { val /= 1073741824; unit = 'G'; }
            else if (val > 1048576) { val /= 1048576; unit = 'M'; }
            else if (val > 1024) { val /= 1024; unit = 'K'; }
            fprintf(stderr, "[%03d] 0x%lx (%.1f %cB)\n", saved, s, val, unit);
            saved++;
        } else {
            fprintf(stderr, "  fail create %s\n", out);
        }
        munmap(map, sz);
    }
    close(mem);
    fclose(maps);
    fprintf(stderr, "[+] rw-p lines found: %d, saved: %d\n", rwp, saved);
    *count = saved;
}

int main() {
    fprintf(stderr, "[+] OXIDE Dumper v6 by Bin\n");
    mkdir(OUTPUT_DIR, 0755);

    int pid = -1;
    for (int i = 0; i < 30; i++) {
        pid = find_pid(PACKAGE_NAME);
        if (pid > 0) { fprintf(stderr, "[+] PID: %d (attempt %d)\n", pid, i+1); break; }
        sleep(2);
    }
    if (pid < 0) { fprintf(stderr, "[-] game not running\n"); return 1; }

    sleep(10);

    int lib_ok = 0;
    dump_libil2cpp(pid, &lib_ok);

    sleep(5);

    int rwp_count = 0;
    dump_all_rwp(pid, &rwp_count);

    fprintf(stderr, "[+] Done! lib:%d regions:%d\n", lib_ok, rwp_count);
    return 0;
}
