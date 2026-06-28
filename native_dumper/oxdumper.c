/*
 * OXIDE Memory Dumper v2 вЂ” РїРѕР»РЅС‹Р№ РґР°РјРї РїР°РјСЏС‚Рё
 * for Jack by Bin
 */
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

static void dump_libil2cpp(int pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) return;

    char line[512];
    char lib_path[256] = {0};
    while (fgets(line, sizeof(line), maps)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        if (!strstr(path, "libil2cpp.so")) continue;
        if (strstr(path, "arm64")) {
            strncpy(lib_path, path, sizeof(lib_path) - 1);
            break;
        }
        if (lib_path[0] == 0)
            strncpy(lib_path, path, sizeof(lib_path) - 1);
    }
    fclose(maps);
    if (lib_path[0] == 0) return;

    size_t len = strlen(lib_path);
    while (len > 0 && (lib_path[len-1] == '\n' || lib_path[len-1] == '\r'))
        lib_path[--len] = 0;
    fprintf(stderr, "[+] libil2cpp: %s\n", lib_path);

    char out_path[256];
    snprintf(out_path, sizeof(out_path), "%s/libil2cpp.so", OUTPUT_DIR);
    int src_fd = open(lib_path, O_RDONLY);
    if (src_fd < 0) return;
    int dst_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) { close(src_fd); return; }
    char buf[65536]; ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0)
        write(dst_fd, buf, n);
    close(src_fd); close(dst_fd);
    fprintf(stderr, "[+] libil2cpp saved\n");
}

static void dump_all_rwp(int pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) { fprintf(stderr, "[-] cant open maps\n"); return; }

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) { fclose(maps); return; }

    char line[512];
    int reg_id = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, "rw-p")) continue;
        unsigned long start, end;
        char perms[8], offset[32], dev[32], path[256] = {0};
        sscanf(line, "%lx-%lx %s %s %s %*s %s", &start, &end, perms, offset, dev, path);

        size_t size = end - start;
        // Р±РµР· Р»РёРјРёС‚Р° - РґР°РјРїРёРј РІСЃС‘

        char *map = (char *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, mem_fd, start);
        if (map == MAP_FAILED) { continue; }

        char out[384];
        snprintf(out, sizeof(out), "%s/rwp_%03d_0x%lx.bin", OUTPUT_DIR, reg_id++, start);
        FILE *f = fopen(out, "wb");
        if (f) {
            fwrite(map, 1, size, f);
            fclose(f);
            fprintf(stderr, "[%03d] saved 0x%lx (%zu KB)\n", reg_id-1, start, size/1024);
        }
        munmap(map, size);
    }
    close(mem_fd);
    fclose(maps);
    fprintf(stderr, "[+] Total rw-p regions: %d\n", reg_id);
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "[+] OXIDE Dumper v2 by Bin\n");
    mkdir(OUTPUT_DIR, 0755);

    int pid = -1;
    for (int i = 0; i < 30; i++) {
        pid = find_pid(PACKAGE_NAME);
        if (pid > 0) { fprintf(stderr, "[+] Game PID: %d\n", pid); break; }
        sleep(2);
    }
    if (pid < 0) { fprintf(stderr, "[-] Game not found\n"); return 1; }

    fprintf(stderr, "[*] Waiting 10s...\n");
    sleep(10);

    dump_libil2cpp(pid);

    fprintf(stderr, "[*] Waiting 5s for metadata...\n");
    sleep(5);

    fprintf(stderr, "[*] Dumping all rw-p memory regions...\n");
    dump_all_rwp(pid);

    fprintf(stderr, "[+] Done! Check %s\n", OUTPUT_DIR);
    return 0;
}
