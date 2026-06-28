/*
 * OXIDE Memory Dumper вЂ” РЅР°С‚РёРІРЅС‹Р№ ARM Р±РёРЅР°СЂРЅРёРє
 * for Jack <3 by Bin
 *
 * Р§РёС‚Р°РµС‚ РїР°РјСЏС‚СЊ РїСЂРѕС†РµСЃСЃР° РёРіСЂС‹ РЅР°РїСЂСЏРјСѓСЋ С‡РµСЂРµР· /proc/pid/mem
 * РЎРѕС…СЂР°РЅСЏРµС‚ libil2cpp.so Рё СЂР°СЃС€РёС„СЂРѕРІР°РЅРЅС‹Р№ global-metadata.dat
 * РЎРѕР±РёСЂР°РµС‚СЃСЏ РїРѕРґ Android С‡РµСЂРµР· NDK
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
#include <elf.h>

#define PACKAGE_NAME "com.catsbit.oxidesurvivalisland"
#define OUTPUT_DIR  "/sdcard/oxcide_dump"
#define METADATA_SIG "\x3C\xB8\x00\x00"

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
            // cmdline РјРѕР¶РµС‚ Р±С‹С‚СЊ СЂР°Р·РґРµР»С‘РЅ РЅСѓР»СЏРјРё, Р±РµСЂС‘Рј С‚РѕР»СЊРєРѕ РїРµСЂРІСѓСЋ С‡Р°СЃС‚СЊ
            if (strncmp(cmdline, pkg, strlen(pkg)) == 0) {
                fclose(fp);
                closedir(dir);
                return pid;
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
    if (!maps) {
        perror("[-] fopen maps");
        return;
    }

    char line[512];
    char lib_path[256] = {0};
    while (fgets(line, sizeof(line), maps)) {
        // РёС‰РµРј РїСѓС‚СЊ, СЃРѕРґРµСЂР¶Р°С‰РёР№ libil2cpp.so
        char *path = strchr(line, '/');
        if (path && strstr(path, "libil2cpp.so")) {
            strncpy(lib_path, path, sizeof(lib_path) - 1);
            // СѓР±РёСЂР°РµРј СЃРёРјРІРѕР» РїРµСЂРµРІРѕРґР° СЃС‚СЂРѕРєРё
            size_t len = strlen(lib_path);
            while (len > 0 && (lib_path[len-1] == '\n' || lib_path[len-1] == '\r'))
                lib_path[--len] = 0;
            break;
        }
    }
    fclose(maps);

    if (lib_path[0] == 0) {
        fprintf(stderr, "[-] libil2cpp.so not found in maps\n");
        return;
    }

    fprintf(stderr, "[+] Found libil2cpp.so: %s\n", lib_path);

    // РѕС‚РєСЂС‹РІР°РµРј РёСЃС…РѕРґРЅС‹Р№ .so С‡РµСЂРµР· maps вЂ” РѕРЅ СѓР¶Рµ Р·Р°РіСЂСѓР¶РµРЅ РІ РїР°РјСЏС‚СЊ
    // РЅРѕ РјС‹ РјРѕР¶РµРј СЃРєРѕРїРёСЂРѕРІР°С‚СЊ СЃР°Рј С„Р°Р№Р» СЃ РґРёСЃРєР° С‡РµСЂРµР· readlink РёР· maps
    // РёР»Рё РїСЂРѕСЃС‚Рѕ РїСЂРѕС‡РёС‚Р°С‚СЊ /proc/pid/exe вЂ” РЅРµС‚, РЅР°Рј РЅСѓР¶РµРЅ РєРѕРЅРєСЂРµС‚РЅС‹Р№ .so

    // РєРѕРїРёСЂСѓРµРј С„Р°Р№Р»
    char out_path[256];
    snprintf(out_path, sizeof(out_path), "%s/libil2cpp.so", OUTPUT_DIR);

    int src_fd = open(lib_path, O_RDONLY);
    if (src_fd < 0) {
        perror("[-] open libil2cpp.so");
        return;
    }

    int dst_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        perror("[-] open output");
        close(src_fd);
        return;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        write(dst_fd, buf, n);
    }

    close(src_fd);
    close(dst_fd);
    fprintf(stderr, "[+] libil2cpp.so saved to %s\n", out_path);
}

static void dump_global_metadata(int pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) return;

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror("[-] open mem");
        fclose(maps);
        return;
    }

    char line[512];
    char out_path[256];
    snprintf(out_path, sizeof(out_path), "%s/global-metadata.dat", OUTPUT_DIR);

    char sig[] = METADATA_SIG;
    int sig_len = 4;
    int found = 0;

    while (fgets(line, sizeof(line), maps)) {
        // РЅР°СЃ РёРЅС‚РµСЂРµСЃСѓСЋС‚ С‚РѕР»СЊРєРѕ rw-p СЂРµРіРёРѕРЅС‹
        if (!strstr(line, "rw-p")) continue;

        unsigned long start, end;
        char perms[8], offset[16], dev[16], inode[32];
        char path[256] = {0};

        sscanf(line, "%lx-%lx %s %s %s %ld %s", &start, &end,
               perms, offset, dev, (long *)&inode, path);

        // Р°РЅРѕРЅРёРјРЅС‹Рµ РјР°РїРїРёРЅРіРё (Р±РµР· РїСѓС‚Рё) вЂ” СЃР°РјС‹Рµ РёРЅС‚РµСЂРµСЃРЅС‹Рµ
        // РЅРѕ РїСЂРѕРІРµСЂРёРј РІСЃС‘ rw-p
        size_t size = end - start;
        if (size > 1024 * 1024 * 100) continue; // СЃРєРёРїР°РµРј СЂРµРіРёРѕРЅС‹ > 100MB

        // mmap СЂРµРіРёРѕРЅ
        void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, mem_fd, start);
        if (map == MAP_FAILED) continue;

        unsigned char *data = (unsigned char *)map;
        for (size_t i = 0; i < size - sig_len; i++) {
            if (memcmp(data + i, sig, sig_len) == 0) {
                fprintf(stderr, "[+] Found metadata at 0x%lx + 0x%zx\n", start, i);

                // С‡РёС‚Р°РµРј СЂР°Р·РјРµСЂ РёР· СЃРјРµС‰РµРЅРёСЏ +8 (4 Р±Р°Р№С‚Р°)
                unsigned int meta_size;
                if (i + 12 <= size) {
                    meta_size = *(unsigned int *)(data + i + 8);
                } else {
                    meta_size = 0;
                }

                unsigned int total_size;
                if (meta_size > 0 && meta_size < 1024 * 1024 * 50) {
                    total_size = meta_size + 16;
                } else {
                    total_size = size - i; // РЅР° РІСЃСЏРєРёР№ СЃР»СѓС‡Р°Р№
                    if (total_size > 1024 * 1024 * 10) total_size = 1024 * 1024 * 10;
                }

                // СЃРѕС…СЂР°РЅСЏРµРј
                FILE *out = fopen(out_path, "wb");
                if (out) {
                    fwrite(data + i, 1, total_size, out);
                    fclose(out);
                    fprintf(stderr, "[+] global-metadata.dat saved (%u bytes)\n", total_size);
                    found = 1;
                }
                break;
            }
        }

        munmap(map, size);
        if (found) break;
    }

    if (!found) {
        fprintf(stderr, "[-] global-metadata signature not found\n");
    }

    close(mem_fd);
    fclose(maps);
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "[+] OXIDE Dumper by Bin\n");

    // СЃРѕР·РґР°С‘Рј РґРёСЂРµРєС‚РѕСЂРёСЋ
    mkdir(OUTPUT_DIR, 0755);

    // Р¶РґС‘Рј РїРѕРєР° РёРіСЂР° Р·Р°РїСѓСЃС‚РёС‚СЃСЏ
    int pid = -1;
    for (int i = 0; i < 30; i++) {
        pid = find_pid(PACKAGE_NAME);
        if (pid > 0) {
            fprintf(stderr, "[+] Game PID: %d (attempt %d)\n", pid, i + 1);
            break;
        }
        sleep(2);
    }

    if (pid < 0) {
        fprintf(stderr, "[-] Game not found after 60 seconds\n");
        return 1;
    }

    // Р¶РґС‘Рј 10 СЃРµРєСѓРЅРґ РґР»СЏ Р·Р°РіСЂСѓР·РєРё Unity
    fprintf(stderr, "[+] Waiting 10 seconds for Unity to load...\n");
    sleep(10);

    // РґР°РјРїРёРј libil2cpp.so
    dump_libil2cpp(pid);

    // Р¶РґС‘Рј РµС‰С‘ РґР»СЏ РјРµС‚Р°РґР°С‚С‹
    sleep(5);

    // РґР°РјРїРёРј global-metadata
    dump_global_metadata(pid);

    fprintf(stderr, "[+] Done! Check %s\n", OUTPUT_DIR);
    return 0;
}
