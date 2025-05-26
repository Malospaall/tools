// For compile on attacker machine: sudo apt install libpdp-dev libparsec-mic3-dev
// gcc astra-check-security.c -o astra-check-security -lpdp
// Run execute file on vuln machine

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ftw.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include <parsec/parsec.h>
#include <parsec/parsec_mac.h>
#include <parsec/pdp.h>
#include "parsec/pdp_common.h"

#define CONFIG_FILE "/etc/parsec/fs-ilev.conf"
#define MAX_PATH_LEN 4096
#define MAX_ENTRIES 1024

typedef struct {
    int exc;
    PDP_ILEV_T ilev;
    char path[MAX_PATH_LEN];
    int has_wildcard;
} ConfigEntry;

static ConfigEntry entries[MAX_ENTRIES];
static int entries_count = 0;
static int errors_found = 0;
static PDP_ILEV_T max_ilev = 63;

// === Парсинг уровня целостности ===
static int parse_ilev(const char *txt, PDP_ILEV_T *ilev) {
    if (!txt || *txt == '\0') return *ilev = 0, 0;

    if (!strcmp(txt, "max") || !strcmp(txt, "high")) return *ilev = max_ilev, 0;
    if (!strcmp(txt, "min") || !strcmp(txt, "low")) return *ilev = 0, 0;

    if (strncmp(txt, "0b", 2) == 0) {
        PDP_ILEV_T val = 0;
        for (const char *p = txt + 2; *p == '0' || *p == '1'; ++p)
            val = (val << 1) | (*p - '0');
        return *ilev = val, 0;
    }

    char *endptr;
    long val = strtol(txt, &endptr, 0);
    if (*endptr || val < 0) return -1;
    *ilev = (PDP_ILEV_T)val;
    return 0;
}

static void add_entry(int exc, PDP_ILEV_T ilev, const char *path) {
    if (entries_count >= MAX_ENTRIES) return;
    ConfigEntry *e = &entries[entries_count++];
    e->exc = exc;
    e->ilev = ilev;
    strncpy(e->path, path, MAX_PATH_LEN - 1);
    e->path[MAX_PATH_LEN - 1] = '\0';
    e->has_wildcard = (strchr(path, '*') != NULL);
}

static int read_config(void) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return perror("fopen"), -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        char ilev_str[64], path_str[MAX_PATH_LEN];
        int exc_flag = 0;

        if (sscanf(p, "%63s %4095s", ilev_str, path_str) != 2) continue;
        if (!strcmp(ilev_str, "exc")) {
            add_entry(1, 0, path_str);
            continue;
        }

        if (path_str[0] != '/') continue;

        PDP_ILEV_T ilev_val;
        if (parse_ilev(ilev_str, &ilev_val) != 0) {
            fprintf(stderr, "Bad ilev: %s\n", ilev_str);
            continue;
        }
        add_entry(0, ilev_val, path_str);
    }

    fclose(f);
    return 0;
}

static int is_path_match(const char *pattern, const char *filepath, int wildcard) {
    if (wildcard) return fnmatch(pattern, filepath, 0) == 0;
    size_t len = strlen(pattern);
    return strncmp(filepath, pattern, len) == 0 && (filepath[len] == '\0' || filepath[len] == '/');
}

static int is_excluded(const char *filepath) {
    for (int i = 0; i < entries_count; ++i)
        if (entries[i].exc && is_path_match(entries[i].path, filepath, entries[i].has_wildcard))
            return 1;
    return 0;
}

static int check_file(const char *filepath) {
    if (is_excluded(filepath)) return 0;

    int best_idx = -1;
    size_t best_len = 0;

    for (int i = 0; i < entries_count; ++i) {
        ConfigEntry *e = &entries[i];
        if (e->exc) continue;
        if (is_path_match(e->path, filepath, e->has_wildcard)) {
            size_t len = strlen(e->path);
            if (len > best_len) best_idx = i, best_len = len;
        }
    }

    if (best_idx == -1) return 0;

    ConfigEntry *ce = &entries[best_idx];
    PDPL_T *label = pdp_get_path(filepath);
    if (!label) return 0;

    PDP_ILEV_T real_ilev = pdpl_ilev(label);
    pdpl_put(label);

    if (real_ilev != ce->ilev) {
        if (!errors_found) printf("   Защита файловой системы:\n");
        printf("   - запрошен: %d установлен: %d %s\n", ce->ilev, real_ilev, filepath);
        errors_found = 1;
    }

    return 0;
}

static int nftw_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (typeflag == FTW_F) check_file(fpath);
    return 0;
}

static int process_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    if (S_ISDIR(st.st_mode)) nftw(path, nftw_callback, 20, FTW_PHYS);
    else if (S_ISREG(st.st_mode)) check_file(path);

    return 0;
}

static int check_exim4_ilev1(void) {
    FILE *fp = popen("systemctl cat exim4.service 2>/dev/null", "r");
    if (!fp) return fprintf(stderr, "Ошибка systemctl\n"), -1;

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp))
        if (strstr(buffer, "/etc/systemd/system/exim4.service.d/ilev1.conf"))
            return pclose(fp), 1;

    return pclose(fp), 0;
}

static int check_digsig_elf_mode_status(void) {
    const char *filename = "/etc/digsig/digsig_initramfs.conf";
    FILE *f = fopen(filename, "r");
    if (!f) {
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "DIGSIG_ELF_MODE=1")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

typedef enum {
    SECDEL_ACCESS_DENIED = -1,
    SECDEL_INACTIVE = 0,
    SECDEL_SIGNATURE,
    SECDEL_RANDOM
} SecdelStatus;

static SecdelStatus check_secdel_status(void) {
    FILE *f = fopen("/etc/fstab", "r");
    if (!f) return SECDEL_ACCESS_DENIED;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "secdelrnd")) {
            fclose(f);
            return SECDEL_RANDOM;
        } else if (strstr(line, "secdel")) {
            fclose(f);
            return SECDEL_SIGNATURE;
        }
    }

    fclose(f);
    return SECDEL_INACTIVE;
}

static int check_swap_wiper(void) {
    FILE *f = fopen("/etc/parsec/swap_wiper.conf", "r");
    if (!f) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ENABLED=Y", 9) == 0) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

static int check_ufw_status(void) {
    FILE *f = fopen("/etc/ufw/ufw.conf", "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "ENABLED=no")) {
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return 1;
}

static int check_removable_mounting(void) {
    FILE *f = fopen("/lib/udev/rules.d/91-group-floppy.rules", "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "GROUP=\"astra-admin\"")) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

static int check_parsec_audit_rules(void) {
    const char *files[] = {
        "/parsecfs/disable-all-audit",
        "/parsecfs/disable-denied-audit",
        "/parsecfs/disable-non-mac-audit"
    };

    char buf[8];

    for (int i = 0; i < 3; ++i) {
        FILE *f = fopen(files[i], "r");
        if (!f) return -1;
        if (!fgets(buf, sizeof(buf), f)) {
            fclose(f);
            return 0;
        }
        fclose(f);
        if (buf[0] != '0') return 0;
    }

    return 1;
}

static int check_apache_cups_controls(void) {
    FILE *f;
    char line[512];

    f = fopen("/etc/apache2/apache2.conf", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "AstraMode on")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }

    f = fopen("/etc/cups/cupsd.conf", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "MacEnable on")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }

    return 0;
}

static int check_overlay_root(void) {
    FILE *fp = popen("findmnt -lnf -o FSTYPE / 2>/dev/null", "r");
    if (!fp) return 0;

    char buf[64];
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return 0;
    }
    pclose(fp);

    buf[strcspn(buf, "\r\n")] = '\0';

    return strcmp(buf, "overlay") == 0;
}

static int check_lkrg_status(void) {
    FILE *fp = popen("/sbin/sysctl -a 2>/dev/null", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "lkrg.", 5) == 0) {
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }

    int modinfo_result = system("modinfo lkrg >/dev/null 2>&1");
    if (modinfo_result == 0)
        return 0;

    return -1;
}

static int check_grub_menu_hidden(void) {
    FILE *fp = fopen("/etc/default/grub", "r");
    if (!fp) {
        return -1;
    }

    char line[256];
    int grub_timeout = -1;
    int grub_hidden_timeout = -1;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;

        if (line[0] == '#' || strlen(line) == 0) {
            continue;
        }

        if (strncmp(line, "GRUB_TIMEOUT=", 13) == 0) {
            grub_timeout = atoi(line + 13);
        } else if (strncmp(line, "GRUB_HIDDEN_TIMEOUT=", 20) == 0) {
            grub_hidden_timeout = atoi(line + 20);
        }
    }

    fclose(fp);

    if (grub_timeout == 0 || grub_hidden_timeout == 0) {
        return 1;
    } else if (grub_timeout != -1 && grub_hidden_timeout != -1) {
        return 0;
    }
}

static int check_ptrace_lock(void) {
    FILE *fp = popen("grep -q '^kernel.yama.ptrace_scope=0' /etc/sysctl.d/999-astra.conf 2>/dev/null; echo $?", "r");
    if (!fp) return -1;

    char buf[8];
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    int status = atoi(buf);

    if (status == 0)
        return 0;
    else if (status == 2)
        return -1;
    else
        return 1;
}

static int check_sudo_password(void) {
    FILE *fp = popen("grep -q '^%astra-admin.*NOPASSWD:' /etc/sudoers 2>/dev/null; echo $?", "r");
    if (!fp) return -1;

    char buf[8];
    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    int status = atoi(buf);

    if (status == 0)
        return 0;
    else if (status == 2)
        return -1;
    else
        return 1;
}

int check_sumac(char error_msgs[][256], int *error_count) {
    struct {
        const char *path;
        const char *req_perm;
        const char *req_owner;
        const char *req_group;
    } files[] = {
        {"/usr/bin/sumac", "0", "root", "root"},
        {"/usr/lib/x86_64-linux-gnu/fly-run/libsumacrunner.so", "0", "root", "root"},
    };

    int found_files = 0;
    *error_count = 0;
    int max_errors = 10;

    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
        struct stat st;
        if (stat(files[i].path, &st) != 0) {
            if (*error_count < max_errors)
                snprintf(error_msgs[(*error_count)++], 256, "%s: отсутствует", files[i].path);
            continue;
        }

        found_files++;

        char perm_str[5];
        snprintf(perm_str, sizeof(perm_str), "%o", st.st_mode & 07777);

        struct passwd *pw = getpwuid(st.st_uid);
        const char *owner = pw ? pw->pw_name : "UNKNOWN";

        struct group *gr = getgrgid(st.st_gid);
        const char *group = gr ? gr->gr_name : "UNKNOWN";

        char error_msg[256] = "";
        if (strcmp(perm_str, files[i].req_perm) != 0)
            snprintf(error_msg + strlen(error_msg), 256 - strlen(error_msg),
                     "права %s (требуется %s), ", perm_str, files[i].req_perm);

        if (strcmp(owner, files[i].req_owner) != 0)
            snprintf(error_msg + strlen(error_msg), 256 - strlen(error_msg),
                     "владелец %s (требуется %s), ", owner, files[i].req_owner);

        if (strcmp(group, files[i].req_group) != 0)
            snprintf(error_msg + strlen(error_msg), 256 - strlen(error_msg),
                     "группа %s (требуется %s), ", group, files[i].req_group);

        if (error_msg[0] != '\0') {
            size_t len = strlen(error_msg);
            if (len >= 2)
                error_msg[len - 2] = '\0';
            if (*error_count < max_errors)
                snprintf(error_msgs[(*error_count)++], 256, "%s: %s", files[i].path, error_msg);
        }
    }

    if (found_files == 0)
        return 2;

    if (*error_count == 0)
        return 0;

    return 1;
}

static int check_ssh_root_login(void) {
    FILE *f = fopen("/etc/ssh/sshd_config", "r");
    if (!f) return -1;

    char line[512];
    int active = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, "PermitRootLogin no", 18) == 0) {
            active = 1;
            break;
        }
    }
    fclose(f);
    return active;
}

static int check_shutdown_lock(void) {
    FILE *f = fopen("/etc/X11/fly-dm/fly-dmrc", "r");
    if (!f) return -1;

    char line[512];
    int active = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, "AllowShutdown=Root", 17) == 0) {
            active = 1;
            break;
        }
    }
    fclose(f);
    return active;
}

static int check_format_password_request(void) {
    const char *policy_file = "/usr/share/polkit-1/actions/ru.rusbitech.fly.formatdevicehelper.policy";
    FILE *f = fopen(policy_file, "r");
    if (!f) return -1;

    char line[1024];
    int inactive = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "<allow_active>") && strstr(line, "yes") && strstr(line, "</allow_active>")) {
            inactive = 1;
            break;
        }
    }
    fclose(f);
    return inactive ? 0 : 1;
}

static int check_autologin(void) {
    const char *file = "/etc/X11/fly-dm/fly-dmrc";
    FILE *f = fopen(file, "r");
    if (!f) return -1;

    char line[256];
    int active = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;

        char *start = line;
        while (*start && isspace((unsigned char)*start)) start++;

        if (strncmp(start, "AutoLoginEnable", 15) == 0) {
            char *eq = strchr(start, '=');
            if (eq) {
                eq++;
                while (*eq && isspace((unsigned char)*eq)) eq++;
                if (strncmp(eq, "true", 4) == 0)
                    active = 1;
            }
            break;
        }
    }
    fclose(f);
    return active;
}

static int check_nochmodx(void) {
    FILE *f1 = fopen("/etc/parsec/nochmodx", "r");
    FILE *f2 = fopen("/parsecfs/nochmodx", "r");

    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return -1;
    }

    char buf1[16] = {0}, buf2[16] = {0};
    fgets(buf1, sizeof(buf1), f1);
    fgets(buf2, sizeof(buf2), f2);

    fclose(f1);
    fclose(f2);

    buf1[strcspn(buf1, "\r\n")] = 0;
    buf2[strcspn(buf2, "\r\n")] = 0;

    if (strcmp(buf1, "1") == 0 && strcmp(buf2, "1") == 0)
        return 1;
    else
        return 0;
}

// === Функции для проверки блокировки интерпретаторов ===
static char *interp_dirs[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"};
static char *interp_patterns[] = {
    "perl*", "python*", "ruby*", "irb*", "dash*", "ksh*", "zsh*", "csh*", "tcl*", "tk*", "expect*", "lua*", "php[0123456789]*", "node*", "qemu-*-static*", "ptksh*", "cpan*", "blender*", "vim.gtk*"
};

static char *loader_dirs[] = {"/lib", "/lib64"};
static char *loader_patterns[] = {"ld-*.so*"};

static char *missing_attr_files[MAX_ENTRIES];
static int missing_count = 0;
static int total_files_found = 0;

static int file_matches_patterns(const char *filename, char **patterns, int patterns_count) {
    for (int i = 0; i < patterns_count; i++) {
        if (fnmatch(patterns[i], filename, 0) == 0)
            return 1;
    }
    return 0;
}

static int is_executable_file(const char *path, const struct stat *sb) {
    if (!S_ISREG(sb->st_mode)) return 0;
    if (access(path, X_OK) == 0) return 1;
    return 0;
}

static int check_security_interpreter_attr(const char *filepath) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "getfattr -n security.interp '%s' 2>/dev/null", filepath);

    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;

    char buf[128];
    int has_attr = 0;
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        has_attr = 1;
    }
    pclose(fp);
    return has_attr;
}

static void add_missing_file(const char *filepath) {
    if (missing_count < MAX_ENTRIES) {
        missing_attr_files[missing_count] = strdup(filepath);
        missing_count++;
    }
}

static int scan_dir_for_patterns(const char *dirpath, char **patterns, int patterns_count) {
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat sb;
        if (stat(fullpath, &sb) == -1) continue;

        if (S_ISDIR(sb.st_mode)) {
            continue;
        }

        if (!file_matches_patterns(entry->d_name, patterns, patterns_count))
            continue;

        if (!is_executable_file(fullpath, &sb))
            continue;

        total_files_found++;

        if (!check_security_interpreter_attr(fullpath)) {
            add_missing_file(fullpath);
        }
    }

    closedir(dir);
    return 0;
}

static int scan_dir_recursive_for_loaders(const char *dirpath, char **patterns, int patterns_count) {
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat sb;
        if (stat(fullpath, &sb) == -1) continue;

        if (strstr(fullpath, "/live/")) continue;

        if (S_ISDIR(sb.st_mode)) {
            scan_dir_recursive_for_loaders(fullpath, patterns, patterns_count);
            continue;
        }

        if (!file_matches_patterns(entry->d_name, patterns, patterns_count))
            continue;

        if (!is_executable_file(fullpath, &sb))
            continue;

        total_files_found++;

        if (!check_security_interpreter_attr(fullpath)) {
            add_missing_file(fullpath);
        }
    }

    closedir(dir);
    return 0;
}

static void check_security_interp(void) {
    for (int i = 0; i < (int)(sizeof(interp_dirs)/sizeof(interp_dirs[0])); i++) {
        scan_dir_for_patterns(interp_dirs[i], interp_patterns, sizeof(interp_patterns)/sizeof(interp_patterns[0]));
    }

    for (int i = 0; i < (int)(sizeof(loader_dirs)/sizeof(loader_dirs[0])); i++) {
        scan_dir_recursive_for_loaders(loader_dirs[i], loader_patterns, sizeof(loader_patterns)/sizeof(loader_patterns[0]));
    }

    if (total_files_found == 0) {
        printf("НЕ НАЙДЕНО ФАЙЛОВ ДЛЯ ПРОВЕРКИ\n");
    } else if (missing_count == 0) {
        printf("АКТИВНО\n");
    } else {
        printf("НЕАКТИВНО (Отсутствует security.interp в файлах):\n");
        for (int i = 0; i < missing_count; i++) {
            printf("    - %s\n", missing_attr_files[i]);
            free(missing_attr_files[i]);
        }
    }
    missing_count = 0;
}

// === Функции для проверки блокировки bash ===
static const char *search_dirs[] = {
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"
};

static const char *bash_patterns[] = {
    "bash*"
};

static char *missing_bash_files[MAX_ENTRIES];
static int missing_bash_count = 0;
static int total_bash_found = 0;

static int bash_file_matches_patterns(const char *filename) {
    for (int i = 0; i < (int)(sizeof(bash_patterns)/sizeof(bash_patterns[0])); i++) {
        if (fnmatch(bash_patterns[i], filename, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

static int has_security_interp(const char *path) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "getfattr -n security.interp '%s' 2>/dev/null", path);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;

    char buf[128];
    int has_attr = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "security.interp")) {
            has_attr = 1;
            break;
        }
    }
    pclose(fp);
    return has_attr;
}

static void add_missing_bash_file(const char *path) {
    if (missing_bash_count < MAX_ENTRIES) {
        missing_bash_files[missing_bash_count++] = strdup(path);
    }
}

static void scan_bash_dir(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat sb;
        if (stat(fullpath, &sb) != 0) continue;

        if (!bash_file_matches_patterns(entry->d_name))
            continue;

        if (!is_executable_file(fullpath, &sb))
            continue;

        total_bash_found++;

        if (!has_security_interp(fullpath)) {
            add_missing_bash_file(fullpath);
        }
    }

    closedir(dir);
}

static void check_bash_lock(void) {
    for (int i = 0; i < (int)(sizeof(search_dirs)/sizeof(search_dirs[0])); i++) {
        scan_bash_dir(search_dirs[i]);
    }

    if (total_bash_found == 0) {
        printf("НЕ НАЙДЕНО ФАЙЛОВ ДЛЯ ПРОВЕРКИ\n");
    } else if (missing_bash_count == 0) {
        printf("АКТИВНО (Все %d файлов имеют security.interp)\n", total_bash_found);
    } else {
        printf("НЕАКТИВНО (Отсутствует security.interp в %d файлах из %d):\n", missing_bash_count, total_bash_found);
        for (int i = 0; i < missing_bash_count; i++) {
            printf("    - %s\n", missing_bash_files[i]);
            free(missing_bash_files[i]);
        }
    }
}

static void check_macro_execution_lock(void) {
    const char *unopkg_paths[] = {
        "/usr/bin/unopkg",
        "/usr/lib/libreoffice/program/unopkg"
    };
    int total_checks = 0;
    int found_config = 0;

    for (int i = 0; i < (int)(sizeof(unopkg_paths)/sizeof(unopkg_paths[0])); i++) {
        const char *unopkg = unopkg_paths[i];
        if (access(unopkg, X_OK) == 0) {
            total_checks++;
            char cmd[4096];
            snprintf(cmd, sizeof(cmd), "'%s' list --shared 2>/dev/null", unopkg);

            FILE *fp = popen(cmd, "r");
            if (!fp) continue;

            char buf[1024];
            while (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "Identifier: config_level_macros")) {
                    found_config++;
                    break;
                }
            }
            pclose(fp);
        }
    }

    if (total_checks == 0) {
        printf("LibreOffice не установлен или unopkg не найден\n");
    } else if (found_config == total_checks) {
        printf("АКТИВНО\n");
    } else if (found_config > 0) {
        printf("ЧАСТИЧНО (найдено в %d из %d проверок)\n", found_config, total_checks);
    } else {
        printf("НЕАКТИВНО\n");
    }
}

static void check_console_lock(void) {
    struct {
        const char *path;
        int required_mode;
        const char *required_owner;
        const char *required_group;
    } check_params[] = {
        { "/usr/bin/fly-run", 0750, "root", "astra-console" },
        { "/dev/pts",         0750, "root", "astra-console" },
        { "/dev/ptmx",        0672, "root", "astra-console" }
    };

    struct {
        const char *file;
        char message[256];
    } error_list[10];  // до 10 проблемных файлов, можно расширить

    int error_count = 0;
    int total = sizeof(check_params) / sizeof(check_params[0]);

    for (int i = 0; i < total; i++) {
        const char *file = check_params[i].path;
        struct stat sb;

        if (stat(file, &sb) != 0) {
            snprintf(error_list[error_count].message, sizeof(error_list[error_count].message),
                     "%s: отсутствует", file);
            error_list[error_count].file = file;
            error_count++;
            continue;
        }

        int actual_mode = sb.st_mode & 0777;
        struct passwd *pw = getpwuid(sb.st_uid);
        struct group  *gr = getgrgid(sb.st_gid);

        const char *actual_owner = pw ? pw->pw_name : "UNKNOWN";
        const char *actual_group = gr ? gr->gr_name : "UNKNOWN";

        char msg[256] = "";
        int mismatch = 0;

        if (actual_mode != check_params[i].required_mode) {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                     "права %o (требуется %o), ", actual_mode, check_params[i].required_mode);
            mismatch = 1;
        }

        if (strcmp(actual_owner, check_params[i].required_owner) != 0) {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                     "владелец %s (требуется %s), ", actual_owner, check_params[i].required_owner);
            mismatch = 1;
        }

        if (strcmp(actual_group, check_params[i].required_group) != 0) {
            snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                     "группа %s (требуется %s), ", actual_group, check_params[i].required_group);
            mismatch = 1;
        }

        if (mismatch) {
            // Убираем последнюю запятую и пробел
            size_t len = strlen(msg);
            if (len >= 2) msg[len - 2] = '\0';

            snprintf(error_list[error_count].message, sizeof(error_list[error_count].message),
                     "%s: %s", file, msg);
            error_list[error_count].file = file;
            error_count++;
        }
    }

    if (error_count == 0) {
        printf("АКТИВНО\n");
    } else {
        printf("НЕАКТИВНО (Проблемы: %d из %d файлов)\n", error_count, total);
        for (int i = 0; i < error_count; i++) {
            printf("    - %s\n", error_list[i].message);
        }
    }
}

static void check_system_commands_lock(void) {
    struct {
        const char *name;
        int required_mode;
    } commands[] = {
        { "df",      0750 },
        { "chattr",  0750 },
        { "arp",     0750 },
        { "ip",      0750 },
        { "busybox", 0750 }
    };

    const char *search_dirs[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"
    };

    struct {
        char path[256];
        char message[256];
    } errors[10];  // до 10 ошибок
    int error_count = 0;
    int found_files = 0;

    for (int i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
        char found_path[256] = "";
        for (int j = 0; j < sizeof(search_dirs)/sizeof(search_dirs[0]); j++) {
            snprintf(found_path, sizeof(found_path), "%s/%s", search_dirs[j], commands[i].name);
            if (access(found_path, F_OK) == 0) {
                break;
            }
            found_path[0] = '\0'; // not found yet
        }

        if (found_path[0] == '\0') {
            snprintf(errors[error_count].message, sizeof(errors[error_count].message),
                     "%s: не найден", commands[i].name);
            error_count++;
            continue;
        }

        found_files++;

        struct stat sb;
        if (stat(found_path, &sb) != 0) {
            snprintf(errors[error_count].message, sizeof(errors[error_count].message),
                     "%s: невозможно получить stat()", found_path);
            error_count++;
            continue;
        }

        int actual_mode = sb.st_mode & 0777;
        if (actual_mode != commands[i].required_mode) {
            snprintf(errors[error_count].message, sizeof(errors[error_count].message),
                     "%s: права %o (требуется %o)",
                     found_path, actual_mode, commands[i].required_mode);
            error_count++;
        }
    }

    if (found_files == 0) {
        printf("ФАЙЛЫ НЕ НАЙДЕНЫ\n");
    } else if (error_count == 0) {
        printf("АКТИВНО (Все %d файлов с требуемыми правами)\n", found_files);
    } else {
        printf("НЕАКТИВНО (%d ошибок из %d файлов)\n", error_count, found_files);
        for (int i = 0; i < error_count; i++) {
            printf("    - %s\n", errors[i].message);
        }
    }
}

static void check_docker_isolation(void) {
    const char *script_path = "/usr/share/docker.io/contrib/parsec/docker-isolation";
    FILE *fp;

    if (access(script_path, F_OK) != 0) {
        printf("Скрипт docker-isolation не установлен\n");
        return;
    }

    fp = popen(script_path, "r");
    if (!fp) {
        printf("ОШИБКА при запуске docker-isolation\n");
        return;
    }

    char buf[128];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strncmp(buf, "on", 2) == 0) {
            printf("АКТИВНО\n");
        } else {
            printf("НЕАКТИВНО\n");
        }
    } else {
        printf("НЕАКТИВНО\n");
    }

    pclose(fp);
}

static void check_ulimits_control(void) {
    const char *file = "/etc/security/limits.conf";
    FILE *fp = fopen(file, "r");
    if (!fp) {
        printf("НЕ УДАЛОСЬ ОТКРЫТЬ limits.conf\n");
        return;
    }

    char line[512];
    int after_end_marker = 0;
    int active_lines_found = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "# End of file")) {
            after_end_marker = 1;
            continue;
        }

        if (after_end_marker && line[0] != '#' && strspn(line, " \t\r\n") != strlen(line)) {
            active_lines_found = 1;
            break;
        }
    }

    fclose(fp);

    if (active_lines_found) {
        printf("АКТИВНО\n");
    } else {
        printf("НЕАКТИВНО\n");
    }
}

static void check_noautonet_control(void) {
    const char *filepath = "/etc/xdg/autostart/nm-applet.desktop";
    struct stat sb;
    if (stat(filepath, &sb) != 0) {
        printf("НЕАКТИВНО (файл не найден)\n");
        return;
    }

    int mode = sb.st_mode & 0777;
    if (mode == 0) {
        printf("АКТИВНО\n");
    } else {
        printf("НЕАКТИВНО\n");
    }
}

static void check_rtc_local_time(void) {
    FILE *fp = popen("timedatectl", "r");
    if (!fp) {
        printf("ОШИБКА при запуске timedatectl\n");
        return;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "RTC in local TZ: yes")) {
            found = 1;
            break;
        }
    }

    pclose(fp);

    if (found) {
        printf("НЕАКТИВНО\n");
    } else {
        printf("АКТИВНО\n");
    }
}

static void check_sysrq_lock(void) {
    FILE *fp = fopen("/proc/sys/kernel/sysrq", "r");
    if (!fp) {
        printf("НЕАКТИВНО (файл недоступен)\n");
        return;
    }

    char buf[16];
    if (fgets(buf, sizeof(buf), fp)) {
        int value = atoi(buf);
        if (value == 0) {
            printf("АКТИВНО\n");
        } else {
            printf("НЕАКТИВНО\n");
        }
    } else {
        printf("НЕАКТИВНО\n");
    }

    fclose(fp);
}

void search_files_with_silev(void) {
    static const char *excluded_dirs[] = {
        "/proc", "/sys", "/dev", "/run", "/snap", "/tmp", "/mnt", "/media"
    };
    static const int excluded_dirs_count = sizeof(excluded_dirs) / sizeof(excluded_dirs[0]);

    // Вложенная рекурсивная функция для обхода каталогов
    void walk(const char *path) {
        struct stat sb;
        if (lstat(path, &sb) == -1) {
            return;
        }

        if (S_ISDIR(sb.st_mode)) {
            for (int i = 0; i < excluded_dirs_count; i++) {
                size_t len = strlen(excluded_dirs[i]);
                if (strncmp(path, excluded_dirs[i], len) == 0 &&
                    (path[len] == '/' || path[len] == '\0')) {
                    return;
                }
            }

            DIR *dir = opendir(path);
            if (dir == NULL) {
                return;
            }

            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                    continue;

                char full_path[4096];
                if (strcmp(path, "/") == 0) {
                    snprintf(full_path, sizeof(full_path), "/%s", entry->d_name);
                } else {
                    snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
                }

                walk(full_path);
            }

            closedir(dir);
        } else if (S_ISREG(sb.st_mode)) {
            if ((sb.st_mode & S_IXUSR) || (sb.st_mode & S_IXGRP) || (sb.st_mode & S_IXOTH)) {
                PDPL_T *label = pdp_get_path(path);
                if (label == NULL) return;

                char *label_text = pdpl_get_text(label, PDPL_FMT_TXT);
                if (label_text != NULL) {
                    if (strstr(label_text, "silev") != NULL) {
                        printf("   - %s\n", path);
                    }
                    free(label_text);
                }
                free(label);
            }
        }
    }

    walk("/");
    pdp_release();
}

int main(void) {
    int level = parsec_astramode();
    if (level < 0) return fprintf(stderr, "Ошибка: не удалось получить уровень защищенности ОС\n"), 1;

    // Уровень защищенности ОС
    // astra-modeswitch getname
    printf("0. Уровень защищенности ОС: ");
    const char *levels[] = {"0 - Базовый (Орел)", "1 - Усиленный (Воронеж)", "2 - Максимальный (Смоленск)"};
    printf("%s\n", (level >= 0 && level <= 2) ? levels[level] : "Неизвестный уровень");

    if (!parsec_enabled()) return printf("   Система PARSEC: НЕАКТИВНО\n"), 0;
    printf("   Система PARSEC: АКТИВНО\n\n");

    FILE *file = fopen("/sys/module/parsec/parameters/max_ilev", "r");
    if (!file) return fprintf(stderr, "Не удалось открыть файл max_ilev\n"), 1;

    int max_ilev_file = 0;
    if (fscanf(file, "%d", &max_ilev_file) != 1) return fclose(file), fprintf(stderr, "Ошибка чтения max_ilev\n"), 1;
    fclose(file);

    // Мандатный контроль целостности
    // astra-mic-control
    printf("1. Мандатный контроль целостности (МКЦ): %s\n", max_ilev_file ? "АКТИВНО" : "НЕАКТИВНО");
    printf("   Максимальный уровень целостности: %d\n", pdp_get_max_ilev());

    // astra-ilev1-control
    printf("   Первый уровень целостности для сетевых служб: ");
    int exim_status = check_exim4_ilev1();
    printf("%s\n", exim_status == 1 ? "АКТИВНО" : (exim_status == 0 ? "НЕАКТИВНО" : "ОШИБКА"));

    // astra-strictmode-control
    int strict_mode = parsec_strict_mode();
    printf("   Расширенный режим МКЦ: %s\n", strict_mode == 1 ? "АКТИВНО" : (strict_mode == 0 ? "НЕАКТИВНО" : "ОШИБКА"));

    // set-fs-ilev status -v
    if (!max_ilev_file) {
        printf("   Защита файловой системы: ПРОПУСК\n");
        return 0;
    }

    if (read_config() != 0) return fprintf(stderr, "Failed to read config\n"), 1;

    for (int i = 0; i < entries_count; ++i)
        if (!entries[i].exc) process_path(entries[i].path);

    if (!errors_found) printf("   Защита файловой системы: ПОЛНАЯ\n");

    // Мандатное управление доступом
    // astra-mac-control
    printf("\n2. Мандатное управление доступом (МРД): %s\n", parsec_mac_enabled() ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Замкнутая программная среда
    // astra-digsig-control
    int digsig_status = check_digsig_elf_mode_status();
    printf("3. Замкнутая программная среда (ЗПС): ");
    printf("%s\n", digsig_status ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Очистка освобождаемой внешней памяти
    // astra-secdel-control
    SecdelStatus secdel = check_secdel_status();
    printf("4. Очистка освобождаемой внешней памяти: ");
    switch (secdel) {
        case SECDEL_ACCESS_DENIED:
            printf("ОТКАЗАНО В ДОСТУПЕ\n");
            break;
        case SECDEL_INACTIVE:
            printf("НЕАКТИВНО\n");
            break;
        case SECDEL_SIGNATURE:
            printf("СИГНАТУРА\n");
            break;
        case SECDEL_RANDOM:
            printf("СЛУЧАЙНО\n");
            break;
    }

    // Очистка разделов подкачки
    // astra-swapwiper-control
    int swap_wiper = check_swap_wiper();
    printf("\n5. Очистка разделов подкачки: ");
    if (swap_wiper < 0)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("%s\n", swap_wiper ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Межсетевой экран ufw
    // astra-ufw-control
    int ufw = check_ufw_status();
    printf("6. Межсетевой экран ufw: ");
    if (ufw < 0)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("%s\n", ufw ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Монтирование съемных носителей
    // astra-mount-lock
    int removable = check_removable_mounting();
    printf("7. Монтирование съемных носителей: ");
    if (removable < 0)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("%s\n", removable ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Правила PARSEC-аудита процессов и файлов
    // astra-audit-control
    int audit = check_parsec_audit_rules();
    printf("8. Правила PARSEC-аудита процессов и файлов: ");
    if (audit < 0)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("%s\n", audit ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // AstraMode apache2 и MacEnable cups
    // astra-mode-apps
    int apcups = check_apache_cups_controls();
    printf("9. AstraMode apache2 и MacEnable cups: ");
    printf("%s\n", apcups ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Работа Overlay
    // astra-overlay
    int overlay = check_overlay_root();
    printf("10. Работа Overlay: ");
    printf("%s\n", overlay ? "АКТИВНО\n" : "НЕАКТИВНО\n");

    // Защита ядра LKRG
    // astra-lkrg-control
    int lkrg = check_lkrg_status();
    printf("11. Защита ядра LKRG: ");
    if (lkrg == 1)
        printf("АКТИВНО\n");
    else if (lkrg == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("МОДУЛЬ LKRG НЕ УСТАНОВЛЕН\n");

    // Запрет вывода меню загрузчика
    // astra-nobootmenu-control
    int nobootmenu = check_grub_menu_hidden();
    printf("\n12. Запрет вывода меню загрузчика: ");
    if (nobootmenu == 1) {
        printf("АКТИВНО\n");
    } else if (nobootmenu == 0) {
        printf("НЕАКТИВНО\n");
    } else {
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    }

    // Запрет трассировки ptrace
    // astra-ptrace-lock
    printf("\n13. Запрет трассировки ptrace: ");
    int ptrace_lock = check_ptrace_lock();
    if (ptrace_lock == 0)
        printf("НЕАКТИВНО\n");
    else if (ptrace_lock == -1)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("АКТИВНО\n");

    // Запрос пароля для sudo
    // astra-sudo-control
    printf("\n14. Запрос пароля для sudo: ");
    int sudo_pw = check_sudo_password();
    if (sudo_pw == 0)
        printf("НЕАКТИВНО\n");
    else if (sudo_pw == -1)
        printf("ОТКАЗАНО В ДОСТУПЕ\n");
    else
        printf("АКТИВНО\n");

    // Запрет sumac
    // astra-sumac-lock
    char errors[10][256];
    int error_count = 0;

    int sumac_status = check_sumac(errors, &error_count);

    printf("\n15. Запрет sumac: ");
    if (sumac_status == 0) {
        printf("АКТИВНО (Все файлы соответствуют требованиям)\n");
    } else if (sumac_status == 2) {
        printf("ФАЙЛЫ НЕ НАЙДЕНЫ\n");
    } else {
        printf("НЕАКТИВНО (Проблемы: %d)\n", error_count);
        for (int i = 0; i < error_count; i++) {
            printf("    - %s\n", errors[i]);
        }
    }

    // SSH для root
    // astra-rootloginssh-control
    int ssh_root = check_ssh_root_login();
    printf("\n16. SSH для root: ");
    if (ssh_root == 1)
        printf("АКТИВНО\n");
    else if (ssh_root == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("ОТКАЗАНО В ДОСТУПЕ\n");

    // Блокировка выключения
    // astra-shutdown-lock
    int shutdown_lock = check_shutdown_lock();
    printf("\n17. Блокировка выключения: ");
    if (shutdown_lock == 1)
        printf("АКТИВНО\n");
    else if (shutdown_lock == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("ОТКАЗАНО В ДОСТУПЕ\n");

    // Запрос пароля при форматировании
    // astra-format-lock
    int format_lock = check_format_password_request();
    printf("\n18. Запрос пароля при форматировании: ");
    if (format_lock == 1)
        printf("АКТИВНО\n");
    else if (format_lock == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("ОТКАЗАНО В ДОСТУПЕ\n");

    // Автоматический вход в графическую среду
    // astra-autologin-control
    int autologin = check_autologin();
    printf("\n19. Автоматический вход в графическую среду: ");
    if (autologin == 1)
        printf("АКТИВНО\n");
    else if (autologin == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("ОТКАЗАНО В ДОСТУПЕ\n");

    // Запрет установки бита исполнения
    // astra-nochmodx-lock
    int nochmodx_status = check_nochmodx();
    printf("\n20. Запрет установки бита исполнения: ");
    if (nochmodx_status == 1)
        printf("АКТИВНО\n");
    else if (nochmodx_status == 0)
        printf("НЕАКТИВНО\n");
    else
        printf("ОТКАЗАНО В ДОСТУПЕ\n");

    // Запрет исполнения скриптов для пользователей (Блокировка интерпретаторов)
    // astra-interpreters-lock
    printf("\n21. Запрет исполнения скриптов для пользователей (Блокировка интерпретаторов): ");
    check_security_interp();

    // Блокировка bash
    // astra-bash-lock
    printf("\n22. Блокировка bash: ");
    check_bash_lock();

    // Запрет исполнения макросов для пользователей
    // astra-macros-lock
    printf("\n23. Запрет исполнения макросов для пользователей: ");
    check_macro_execution_lock();

    // Блокировка консоли
    // astra-console-lock
    printf("\n24. Блокировка консоли: ");
    check_console_lock();

    // Блокировка системных команд
    // astra-commands-lock
    printf("\n25. Блокировка системных команд: ");
    check_system_commands_lock();

    // Изоляция Docker
    // astra-docker-isolation
    printf("\n26. Изоляция Docker: ");
    check_docker_isolation();

    // Системные ограничения ulimits
    // astra-ulimits-control
    printf("\n27. Системные ограничения ulimits: ");
    check_ulimits_control();

    // Запрет автонастройки сети
    // astra-noautonet-control
    printf("\n28. Запрет автонастройки сети: ");
    check_noautonet_control();

    // Местное время для системных часов
    printf("\n29. Местное время для системных часов: ");
    check_rtc_local_time();

    // Блокировка клавиш SysRq
    // astra-sysrq-lock
    printf("\n30. Блокировка клавиш SysRq: ");
    check_sysrq_lock();

    // Поиск файлов с атрибутом silev (позволяет повысить уровень целостности)
    // /usr/bin/pdp-ls -M </path/to/file>
    printf("\n31. Поиск файлов с атрибутом silev:\n");
    search_files_with_silev();

    return 0;
}