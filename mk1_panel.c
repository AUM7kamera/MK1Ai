#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <ncurses.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "mk1_memory_guard.h"
#include "mk1_path_trust.h"
#include "mk1_tunnel.h"

#define CONFIG_PATH "ai_data/panel-config.json"
#define STATUS_PATH "ai_data/panel-status.txt"
#define LOG_PATH "ai_data/panel.log"
#define TUNNEL_CONTROL_PATH "ai_data/tunnel-control.sock"
#define VALUE_SIZE 512

typedef struct {
    char interface[VALUE_SIZE];
    char mode[16];
    char colab_endpoint[VALUE_SIZE];
    int ram_limit;
    int map_mode;
    int usb_guard_enabled;
    int secure_tunnel_enabled;
    int memory_guard_enabled;
} PanelConfig;

typedef struct {
    char state[32];
    char alert[32];
    double packets_per_second;
    double threat_score;
    double backdoor_score;
    double ram_used_mb;
    double ram_limit_mb;
    double swap_used_mb;
    long long packets_total;
    int isolation_active;
    int dry_run;
    int secure_tunnel_active;
    int memory_guard_active;
} PanelStatus;

static pid_t monitor_pid = -1;
static pid_t dashboard_pid = -1;
static volatile sig_atomic_t close_requested = 0;
static volatile sig_atomic_t isolation_closed = 0;
static char message[256] = "準備完了";
static void set_message(const char *text);

static void handle_shutdown_signal(int signal_number) {
    if (signal_number == SIGTERM) {
        isolation_closed = 1;
        close_requested = 1;
    }
}

static void copy_value(char *destination, size_t capacity, const char *source) {
    if (capacity == 0) return;
    size_t length = strnlen(source, capacity - 1);
    memcpy(destination, source, length);
    destination[length] = '\0';
}

static bool read_json_string(const char *json, const char *key, char *output, size_t capacity) {
    char key_pattern[64];
    snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", key);
    const char *position = strstr(json, key_pattern);
    if (position == NULL) return false;
    position = strchr(position + strlen(key_pattern), ':');
    if (position == NULL) return false;
    while (isspace((unsigned char)*++position)) {}
    if (*position++ != '"') return false;

    size_t used = 0;
    while (*position != '\0' && *position != '"') {
        char value = *position++;
        if (value == '\\') {
            if (*position == '\0') return false;
            value = *position++;
            if (value != '\\' && value != '"') return false;
        }
        if ((unsigned char)value < 0x20 || used + 1 >= capacity) return false;
        output[used++] = value;
    }
    if (*position != '"') return false;
    output[used] = '\0';
    return true;
}

static bool read_json_integer_range(
    const char *json,
    const char *key,
    int minimum,
    int maximum,
    int *output
) {
    char key_pattern[64];
    snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", key);
    const char *position = strstr(json, key_pattern);
    if (position == NULL) return false;
    position = strchr(position + strlen(key_pattern), ':');
    if (position == NULL) return false;
    while (isspace((unsigned char)*++position)) {}
    char *end = NULL;
    errno = 0;
    long value = strtol(position, &end, 10);
    if (errno != 0 || end == position || value < minimum || value > maximum) return false;
    *output = (int)value;
    return true;
}

static bool read_json_integer(const char *json, const char *key, int *output) {
    return read_json_integer_range(json, key, 1, 1048576, output);
}

static void load_config_file(const char *path, PanelConfig *config) {
    FILE *file = fopen(path, "r");
    if (file == NULL) return;
    char content[4096];
    size_t length = fread(content, 1, sizeof(content) - 1, file);
    content[length] = '\0';
    fclose(file);
    read_json_string(content, "interface", config->interface, sizeof(config->interface));
    read_json_string(content, "mode", config->mode, sizeof(config->mode));
    read_json_string(content, "colab_endpoint", config->colab_endpoint, sizeof(config->colab_endpoint));
    read_json_integer(content, "ram_limit", &config->ram_limit);
    read_json_integer_range(content, "map_mode", 0, 2, &config->map_mode);
    read_json_integer_range(content, "usb_guard_enabled", 0, 1, &config->usb_guard_enabled);
    read_json_integer_range(content, "secure_tunnel_enabled", 0, 1, &config->secure_tunnel_enabled);
    read_json_integer_range(content, "memory_guard_enabled", 0, 1, &config->memory_guard_enabled);
}

static void load_config(PanelConfig *config) {
    copy_value(config->interface, sizeof(config->interface), "eth0");
    copy_value(config->mode, sizeof(config->mode), "normal");
    config->colab_endpoint[0] = '\0';
    config->ram_limit = 500;
    config->map_mode = 0;
    config->usb_guard_enabled = 0;
    config->secure_tunnel_enabled = 1;
    config->memory_guard_enabled = 0;
    load_config_file("ai_data/config.json", config);
    load_config_file(CONFIG_PATH, config);
}

static bool valid_interface(const char *value) {
    if (value[0] == '\0' || strlen(value) >= VALUE_SIZE) return false;
    for (const unsigned char *character = (const unsigned char *)value; *character; character++) {
        if (!isalnum(*character) && strchr("_.:@-", *character) == NULL) return false;
    }
    return true;
}

static bool valid_wireguard_interface(const char *value) {
    size_t length = strlen(value);
    if (length == 0 || length > 15) return false;
    for (const unsigned char *character = (const unsigned char *)value; *character; character++) {
        if (!((*character >= 'a' && *character <= 'z')
              || (*character >= 'A' && *character <= 'Z')
              || (*character >= '0' && *character <= '9')
              || strchr("_.-", *character) != NULL)) return false;
    }
    return true;
}

static bool run_wireguard_link_state(const char *interface, bool enabled) {
    pid_t child = fork();
    if (child < 0) {
        snprintf(message, sizeof(message), "WireGuard制御を起動できません: %s", strerror(errno));
        return false;
    }
    if (child == 0) {
        execlp("sudo", "sudo", "-n", "/usr/local/sbin/mk1-wg-link",
               interface, enabled ? "up" : "down", (char *)NULL);
        _exit(127);
    }
    int status = -1;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        snprintf(message, sizeof(message), "WireGuard制御の結果を取得できません: %s", strerror(errno));
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        set_message("WireGuard操作に失敗しました。sudo権限とインターフェース名を確認してください");
        return false;
    }
    return true;
}

static bool request_local_guard_state(char guard, bool enabled) {
    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return false;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(TUNNEL_CONTROL_PATH) >= sizeof(address.sun_path)) {
        close(descriptor);
        return false;
    }
    copy_value(address.sun_path, sizeof(address.sun_path), TUNNEL_CONTROL_PATH);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(descriptor);
        return false;
    }
    char command[2] = {guard, enabled ? '1' : '0'};
    ssize_t sent;
    do {
        sent = send(descriptor, command, sizeof(command), 0);
    } while (sent < 0 && errno == EINTR);
    char response = '\0';
    ssize_t received = -1;
    if (sent == (ssize_t)sizeof(command)) {
        do {
            received = recv(descriptor, &response, 1, 0);
        } while (received < 0 && errno == EINTR);
    }
    close(descriptor);
    return received == 1 && response == '1';
}

static bool request_secure_transport_state(bool enabled) {
    return request_local_guard_state('T', enabled);
}

static bool request_memory_guard_state(bool enabled) {
    return request_local_guard_state('M', enabled);
}

static bool valid_endpoint(const char *value) {
    if (value[0] == '\0') return true;
    if (strncmp(value, "https://", 8) != 0 || strlen(value) >= VALUE_SIZE) return false;
    for (const unsigned char *character = (const unsigned char *)value; *character; character++) {
        if (isspace(*character) || iscntrl(*character) || *character == '"' || *character == '\\') return false;
    }
    return true;
}

static void write_json_string(FILE *file, const char *value) {
    fputc('"', file);
    for (const unsigned char *character = (const unsigned char *)value; *character; character++) {
        if (*character == '"' || *character == '\\') fputc('\\', file);
        fputc(*character, file);
    }
    fputc('"', file);
}

static bool save_config(const PanelConfig *config) {
    char temporary_path[] = "ai_data/.panel-config.XXXXXX";
    int descriptor = mkstemp(temporary_path);
    if (descriptor < 0) {
        snprintf(message, sizeof(message), "設定ファイルを作成できません: %s", strerror(errno));
        return false;
    }
    if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
        snprintf(message, sizeof(message), "設定ファイルの権限を設定できません: %s", strerror(errno));
        close(descriptor);
        unlink(temporary_path);
        return false;
    }
    FILE *file = fdopen(descriptor, "w");
    if (file == NULL) {
        snprintf(message, sizeof(message), "設定ファイルを開けません: %s", strerror(errno));
        close(descriptor);
        unlink(temporary_path);
        return false;
    }
    fputs("{\n  \"interface\": ", file);
    write_json_string(file, config->interface);
    fprintf(file, ",\n  \"ram_limit\": %d,\n  \"map_mode\": %d,\n  \"usb_guard_enabled\": %d,\n  \"secure_tunnel_enabled\": %d,\n  \"memory_guard_enabled\": %d,\n  \"mode\": ",
            config->ram_limit, config->map_mode, config->usb_guard_enabled,
            config->secure_tunnel_enabled, config->memory_guard_enabled);
    write_json_string(file, config->mode);
    fputs(",\n  \"colab_endpoint\": ", file);
    write_json_string(file, config->colab_endpoint);
    fputs("\n}\n", file);
    int save_error = 0;
    if (fflush(file) != 0) save_error = errno;
    if (save_error == 0 && fsync(descriptor) != 0) save_error = errno;
    if (fclose(file) != 0 && save_error == 0) save_error = errno;
    bool saved = save_error == 0;
    if (!saved || rename(temporary_path, CONFIG_PATH) != 0) {
        int saved_errno = save_error != 0 ? save_error : errno;
        unlink(temporary_path);
        snprintf(message, sizeof(message), "設定を保存できません: %s", strerror(saved_errno));
        return false;
    }
    copy_value(message, sizeof(message), "設定を安全に保存しました");
    return true;
}

static bool read_status(PanelStatus *status) {
    memset(status, 0, sizeof(*status));
    copy_value(status->state, sizeof(status->state), "STOPPED");
    copy_value(status->alert, sizeof(status->alert), "NONE");
    FILE *file = fopen(STATUS_PATH, "r");
    if (file == NULL) return false;

    char line[128];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "state=%31s", status->state) == 1) continue;
        if (sscanf(line, "alert=%31s", status->alert) == 1) continue;
        if (sscanf(line, "packets_per_second=%lf", &status->packets_per_second) == 1) continue;
        if (sscanf(line, "packets_total=%lld", &status->packets_total) == 1) continue;
        if (sscanf(line, "threat_score=%lf", &status->threat_score) == 1) continue;
        if (sscanf(line, "backdoor_score=%lf", &status->backdoor_score) == 1) continue;
        if (sscanf(line, "ram_used_mb=%lf", &status->ram_used_mb) == 1) continue;
        if (sscanf(line, "ram_limit_mb=%lf", &status->ram_limit_mb) == 1) continue;
        if (sscanf(line, "swap_used_mb=%lf", &status->swap_used_mb) == 1) continue;
        if (sscanf(line, "isolation_active=%d", &status->isolation_active) == 1) continue;
        if (sscanf(line, "secure_tunnel_active=%d", &status->secure_tunnel_active) == 1) continue;
        if (sscanf(line, "memory_guard_active=%d", &status->memory_guard_active) == 1) continue;
        sscanf(line, "dry_run=%d", &status->dry_run);
    }
    fclose(file);
    return true;
}

static void set_message(const char *text) {
    copy_value(message, sizeof(message), text);
}

static void stop_monitor(void) {
    if (monitor_pid <= 0) {
        set_message("監視プロセスは起動していません");
        return;
    }
    kill(-monitor_pid, SIGINT);
    for (int attempt = 0; attempt < 50; attempt++) {
        int status;
        pid_t result = waitpid(monitor_pid, &status, WNOHANG);
        if (result == monitor_pid || (result < 0 && errno == ECHILD)) {
            monitor_pid = -1;
            set_message("監視を停止しました");
            return;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    kill(-monitor_pid, SIGTERM);
    waitpid(monitor_pid, NULL, 0);
    monitor_pid = -1;
    set_message("監視を停止しました (SIGTERM)");
}

static void stop_dashboard(void) {
    if (dashboard_pid <= 0) {
        set_message("リモート画面サーバーは起動していません");
        return;
    }
    kill(-dashboard_pid, SIGTERM);
    for (int attempt = 0; attempt < 50; attempt++) {
        int status;
        pid_t result = waitpid(dashboard_pid, &status, WNOHANG);
        if (result == dashboard_pid || (result < 0 && errno == ECHILD)) {
            dashboard_pid = -1;
            set_message("HTTPSリモート画面サーバーを停止しました");
            return;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    kill(-dashboard_pid, SIGKILL);
    waitpid(dashboard_pid, NULL, 0);
    dashboard_pid = -1;
    set_message("HTTPSサーバーが応答せず、停止シグナルを送りました");
}

static void start_dashboard(void) {
    if (dashboard_pid > 0) {
        set_message("HTTPSリモート画面サーバーはすでに起動しています");
        return;
    }
    const char *python = getenv("MK1_PYTHON_BIN");
    if (python == NULL || python[0] == '\0') python = "python3";
    pid_t child = fork();
    if (child < 0) {
        snprintf(message, sizeof(message), "HTTPSサーバーを起動できません: %s", strerror(errno));
        return;
    }
    if (child == 0) {
        setpgid(0, 0);
        FILE *log_file = fopen("ai_data/remote-dashboard.log", "a");
        if (log_file != NULL) {
            dup2(fileno(log_file), STDOUT_FILENO);
            dup2(fileno(log_file), STDERR_FILENO);
            fclose(log_file);
        }
        execl(python, python, "mk1_remote_dashboard.py", (char *)NULL);
        _exit(127);
    }
    setpgid(child, child);
    dashboard_pid = child;
    set_message("閲覧専用HTTPSサーバーを起動中。URL/設定と認証手順: ai_data/remote-dashboard.log");
}

static bool confirm_monitor_start(bool full_isolation) {
    erase();
    attron(A_BOLD);
    mvprintw(2, 2, "起動前のセキュリティ警告");
    attroff(A_BOLD);
    if (full_isolation) {
        mvprintw(4, 2, "脅威検知時はOSのファイアウォール/ネットワーク機能で全通信の遮断を試みます。");
        mvprintw(5, 2, "誤検知でもWi-Fi/有線/VPN/SSH/リモート操作が切断される場合があります。");
        mvprintw(6, 2, "隔離後の遠隔復旧はできません。端末の前でのみ復旧してください。");
        mvprintw(7, 2, "管理者認証を行い、--no-dry-runで監視を開始します。");
    } else {
        mvprintw(4, 2, "Dry-Runでは検知しても通信を遮断しません。実際の防御強度は低下します。");
        mvprintw(5, 2, "本番通信の保護やエアギャップが有効になったとはみなさないでください。");
    }
    mvprintw(9, 2, "続行しますか? [y]=続行 / その他のキー=キャンセル");
    refresh();
    nodelay(stdscr, FALSE);
    int answer = getch();
    nodelay(stdscr, TRUE);
    return answer == 'y' || answer == 'Y';
}

static bool authorize_admin(void) {
    def_prog_mode();
    endwin();
    pid_t child = fork();
    if (child == 0) {
        execlp("sudo", "sudo", "-v", (char *)NULL);
        _exit(127);
    }
    int status = -1;
    if (child > 0) {
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    reset_prog_mode();
    refresh();
    if (child < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        set_message("管理者認証に失敗しました。実遮断監視は開始していません");
        return false;
    }
    return true;
}

static bool confirm_wireguard_change(const char *interface, bool enabled) {
    erase();
    attron(A_BOLD);
    mvprintw(2, 2, "WireGuard制御の確認");
    attroff(A_BOLD);
    mvprintw(4, 2, "%s のリンクを %s にします。",
             interface, enabled ? "有効" : "無効");
    mvprintw(5, 2, "無効化すると、このWireGuard経由の通信が切断されます。");
    mvprintw(6, 2, "有効化は既存リンクのip link upのみで、wg-quick設定は起動しません。");
    mvprintw(7, 2, "カーネルのWireGuard秘密鍵をユーザー空間から消去する操作ではありません。");
    mvprintw(9, 2, "続行しますか? [y]=続行 / その他のキー=キャンセル");
    refresh();
    nodelay(stdscr, FALSE);
    int answer = getch();
    nodelay(stdscr, TRUE);
    return answer == 'y' || answer == 'Y';
}

static void toggle_secure_tunnel(PanelConfig *config) {
    const char *interface = getenv("MK1_WIREGUARD_INTERFACE");
    if (interface == NULL || interface[0] == '\0') interface = "wg0";
    if (!valid_wireguard_interface(interface)) {
        set_message("MK1_WIREGUARD_INTERFACEが不正です。英数字・_.-の15文字以内で指定してください");
        return;
    }

    bool enabled = !config->secure_tunnel_enabled;
    int previous_state = config->secure_tunnel_enabled;
    if (!confirm_wireguard_change(interface, enabled)) {
        set_message("WireGuard操作をキャンセルしました");
        return;
    }
    if (!authorize_admin()) return;

    bool transport_acknowledged = monitor_pid <= 0;
    bool local_key_wiped = true;
    if (!enabled) {
        local_key_wiped = mk1_secure_key_wipe() == 0;
        if (monitor_pid > 0) {
            transport_acknowledged = request_secure_transport_state(false);
        }
        config->secure_tunnel_enabled = 0;
        if (!save_config(config)) {
            config->secure_tunnel_enabled = previous_state;
            return;
        }
        if (!local_key_wiped) {
            set_message("C暗号鍵mutex取得に失敗。リンク遮断を続行しますが鍵消去を確認できません");
        }
    }
    if (!run_wireguard_link_state(interface, enabled)) {
        char operation_error[sizeof(message)];
        copy_value(operation_error, sizeof(operation_error), message);
        config->secure_tunnel_enabled = previous_state;
        if (!save_config(config)) {
            set_message("WireGuard操作失敗後、設定の復元にも失敗しました");
        } else {
            copy_value(message, sizeof(message), operation_error);
        }
        if (!enabled && monitor_pid > 0 && previous_state) {
            bool restored = request_secure_transport_state(true);
            if (restored && mk1_tunnel_set_enabled(true) != 0) {
                (void)mk1_secure_key_wipe();
                (void)request_secure_transport_state(false);
            }
        }
        return;
    }
    if (enabled) {
        config->secure_tunnel_enabled = 1;
        if (!save_config(config)) {
            config->secure_tunnel_enabled = previous_state;
            if (!run_wireguard_link_state(interface, false)) {
                set_message("設定保存失敗。WireGuardの復旧遮断にも失敗しました");
            } else {
                set_message("設定保存失敗のためWireGuardを再び無効化しました");
            }
            return;
        }
    }
    if (enabled && monitor_pid > 0) {
        transport_acknowledged = request_secure_transport_state(true);
    }
    if (enabled && transport_acknowledged && monitor_pid > 0) {
        if (mk1_tunnel_set_enabled(true) != 0) {
            (void)mk1_secure_key_wipe();
            transport_acknowledged = false;
            (void)request_secure_transport_state(false);
        }
    }
    if (enabled && !transport_acknowledged && mk1_secure_key_wipe() != 0) {
        set_message("経路検証失敗に加えC暗号鍵mutex取得にも失敗しました");
        return;
    }
    if (enabled && monitor_pid > 0 && !transport_acknowledged) {
        set_message("リンクはupですがPQC経路検証に失敗。暗号送信ゲートは遮断のままです");
    } else if (!enabled && monitor_pid > 0 && !transport_acknowledged) {
        set_message("WireGuard停止済み。鍵消去IPC未確認のため設定監視による反映を待っています");
    } else if (!enabled) {
        set_message("WireGuardリンクを停止し、稼働中のPQC鍵を消去・送信拒否しました");
    } else if (monitor_pid > 0) {
        set_message("WireGuardリンクとフルトンネル経路を検証し、PQC送信を許可しました");
    } else {
        set_message("WireGuardリンクをupにしました。監視起動時にフルトンネル経路を検証します");
    }
    if (!enabled && !local_key_wiped) {
        set_message("C暗号鍵mutex取得に失敗。リンクは遮断しましたが鍵消去を確認できません");
    }
}

static void toggle_memory_guard(PanelConfig *config) {
    bool enabled = !config->memory_guard_enabled;
    int previous_state = config->memory_guard_enabled;
    int guard_error = mk1_memory_guard_set_enabled(enabled);
    if (guard_error != 0) {
        snprintf(message, sizeof(message), "メモリ保護を変更できません: %s",
                 strerror(guard_error));
        return;
    }
    config->memory_guard_enabled = enabled ? 1 : 0;
    if (!save_config(config)) {
        config->memory_guard_enabled = previous_state;
        (void)mk1_memory_guard_set_enabled(previous_state != 0);
        return;
    }
    bool monitor_acknowledged = monitor_pid <= 0
        || request_memory_guard_state(enabled);
    if (!monitor_acknowledged) {
        set_message("パネル側は切替済み。監視プロセスへの同期IPC未確認、設定監視へフォールバックします");
    } else {
        set_message(enabled
            ? "メモリ保護を有効化。ダンプ抑止・ptrace制限・TracerPid監視を開始しました"
            : "メモリ保護を無効化しました");
    }
}

static bool start_monitor(const PanelConfig *config, bool full_isolation) {
    if (monitor_pid > 0) {
        set_message("監視はすでに起動しています");
        return false;
    }
    if (full_isolation && strcmp(config->mode, "RSI") == 0) {
        set_message("RSIモードはDry-Run固定です。通常モードに変更してください");
        return false;
    }
    if (!confirm_monitor_start(full_isolation)) {
        set_message("監視の起動をキャンセルしました");
        return false;
    }
    if (full_isolation) {
        const char *privileged_python = getenv("MK1_PYTHON_BIN");
        if (privileged_python == NULL || privileged_python[0] == '\0') privileged_python = "python3";
        bool python_ok = strchr(privileged_python, '/') == NULL
            || mk1_path_chain_is_root_trusted(privileged_python);
        if (!python_ok || !mk1_path_chain_is_root_trusted("airgap_ai_defender.py")) {
            set_message("実遮断はroot権限で実行されます。スクリプトとPythonをrootが所有し、group/otherが書き込めない場所に配置してください");
            return false;
        }
    }
    if (full_isolation && !authorize_admin()) return false;
    if (!save_config(config)) return false;
    pid_t child = fork();
    if (child < 0) {
        snprintf(message, sizeof(message), "監視を起動できません: %s", strerror(errno));
        return false;
    }
    if (child == 0) {
        setpgid(0, 0);
        const char *python = getenv("MK1_PYTHON_BIN");
        if (python == NULL || python[0] == '\0') python = "python3";
        char parent_pid[32];
        snprintf(parent_pid, sizeof(parent_pid), "%ld", (long)getppid());
        FILE *log_file = fopen(LOG_PATH, "a");
        if (log_file != NULL) {
            dup2(fileno(log_file), STDOUT_FILENO);
            dup2(fileno(log_file), STDERR_FILENO);
            fclose(log_file);
        }
        if (full_isolation) {
            execlp("sudo", "sudo", "-n", python, "airgap_ai_defender.py",
                   "--config", "ai_data/config.json",
                   "--panel-config", CONFIG_PATH,
                   "--panel-parent-pid", parent_pid,
                   "--no-dry-run", "--compact-log", (char *)NULL);
        } else {
            execl(python, python, "airgap_ai_defender.py",
                  "--config", "ai_data/config.json",
                  "--panel-config", CONFIG_PATH,
                  "--compact-log", (char *)NULL);
        }
        _exit(127);
    }
    setpgid(child, child);
    monitor_pid = child;
    set_message(full_isolation
        ? "実遮断監視を起動しました。検知時はTUIを閉じ、遠隔復旧経路を残しません"
        : "Dry-Run監視を起動しました。詳細ログ: ai_data/panel.log");
    return true;
}

static bool run_local_validation(const PanelConfig *config) {
    if (monitor_pid > 0) {
        set_message("検証は監視停止中に実行してください");
        return false;
    }
    if (!save_config(config)) return false;
    pid_t child = fork();
    if (child < 0) {
        snprintf(message, sizeof(message), "検証を起動できません: %s", strerror(errno));
        return false;
    }
    if (child == 0) {
        const char *python = getenv("MK1_PYTHON_BIN");
        if (python == NULL || python[0] == '\0') python = "python3";
        FILE *log_file = fopen(LOG_PATH, "a");
        if (log_file != NULL) {
            dup2(fileno(log_file), STDOUT_FILENO);
            dup2(fileno(log_file), STDERR_FILENO);
            fclose(log_file);
        }
        execl(python, python, "airgap_ai_defender.py",
               "--config", "ai_data/config.json",
               "--panel-config", CONFIG_PATH,
               "--mode", "normal", "--validation-only", "--no-drive-fetch", "--max-samples", "2",
               "--drive-id", "", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            snprintf(message, sizeof(message), "検証結果を取得できません: %s", strerror(errno));
            return false;
        }
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        set_message("ローカル検証に成功しました。ai_data/panel.log を確認してください");
        return true;
    }
    snprintf(message, sizeof(message), "検証に失敗しました。ai_data/panel.log を確認してください (status=%d)", status);
    return false;
}

static void edit_config(PanelConfig *config) {
    PanelConfig original = *config;
    bool valid = true;
    char input[VALUE_SIZE];
    echo();
    curs_set(1);
    nodelay(stdscr, FALSE);

    mvprintw(12, 2, "監視NIC [%s]: ", config->interface);
    clrtoeol();
    getnstr(input, (int)sizeof(input) - 1);
    if (input[0] != '\0') {
        if (valid_interface(input)) copy_value(config->interface, sizeof(config->interface), input);
        else {
            set_message("NIC名に使用できない文字が含まれています");
            valid = false;
        }
    }

    mvprintw(13, 2, "RAM基準MB [%d]: ", config->ram_limit);
    clrtoeol();
    getnstr(input, (int)sizeof(input) - 1);
    if (input[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long value = strtol(input, &end, 10);
        if (errno == 0 && *end == '\0' && value >= 1 && value <= 1048576)
            config->ram_limit = (int)value;
        else {
            set_message("RAM基準は1～1048576の整数を入力してください");
            valid = false;
        }
    }

    mvprintw(14, 2, "モード [normal/RSI] [%s]: ", config->mode);
    clrtoeol();
    getnstr(input, (int)sizeof(input) - 1);
    if (input[0] != '\0') {
        if (strcmp(input, "normal") == 0 || strcmp(input, "RSI") == 0)
            copy_value(config->mode, sizeof(config->mode), input);
        else {
            set_message("モードはnormalまたはRSIを指定してください");
            valid = false;
        }
    }

    mvprintw(15, 2, "Colab HTTPS URL (空欄で変更なし) [%s]: ",
             config->colab_endpoint[0] ? config->colab_endpoint : "未設定");
    clrtoeol();
    getnstr(input, (int)sizeof(input) - 1);
    if (input[0] != '\0') {
        if (valid_endpoint(input))
            copy_value(config->colab_endpoint, sizeof(config->colab_endpoint), input);
        else {
            set_message("Colab URLはhttps://で始まる安全なURLにしてください");
            valid = false;
        }
    }

    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);
    if (!valid || !save_config(config)) *config = original;
}

static void show_interfaces(void) {
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        snprintf(message, sizeof(message), "NIC一覧を取得できません: %s", strerror(errno));
        return;
    }
    pid_t child = fork();
    if (child < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        snprintf(message, sizeof(message), "NIC一覧を起動できません: %s", strerror(errno));
        return;
    }
    if (child == 0) {
        close(descriptors[0]);
        dup2(descriptors[1], STDOUT_FILENO);
        close(descriptors[1]);
        execlp("ip", "ip", "-br", "link", (char *)NULL);
        _exit(127);
    }
    close(descriptors[1]);
    char output[2048];
    ssize_t length = read(descriptors[0], output, sizeof(output) - 1);
    close(descriptors[0]);
    waitpid(child, NULL, 0);
    if (length <= 0) {
        set_message("ip -br link を実行できません。iproute2を確認してください");
        return;
    }
    output[length] = '\0';
    erase();
    mvprintw(2, 2, "ネットワークインターフェース (ip -br link)");
    int row = 4;
    char *line = strtok(output, "\n");
    while (line != NULL && row < LINES - 3) {
        mvprintw(row++, 4, "%s", line);
        line = strtok(NULL, "\n");
    }
    mvprintw(LINES - 2, 2, "キーを押すと操作パネルへ戻ります");
    refresh();
    nodelay(stdscr, FALSE);
    getch();
    nodelay(stdscr, TRUE);
    set_message("監視NIC名を設定から選択してください");
}

static void draw_panel(const PanelConfig *config) {
    if (
        mk1_memory_guard_is_enabled()
        && mk1_memory_guard_check_tracer() != 0
    ) {
        (void)kill(getpid(), SIGKILL);
        return;
    }
    PanelStatus status;
    bool status_available = read_status(&status);
    if (monitor_pid > 0 && !isolation_closed) {
        int child_status;
        pid_t result = waitpid(monitor_pid, &child_status, WNOHANG);
        if (result == monitor_pid || (result < 0 && errno == ECHILD)) {
            monitor_pid = -1;
            set_message("監視プロセスが終了しました。ai_data/panel.log を確認してください");
        }
        if (dashboard_pid > 0) {
            int child_status;
            pid_t result = waitpid(dashboard_pid, &child_status, WNOHANG);
            if (result == dashboard_pid || (result < 0 && errno == ECHILD)) {
                dashboard_pid = -1;
                set_message("HTTPSサーバーが停止しました。ai_data/remote-dashboard.log を確認してください");
            }
        }
    }

    erase();
    attron(A_BOLD);
    mvprintw(1, 2, "MK1Ai C操作パネル");
    attroff(A_BOLD);
    mvprintw(3, 2, "監視NIC: %-16s モード: %-6s RAM基準: %d MB",
             config->interface, config->mode, config->ram_limit);
    mvprintw(4, 2, "Colab HTTPS: %s",
             config->colab_endpoint[0] ? config->colab_endpoint : "未設定");
    const char *map_mode = config->map_mode == 1 ? "Chrome WebSocket" :
        config->map_mode == 2 ? "Local offline cache" : "OFF";
    mvprintw(5, 2, "地図表示: %-20s %s",
             map_mode, config->map_mode == 1 ? "ws://127.0.0.1:9001/map" : "");
    mvprintw(6, 2, "監視状態: %s", monitor_pid > 0 ? "起動中" : "停止中");
    mvprintw(7, 2, "処理速度: %.2f packets/sec   累計: %lld",
             status_available ? status.packets_per_second : 0.0,
             status_available ? status.packets_total : 0LL);
    mvprintw(8, 2, "脅威スコア: %.3f   バックドアリスク: %.3f",
             status_available ? status.threat_score : 0.0,
             status_available ? status.backdoor_score : 0.0);
    if (status_available && strcmp(status.alert, "NONE") != 0) attron(A_BOLD);
    mvprintw(9, 2, "アラート: %s%s",
             status_available ? status.alert : "状態待ち",
             status_available && status.isolation_active ? " (隔離発動)" : "");
    if (status_available && strcmp(status.alert, "NONE") != 0) attroff(A_BOLD);
    const char *monitor_mode = !status_available ? "状態未取得" :
        status.dry_run ? "Dry-Run (遮断なし)" : "実遮断 (管理者権限)";
    mvprintw(10, 2, "実行モード: %s", monitor_mode);
    mvprintw(11, 2, "RAM: %.1f / %.0f MB   退避swap: %.1f MB",
             status_available ? status.ram_used_mb : 0.0,
             status_available ? status.ram_limit_mb : 0.0,
             status_available ? status.swap_used_mb : 0.0);
    mvprintw(12, 2, "USB隔離設定: %s (実遮断モード時のみ有効)",
             config->usb_guard_enabled ? "有効" : "無効");
    mvprintw(13, 2, "Encrypted Sandbox Tunnel: %s / PQC送信ゲート: %s",
             config->secure_tunnel_enabled ? "ON" : "OFF",
             !status_available ? "状態未取得" :
             status.secure_tunnel_active ? "許可" : "遮断");
    mvprintw(14, 2, "メモリ保護: %s / 監視プロセス: %s",
             config->memory_guard_enabled ? "ON" : "OFF",
             !status_available ? "状態未取得" :
             status.memory_guard_active ? "有効" : "無効");

    mvprintw(16, 2, "[1] Dry-Run [2] 停止 [3] 実遮断 [4] 設定 [m] 地図 [u] USB [e] WG [a] メモリ");
    mvprintw(17, 2, "[5] NIC一覧 [6] ローカル検証 [7] HTTPS閲覧開始 [8] 停止");
    mvprintw(18, 2, "リモート閲覧: %s", dashboard_pid > 0 ? "HTTPSサーバー稼働中 (閲覧専用)" : "停止中");
    mvprintw(19, 2, "%.*s", COLS > 4 ? COLS - 4 : 0, message);
    mvprintw(LINES - 2, 2, "状態: %s%s", status_available ? status.state : "ステータス未出力",
             isolation_closed ? " / 隔離後ローカル復旧が必要" : "");
    refresh();
}

int main(void) {
    const char *launcher = getenv("MK1_PANEL_LAUNCHER");
    if (launcher == NULL || strcmp(launcher, "explicit-command") != 0) {
        fprintf(stderr, "このパネルは明示的なGUI起動コマンドからのみ起動できます。\n");
        return 1;
    }
    setlocale(LC_ALL, "");
    if (mkdir("ai_data", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0 && errno != EEXIST) {
        fprintf(stderr, "ai_dataを作成できません: %s\n", strerror(errno));
        return 1;
    }
    PanelConfig config;
    load_config(&config);
    if (config.memory_guard_enabled) {
        int guard_error = mk1_memory_guard_set_enabled(true);
        if (guard_error != 0) {
            fprintf(stderr, "設定済みメモリ保護を有効化できません: %s\n",
                    strerror(guard_error));
            return 1;
        }
    }

    if (initscr() == NULL) {
        fprintf(stderr, "端末画面を初期化できません。対話端末で起動してください。\n");
        return 1;
    }
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);
    struct sigaction shutdown_action = {0};
    shutdown_action.sa_handler = handle_shutdown_signal;
    sigemptyset(&shutdown_action.sa_mask);
    if (sigaction(SIGTERM, &shutdown_action, NULL) != 0) {
        endwin();
        fprintf(stderr, "SIGTERMハンドラーを設定できません: %s\n", strerror(errno));
        return 1;
    }
    struct sigaction pipe_action = {0};
    pipe_action.sa_handler = SIG_IGN;
    sigemptyset(&pipe_action.sa_mask);
    if (sigaction(SIGPIPE, &pipe_action, NULL) != 0) {
        endwin();
        fprintf(stderr, "SIGPIPEハンドラーを設定できません: %s\n", strerror(errno));
        return 1;
    }

    bool running = true;
    while (running && !close_requested) {
        draw_panel(&config);
        int key = getch();
        switch (key) {
            case 'm': {
                int previous_mode = config.map_mode;
                config.map_mode = (config.map_mode + 1) % 3;
                if (!save_config(&config)) {
                    config.map_mode = previous_mode;
                } else {
                    set_message("地図表示モードを保存しました。監視中は自動で反映されます");
                }
                break;
            }
            case 'u': {
                int previous_state = config.usb_guard_enabled;
                config.usb_guard_enabled = !config.usb_guard_enabled;
                if (!save_config(&config)) {
                    config.usb_guard_enabled = previous_state;
                } else {
                    set_message(config.usb_guard_enabled
                        ? "USB隔離を有効にしました。実遮断監視の起動時のみ適用"
                        : "USB隔離を無効にしました");
                }
                break;
            }
            case 'e':
            case 'E':
                toggle_secure_tunnel(&config);
                break;
            case 'a':
            case 'A':
                toggle_memory_guard(&config);
                break;
            case '1':
                start_monitor(&config, false);
                break;
            case '2':
                stop_monitor();
                break;
            case '3':
                start_monitor(&config, true);
                break;
            case '4':
                edit_config(&config);
                break;
            case '5':
                show_interfaces();
                break;
            case '6':
                run_local_validation(&config);
                break;
            case '7':
                start_dashboard();
                break;
            case '8':
                stop_dashboard();
                break;
            case 'q':
            case 'Q':
                running = false;
                break;
            case KEY_RESIZE:
                clear();
                break;
            default:
                break;
        }
        napms(250);
    }
    bool key_wiped = mk1_secure_key_wipe() == 0;
    (void)request_secure_transport_state(false);
    if (!isolation_closed) stop_monitor();
    stop_dashboard();
    endwin();
    if (!key_wiped) {
        fprintf(stderr, "C暗号鍵の破棄に失敗しました。\n");
        return 1;
    }
    return 0;
}
