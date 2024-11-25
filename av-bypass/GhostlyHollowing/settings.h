#define GHOSTING
#define DROPPER

#ifdef _WIN64
#define IS32BIT false
#else
#define IS32BIT true
#endif

#ifdef DROPPER
#define REAL_PASSWORD_NAME "password_0"
#define REAL_PATH "/super_secret_path"
#define SERVER "192.168.100.1"
#define PORT 443

#define REQUESTS_BEFORE 5
#define REQUESTS_AFTER 5

#endif