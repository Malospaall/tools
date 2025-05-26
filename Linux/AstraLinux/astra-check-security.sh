#!/bin/bash

echo "=== Проверка механизмов защиты Astra Linux ==="

# Уровень защищенности ОС
# astra-modeswitch getname
echo -n "0. Уровень защищенности ОС: "
if [ -r /etc/astra_license ]; then
    grep "^DESCRIPTION=" /etc/astra_license 2>/dev/null | cut -d= -f2- || echo "НЕ ОПРЕДЕЛЕНО"
else
    echo "ОТКАЗАНО В ДОСТУПЕ"
fi

echo

# Мандатный контроль целостности
# astra-mic-control
echo -n "1. Мандатный контроль целостности (МКЦ): "
if [ ! -r /sys/module/parsec/parameters/max_ilev ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q 63 /sys/module/parsec/parameters/max_ilev 2>/dev/null; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo -n "   Максимальный уровень целостности: "
if [ ! -r /proc/cmdline ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    parsec_ilev=$(grep -o "parsec.max_ilev=[0-9]*" /proc/cmdline | cut -d= -f2)
    if [ -n "$parsec_ilev" ]; then
        echo "$parsec_ilev"
    else
        echo "не найден"
    fi
fi

# astra-ilev1-control
echo -n "   Первый уровень целостности для сетевых служб: "
if systemctl cat exim4.service 2>/dev/null | grep -q "/etc/systemd/system/exim4.service.d/ilev1.conf"; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

# astra-strictmode-control
echo -n "   Расширенный режим МКЦ: "
if [ ! -r /proc/cmdline ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q "parsec.strict_mode=" /proc/cmdline; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

# set-fs-ilev status -v
# pdpl-file <file>
echo "   Защита файловой системы (занимает некоторое время):"

if ! command -v /usr/sbin/pdpl-file &> /dev/null; then
    echo "   ОШИБКА: Команда pdpl-file не найдена"
    exit 1
fi

if [ ! -r /etc/parsec/fs-ilev.conf ]; then
    echo "   ОТКАЗАНО В ДОСТУПЕ к /etc/parsec/fs-ilev.conf"
    exit 1
fi

max_ilev=$(grep -o "parsec.max_ilev=[0-9]*" /proc/cmdline 2>/dev/null | cut -d= -f2)
[ -z "$max_ilev" ] && max_ilev=63

is_excluded() {
    local path="$1"
    if [[ "$path" == "/usr/share" || "$path" == "/usr/share/"* ]]; then
        return 0
    fi

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue

        if [[ "$line" =~ ^exc[[:space:]]+([^[:space:]]+) ]]; then
            local pattern="${BASH_REMATCH[1]}"
            pattern="${pattern//\*/.*}"
            if [[ "$path" =~ $pattern ]]; then
                return 0
            fi
        fi
    done < /etc/parsec/fs-ilev.conf
    return 1
}

get_required_level() {
    local path="$1"
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue

        if [[ "$line" =~ ^[^[:space:]]+[[:space:]]+([^[:space:]]+) ]]; then
            local config_path="${BASH_REMATCH[1]}"
            if [[ "$path" == "$config_path" || "$path" == "$config_path"/* ]]; then
                if [[ "$line" =~ ^(max|high)[[:space:]] ]]; then
                    echo "Высокий"
                    return
                elif [[ "$line" =~ ^(min|low)[[:space:]] ]]; then
                    echo "Низкий"
                    return
                elif [[ "$line" =~ ^([0-9]+)[[:space:]] ]]; then
                    local ilev="${BASH_REMATCH[1]}"
                    if [ "$ilev" -ge "$max_ilev" ]; then
                        echo "Высокий"
                    else
                        echo "Низкий"
                    fi
                    return
                fi
            fi
        fi
    done < /etc/parsec/fs-ilev.conf
    echo "Не определен"
}

found_issues=0
while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
    [[ "$line" =~ ^exc[[:space:]] ]] && continue

    if [[ "$line" =~ ^[^[:space:]]+[[:space:]]+([^[:space:]]+) ]]; then
        path="${BASH_REMATCH[1]}"

        [ ! -e "$path" ] && continue

        required_level=$(get_required_level "$path")
        [ "$required_level" == "Не определен" ] && continue

        while IFS= read -r -d '' file; do
            if ! is_excluded "$file"; then
                current_level=$(/usr/sbin/pdpl-file "$file" 2>/dev/null | awk -F: '{print $2}')
                if [ "$current_level" != "$required_level" ]; then
                    echo "      запрошен: $required_level    установлен: $current_level    $file"
                    ((found_issues++))
                fi
            fi
        done < <(find "$path" -type f -print0 2>/dev/null)

        if ! is_excluded "$path"; then
            current_level=$(/usr/sbin/pdpl-file "$path" 2>/dev/null | awk -F: '{print $2}')
            if [ "$current_level" != "$required_level" ]; then
                echo "      запрошен: $required_level    установлен: $current_level    $path"
                ((found_issues++))
            fi
        fi
    fi
done < /etc/parsec/fs-ilev.conf

if [ "$found_issues" -eq 0 ]; then
    echo "      Все проверенные файлы имеют корректный уровень целостности"
fi

echo

# Мандатное управление доступом
# astra-mac-control
echo -n "2. Мандатное управление доступом (МРД): "
if [ ! -r /parsecfs/mac_enabled ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q 1 /parsecfs/mac_enabled 2>/dev/null; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Замкнутая программная среда
# astra-digsig-control
echo -n "3. Замкнутая программная среда (ЗПС): "
if [ ! -r /etc/digsig/digsig_initramfs.conf ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q "DIGSIG_ELF_MODE=1" /etc/digsig/digsig_initramfs.conf; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Очистка освобождаемой внешней памяти
# astra-secdel-control
echo -n "4. Очистка освобождаемой внешней памяти: "
if [ ! -r /etc/fstab ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    found_line=$(grep -E "secdel|secdelrnd" /etc/fstab)
    if [ -z "$found_line" ]; then
        echo "НЕАКТИВНО"
    else
        value=$(echo "$found_line" | grep -oE "secdel(rnd)?=[0-9]+" | cut -d= -f2)
        if [ -n "$value" ]; then
            if echo "$found_line" | grep -q "secdelrnd"; then
                echo "СЛУЧАЙНО (Количество: $value)"
            else
                echo "СИГНАТУРА (Количество: $value)"
            fi
        else
		    if echo "$found_line" | grep -q "secdelrnd"; then
                echo "СЛУЧАЙНО"
		    else
			    echo "СИГНАТУРА"
			fi
        fi
    fi
fi

echo

# Очистка разделов подкачки
# astra-swapwiper-control
echo -n "5. Очистка разделов подкачки: "
if [ ! -r /etc/parsec/swap_wiper.conf ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    if grep -q "^ENABLED=Y" /etc/parsec/swap_wiper.conf; then
        ignored=$(grep "^IGNORE=" /etc/parsec/swap_wiper.conf | cut -d= -f2 | tr -d '"')
        if [ -n "$ignored" ]; then
            echo "АКТИВНО (Игнорируются разделы: $ignored)"
        else
            echo "АКТИВНО (Нет игнорируемых разделов)"
        fi
    else
        echo "НЕАКТИВНО"
    fi
fi

echo

# Межсетевой экран ufw
# astra-ufw-control
echo -n "6. Межсетевой экран ufw: "
if cat /etc/ufw/ufw.conf | grep -q 'ENABLED=no'; then
    echo "НЕАКТИВНО"
else
    echo "АКТИВНО"
fi

echo

# Монтирование съемных носителей
# astra-mount-lock
echo -n "7. Монтирование съемных носителей: "
if [ ! -r /lib/udev/rules.d/91-group-floppy.rules ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q 'GROUP="astra-admin"' /lib/udev/rules.d/91-group-floppy.rules; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Правила PARSEC-аудита процессов и файлов
# astra-audit-control
echo -n "8. Правила PARSEC-аудита процессов и файлов: "

if [ ! -f /parsecfs/disable-all-audit ] || [ ! -f /parsecfs/disable-denied-audit ] || [ ! -f /parsecfs/disable-non-mac-audit ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    if [ "$(cat /parsecfs/disable-all-audit)" = "0" ] && \
       [ "$(cat /parsecfs/disable-denied-audit)" = "0" ] && \
       [ "$(cat /parsecfs/disable-non-mac-audit)" = "0" ]; then
        echo "АКТИВНО"
    else
        echo "НЕАКТИВНО"
    fi
fi

echo

# AstraMode apache2 и MacEnable cups
# astra-mode-apps
echo -n "9. AstraMode apache2 и MacEnable cups: "

if [ -f /etc/apache2/apache2.conf ] && grep -q "^AstraMode on" /etc/apache2/apache2.conf 2>/dev/null ||
   [ -f /etc/cups/cupsd.conf ] && grep -q "^MacEnable on" /etc/cups/cupsd.conf 2>/dev/null; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Работа Overlay
# astra-overlay
echo -n "10. Работа Overlay: "
if [ "`findmnt -lnf -o FSTYPE / 2> /dev/null`" = "overlay" ]; then
	echo "АКТИВНО";
else
	echo "НЕАКТИВНО";
fi

echo

# Защита ядра LKRG
# astra-lkrg-control
echo -n "11. Защита ядра LKRG: "

if /sbin/sysctl -a 2>/dev/null | grep -q '^lkrg\.'; then
    echo "АКТИВНО"
else
    if modinfo lkrg >/dev/null 2>&1; then
        echo "НЕАКТИВНО"
    else
        echo "МОДУЛЬ LKRG НЕ УСТАНОВЛЕН"
    fi
fi

echo

# Запрет вывода меню загрузчика
# astra-nobootmenu-control
echo -n "12. Запрет вывода меню загрузчика: "
if [ ! -f /etc/default/grub ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    # Получаем значения параметров
    grub_timeout=$(grep "^GRUB_TIMEOUT=" /etc/default/grub | cut -d= -f2 | tr -d '"')
    grub_hidden_timeout=$(grep "^GRUB_HIDDEN_TIMEOUT=" /etc/default/grub | cut -d= -f2 | tr -d '"')

    # Проверяем, что оба параметра равны 0
    if [ "$grub_timeout" = "0 #1" ] && [ "$grub_hidden_timeout" = "0" ]; then
        echo "АКТИВНО"
    else
        echo "НЕАКТИВНО"
    fi
fi

echo

# Запрет трассировки ptrace
# astra-ptrace-lock
echo -n "13. Запрет трассировки ptrace: "
if grep -q "^kernel.yama.ptrace_scope=0" /etc/sysctl.d/999-astra.conf 2>/dev/null; then
    echo "НЕАКТИВНО"
elif [ $? -eq 2 ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    echo "АКТИВНО"
fi

echo

# Запрос пароля для sudo
# astra-sudo-control
echo -n "14. Запрос пароля для sudo: "
if grep -q "^%astra-admin.*NOPASSWD:" /etc/sudoers 2>/dev/null; then
    echo "НЕАКТИВНО"
elif [ $? -eq 2 ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    echo "АКТИВНО"
fi

echo

# Запрет sumac
# astra-sumac-lock
echo -n "15. Запрет sumac: "

declare -A check_params=(
    ["/usr/bin/sumac"]="0:root:root"
    ["/usr/lib/x86_64-linux-gnu/fly-run/libsumacrunner.so"]="0:root:root"
)

errors=()
found_files=0

for file in "${!check_params[@]}"; do
    IFS=':' read -r required_perm required_owner required_group <<< "${check_params[$file]}"

    if [ ! -e "$file" ]; then
        errors+=("$file: отсутствует")
        continue
    fi

    ((found_files++))
    current_perm=$(stat -c "%a" "$file" 2>/dev/null)
    current_owner=$(stat -c "%U" "$file" 2>/dev/null)
    current_group=$(stat -c "%G" "$file" 2>/dev/null)

    error_msg=""
    if [ "$current_perm" != "$required_perm" ]; then
        error_msg+="права $current_perm (требуется $required_perm), "
    fi
    if [ "$current_owner" != "$required_owner" ]; then
        error_msg+="владелец $current_owner (требуется $required_owner), "
    fi
    if [ "$current_group" != "$required_group" ]; then
        error_msg+="группа $current_group (требуется $required_group), "
    fi

    if [ -n "$error_msg" ]; then
        errors+=("$file: ${error_msg%, }")
    fi
done

if [ ${#errors[@]} -eq 0 ] && [ $found_files -gt 0 ]; then
    echo "АКТИВНО (Все $found_files файлов соответствуют требованиям)"
elif [ $found_files -eq 0 ]; then
    echo "ФАЙЛЫ НЕ НАЙДЕНЫ"
else
    echo "НЕАКТИВНО (Проблемы: ${#errors[@]} из $found_files файлов)"
    for error in "${errors[@]}"; do
        echo "    - $error"
    done
fi

echo

# SSH для root
# astra-rootloginssh-control
echo -n "16. SSH для root: "
if cat /etc/ssh/sshd_config | grep -q '^PermitRootLogin no'; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Блокировка выключения
# astra-shutdown-lock
echo -n "17. Блокировка выключения: "
if grep -q "^AllowShutdown=Root$" /etc/X11/fly-dm/fly-dmrc; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Запрос пароля при форматировании
# astra-format-lock
echo -n "18. Запрос пароля при форматировании: "

policy_file="/usr/share/polkit-1/actions/ru.rusbitech.fly.formatdevicehelper.policy"

if [ ! -f "$policy_file" ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
elif grep -q "<allow_active>\\s*yes\\s*</allow_active>" "$policy_file"; then
    echo "НЕАКТИВНО"
else
    echo "АКТИВНО"
fi

echo

# Автоматический вход в графическую среду
# astra-autologin-control
echo -n "19. Автоматический вход в графическую среду: "

if grep -v "^#" /etc/X11/fly-dm/fly-dmrc | grep '^\s*AutoLoginEnable\s*=\s*true\s*$' 2>&1 > /dev/null; then
	echo "АКТИВНО"
else
	echo "НЕАКТИВНО"
fi

echo

# Запрет установки бита исполнения
# astra-nochmodx-lock
echo -n "20. Запрет установки бита исполнения: " &&
if [ ! -f /etc/parsec/nochmodx ] || [ ! -f /parsecfs/nochmodx ]; then
    echo "ОТКАЗАНО В ДОСТУПЕ"
else
    if [ "$(cat /etc/parsec/nochmodx)" = "1" ] && \
       [ "$(cat /parsecfs/nochmodx)" = "1" ]; then
        echo "АКТИВНО"
    else
        echo "НЕАКТИВНО"
    fi
fi

echo

# Запрет исполнения скриптов для пользователей (Блокировка интерпретаторов)
# astra-interpreters-lock
echo -n "21. Запрет исполнения скриптов для пользователей (Блокировка интерпретаторов): "
## Директории для поиска интерпретаторов
search_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
interp_patterns=("perl*" "python*" "ruby*" "irb*" "dash*" "ksh*" "zsh*" "csh*" "tcl*" "tk*" "expect*" "lua*" "php[0123456789]*" "node*" "qemu-*-static*" "ptksh*" "cpan*" "blender**" "vim.gtk**")

# Возможно добавить в список: "gdb" "tshark*" "wireshark*" "psql*" "sqlite3*" "docker*" "lxc*" "lxd*" "wine*"

## Директории для поиска загрузчиков
loader_dirs=("/lib" "/lib64")
loader_patterns=("ld-*.so*")

## Переменные для хранения результатов
found_files=()
missing_attr_files=()

## Функция проверки атрибутов
check_attributes() {
    local file="$1"
    if ! getfattr -m - "$file" 2>/dev/null | grep -q "security.interp$"; then
        missing_attr_files+=("$file")
    fi
}

## Поиск интерпретаторов
for dir in "${search_dirs[@]}"; do
    for pattern in "${interp_patterns[@]}"; do
        while IFS= read -r -d $'\0' file; do
            found_files+=("$file")
            check_attributes "$file"
        done < <(find -L "$dir" -type f -executable -name "$pattern" -print0 2>/dev/null)
    done
done

## Поиск загрузчиков
for dir in "${loader_dirs[@]}"; do
    for pattern in "${loader_patterns[@]}"; do
        while IFS= read -r -d $'\0' file; do
            found_files+=("$file")
            check_attributes "$file"
        done < <(find -L "$dir" -maxdepth 10 -path "*/live/*" -prune -o -name "$pattern" -type f -print0 2>/dev/null)
    done
done

## Проверка Python-модулей
python_versions=("python3" "python3.10" "python3.11" "python3.12" "python3.9")
for pyver in "${python_versions[@]}"; do
    if command -v "$pyver" >/dev/null 2>&1; then
        site_dir=$($pyver -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" 2>/dev/null)
        if [ -d "$site_dir" ]; then
            while IFS= read -r -d $'\0' file; do
                if [[ -x "$file" ]]; then
                    found_files+=("$file")
                    check_attributes "$file"
                fi
            done < <(find "$site_dir" -type f -name "*.so" -o -name "*.py" -print0 2>/dev/null)
        fi
    fi
done

## Формирование вывода
if [ ${#found_files[@]} -eq 0 ]; then
    echo "НЕ НАЙДЕНО ФАЙЛОВ ДЛЯ ПРОВЕРКИ"
elif [ ${#missing_attr_files[@]} -eq 0 ]; then
    echo "АКТИВНО (Все ${#found_files[@]} файлов имеют security.interp)"
else
    echo "НЕАКТИВНО (Отсутствует security.interp в ${#missing_attr_files[@]} файлах из ${#found_files[@]})"
    for bad_file in "${missing_attr_files[@]}"; do
        echo "    - $bad_file"
    done
fi

echo

# Блокировка bash
# astra-bash-lock
echo -n "22. Блокировка bash: "

## Директории для поиска интерпретаторов
search_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
interp_patterns=("bash*")

## Переменные для хранения результатов
found_files=()
missing_attr_files=()

## Функция проверки атрибутов
check_attributes() {
    local file="$1"
    if ! getfattr -m - "$file" 2>/dev/null | grep -q "security.interp$"; then
        missing_attr_files+=("$file")
    fi
}

## Поиск интерпретаторов
for dir in "${search_dirs[@]}"; do
    for pattern in "${interp_patterns[@]}"; do
        while IFS= read -r -d $'\0' file; do
            found_files+=("$file")
            check_attributes "$file"
        done < <(find -L "$dir" -type f -executable -name "$pattern" -print0 2>/dev/null)
    done
done

## Формирование вывода
if [ ${#found_files[@]} -eq 0 ]; then
    echo "НЕ НАЙДЕНО ФАЙЛОВ ДЛЯ ПРОВЕРКИ"
elif [ ${#missing_attr_files[@]} -eq 0 ]; then
    echo "АКТИВНО (Все ${#found_files[@]} файлов имеют security.interp)"
else
    echo "НЕАКТИВНО (Отсутствует security.interp в ${#missing_attr_files[@]} файлах из ${#found_files[@]})"
    for bad_file in "${missing_attr_files[@]}"; do
        echo "    - $bad_file"
    done
fi

echo

# Запрет исполнения макросов для пользователей
# astra-macros-lock
echo -n "23. Запрет исполнения макросов для пользователей: "

## Проверяем наличие unopkg в стандартных путях
unopkg_paths=(
    "/usr/bin/unopkg"
    "/usr/lib/libreoffice/program/unopkg"
)

found_config=0
total_checks=0

for unopkg in "${unopkg_paths[@]}"; do
    if [ -x "$unopkg" ]; then
        ((total_checks++))
        if /bin/sh "$unopkg" list --shared 2>/dev/null | grep -q "Identifier: config_level_macros"; then
            ((found_config++))
        fi
    fi
done

## Формируем результат
if [ $total_checks -eq 0 ]; then
    echo "LibreOffice не установлен или unopkg не найден"
elif [ $found_config -eq $total_checks ]; then
    echo "АКТИВНО"
elif [ $found_config -gt 0 ]; then
    echo "ЧАСТИЧНО (найдено в $found_config из $total_checks проверок)"
else
    echo "НЕАКТИВНО"
fi

echo

# Блокировка консоли
# astra-console-lock
echo -n "24. Блокировка консоли: "

## Проверяемые файлы, требуемые права и владельцы
declare -A check_params=(
    ["/usr/bin/fly-run"]="750:root:astra-console"
    ["/dev/pts"]="750:root:astra-console"
    ["/dev/ptmx"]="672:root:astra-console"
)

errors=()

## Проверяем каждый файл
for file in "${!check_params[@]}"; do
    if [ ! -e "$file" ]; then
        errors+=("$file: отсутствует")
        continue
    fi

    ## Разбираем параметры проверки
    IFS=':' read -r required_mode required_owner required_group <<< "${check_params[$file]}"

    ## Получаем текущие значения
    current_mode=$(stat -c %a "$file" 2>/dev/null)
    current_owner=$(stat -c %U "$file" 2>/dev/null)
    current_group=$(stat -c %G "$file" 2>/dev/null)

    ## Проверяем соответствие
    error_msg=""
    if [ "$current_mode" != "$required_mode" ]; then
        error_msg+="права $current_mode (требуется $required_mode), "
    fi
    if [ "$current_owner" != "$required_owner" ]; then
        error_msg+="владелец $current_owner (требуется $required_owner), "
    fi
    if [ "$current_group" != "$required_group" ]; then
        error_msg+="группа $current_group (требуется $required_group), "
    fi

    ## Если есть ошибки, добавляем в список
    if [ -n "$error_msg" ]; then
        errors+=("$file: ${error_msg%, }")
    fi
done

## Формируем результат
if [ ${#errors[@]} -eq 0 ]; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО (Проблемы: ${#errors[@]} из ${#check_params[@]} файлов)"
    for error in "${errors[@]}"; do
        echo "    - $error"
    done
fi

echo

# Блокировка системных команд
# astra-commands-lock
echo -n "25. Блокировка системных команд: "

declare -A check_params=(
    ["df"]="750"
    ["chattr"]="750"
    ["arp"]="750"
    ["ip"]="750"
    ["busybox"]="750"
)

search_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")

errors=()
found_files=0

for file in "${!check_params[@]}"; do
    required_perm="${check_params[$file]}"
    file_path=""

    # Поиск файла в системе
    for dir in "${search_dirs[@]}"; do
        if [ -f "$dir/$file" ]; then
            file_path="$dir/$file"
            break
        fi
    done

    if [ -z "$file_path" ]; then
        errors+=("$file: не найден")
        continue
    fi

    ((found_files++))
    current_perm=$(stat -c "%a" "$file_path" 2>/dev/null)

    if [ "$current_perm" != "$required_perm" ]; then
        errors+=("$file_path: права $current_perm (требуется $required_perm)")
    fi
done

if [ ${#errors[@]} -eq 0 ] && [ $found_files -gt 0 ]; then
    echo "АКТИВНО (Все $found_files файлов с требуемыми правами)"
elif [ $found_files -eq 0 ]; then
    echo "ФАЙЛЫ НЕ НАЙДЕНЫ"
else
    echo "НЕАКТИВНО (${#errors[@]} ошибок из $found_files файлов)"
    for error in "${errors[@]}"; do
        echo "    - $error"
    done
fi

echo

# Изоляция Docker
# astra-docker-isolation
echo -n "26. Изоляция Docker: "
if [ ! -f "/usr/share/docker.io/contrib/parsec/docker-isolation" ]; then
    echo "Скрипт docker-isolation не установлен"
elif [ "$(/usr/share/docker.io/contrib/parsec/docker-isolation | head -n1)" = "on" ]; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Системные ограничения ulimits
# astra-ulimits-control
echo -n "27. Системные ограничения ulimits: "
if grep -A20 '# End of file' /etc/security/limits.conf | grep -q '^[^#]'; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Запрет автонастройки сети
# astra-noautonet-control
echo -n "28. Запрет автонастройки сети: "
if [ "$(stat -c %a /etc/xdg/autostart/nm-applet.desktop 2>/dev/null)" = "0" ]; then
    echo "АКТИВНО"
else
    echo "НЕАКТИВНО"
fi

echo

# Местное время для системных часов
echo -n "29. Местное время для системных часов: "
if timedatectl | grep -q 'RTC in local TZ: yes'; then
    echo "НЕАКТИВНО"
else
    echo "АКТИВНО"
fi

echo

# Блокировка клавиш SysRq
# astra-sysrq-lock
echo -n "30. Блокировка клавиш SysRq: " && [ $(cat /proc/sys/kernel/sysrq) -eq 0 ] && echo "АКТИВНО" || echo "НЕАКТИВНО"

echo

# Поиск файлов с атрибутом silev (позволяет повысить уровень целостности)
# /usr/bin/pdp-ls -M </path/to/file>
echo "31. Поиск файлов с атрибутом silev (занимает некоторое время): "
if ! command -v /usr/sbin/pdpl-file &>/dev/null; then
    echo "НЕ НАЙДЕНА КОМАНДА pdpl-file"
    exit 1
fi

SEARCH_PATH="/"
EXCLUDE_PATHS="^/proc|^/sys|^/dev|^/run|^/snap|^/tmp|^/mnt|^/media"

FOUND=0

find "$SEARCH_PATH" -type f -readable -print0 2>/dev/null |
while IFS= read -r -d '' file; do
    if [[ "$file" =~ $EXCLUDE_PATHS ]]; then
        continue
    fi

    output=$(/usr/sbin/pdpl-file "$file" 2>/dev/null)
    if echo "$output" | grep -q 'silev'; then
        echo "      $file: $output"
        FOUND=1
    fi
done

if [ "$FOUND" -eq 0 ]; then
    echo "НЕ ОБНАРУЖЕНО"
fi