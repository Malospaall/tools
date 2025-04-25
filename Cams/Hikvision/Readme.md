# hikvision_web_snapshots.py

Режим snapshot

```bash
python hikvision_web_snapshots.py snapshot -f cameras.txt
  -h, --help
  -f, --file Файл с комбинациями в формате ip,port,login,password

```

Режим web_brute

```bash
python hikvision_web_snapshots.py web_brute -c creds.txt -i hosts.txt

options:
  -h, --help
  -c, --credentials Файл с учетными данными в формате login:password
  -i, --hosts Файл с хостами в формате ip:port
```

# CVE

- CVE-2013-4975
- CVE-2013-4976
- CVE-2017-7921
- CVE-2021-36260