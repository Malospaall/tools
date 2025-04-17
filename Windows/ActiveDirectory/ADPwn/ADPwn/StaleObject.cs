using System;
using System.IO;
using System.DirectoryServices;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;

namespace ADPwn
{
    public static class StaleObject
    {
        public static void CheckOutdatedOS(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Stale Object", ConsoleColor.Blue);

            // Устанавливаем цвет
            ConsoleHelper.WriteColoredLine("[*] Outdated OS", ConsoleColor.Yellow);

            try
            {
                // Создание объекта DirectorySearcher для выполнения запроса
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    // Установка фильтра для поиска устаревших ОС
                    Filter =
                        "(&(objectCategory=computer)(|(operatingSystem=Windows Embedded*)(operatingSystem=Windows NT*)(operatingSystem=Windows Server 2000*)" +
                        "(operatingSystem=Windows Server 2003*)(operatingSystem=Windows Server 2008*)(operatingSystem=Windows Server 2012*)(operatingSystem=Windows XP*)" +
                        "(operatingSystem=Windows Vista*)(operatingSystem=Windows 7*)(operatingSystem=Windows 8*)" +
                        "(operatingSystemVersion=10.0 *10240*)(operatingSystemVersion=10.0 *10586*)(operatingSystemVersion=10.0 *14393*)" +
                        "(operatingSystemVersion=10.0 *15063*)(operatingSystemVersion=10.0 *16299*)(operatingSystemVersion=10.0 *17134*)" +
                        "(operatingSystemVersion=10.0 *17763*)(operatingSystemVersion=10.0 *18362*)(operatingSystemVersion=10.0 *18363*)" +
                        "(operatingSystemVersion=10.0 *19041*)(operatingSystemVersion=10.0 *19042*)(operatingSystemVersion=10.0 *19043*)" +
                        "(operatingSystemVersion=10.0 *19044*)(operatingSystemVersion=10.0 *22000*)(operatingSystemVersion=10.0 *22621*)" +
                        "(operatingSystemVersion=8.*)(operatingSystemVersion=9.*)))",
                    // Ограничение свойств, загружаемых в результате
                    PropertiesToLoad = { "sAMAccountName", "operatingSystem", "OperatingSystemVersion" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No computers with outdated OS!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} computer(s) with outdated OS:", ConsoleColor.Green);
                        List<string> outputLines = new List<string>();
                        bool writeToFile = results.Count > 20;

                        StreamWriter file = null;
                        if (writeToFile)
                        {
                            file = new StreamWriter($"{domain}_OutdatedHosts.csv");
                            file.WriteLine("hostName,ip,operatingSystem");
                        }

                        foreach (SearchResult result in results)
                        {
                            string sAMAccountName = result.Properties.Contains("sAMAccountName") &&
                                                    result.Properties["sAMAccountName"].Count > 0
                                ? result.Properties["sAMAccountName"][0].ToString()
                                : null;

                            string operatingSystem = result.Properties.Contains("operatingSystem") &&
                                                     result.Properties["operatingSystem"].Count > 0
                                ? result.Properties["operatingSystem"][0].ToString()
                                : null;

                            string operatingSystemVersion = result.Properties.Contains("operatingSystemVersion") &&
                                                            result.Properties["operatingSystemVersion"].Count > 0
                                ? result.Properties["operatingSystemVersion"][0].ToString()
                                : null;

                            string hostName = $"{sAMAccountName?.TrimEnd('$')}.{domain}";
                            string ip = ConsoleHelper.GetIPAddress(hostName, dc);
                            string outputLine = $"{hostName},{ip},{operatingSystem} {operatingSystemVersion}";

                            if (writeToFile)
                            {
                                file.WriteLine(outputLine);
                            }
                            else
                            {
                                Console.WriteLine($"\t- IP-Address: {ip} / Name: {hostName} / OS: {operatingSystem} {operatingSystemVersion}");
                            }

                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = ip,
                                HostName = hostName,
                                OperatingSystem = operatingSystem + " " + operatingSystemVersion,
                                VulnerabilityName = "Устаревшая ОС",
                                Description =
                                    "ОС больше не поддерживается, так как она уязвима для многих общеизвестных эксплойтов: " +
                                    "Можно перехватить учетные данные администратора, используются слабые протоколы безопасности и т.п.",
                                Recommendations = "Обновить все рабочие станции до более свежей версии",
                                CVSSv2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                Level = "10.0",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                            "https://www.cert.ssi.gouv.fr/information/CERTFR-2005-INF-003/#SECTION00032400000000000000",
                            "https://attack.mitre.org/mitigations/M1051"
                                }
                            };

                            ParseJson.AppendToJsonFile(jsonData);
                        }

                        if (writeToFile)
                        {
                            file.Close();
                            Console.WriteLine($"\t- Data written to file {domain}_OutdatedHosts.csv");
                        }
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Обновление контроллера домена
        public static void CheckUpdateDC(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Domain controller outdated", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    PropertiesToLoad = { "sAMAccountName", "operatingSystem", "OperatingSystemVersion", "lastLogonTimestamp" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No DC!", ConsoleColor.Red);
                    }
                    else
                    {
                        List<string> lists = new List<string>();

                        foreach (SearchResult result in results)
                        {
                            DateTime dcTimestamp = DateTime.FromFileTime(Convert.ToInt64(result.Properties["lastLogonTimestamp"][0]));

                            if (dcTimestamp < DateTime.Now.AddMonths(-6))
                            {
                                lists.Add(result.Properties["sAMAccountName"][0].ToString());
                            }
                        }

                        if (lists.Count == 0)
                        {
                            ConsoleHelper.WriteColoredLine("\t[X] No outdated DC!", ConsoleColor.Red);
                        }
                        else
                        {
                            ConsoleHelper.WriteColoredLine($"\tFound {lists.Count} outdated DC:", ConsoleColor.Green);

                            foreach (string list in lists)
                            {
                                Console.WriteLine(list);
                            }

                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = dc,
                                VulnerabilityName = "Обновление контроллера домена",
                                Description =
                                    "Контроллер домена необходимо регулярно обновлять, поскольку угрозы для AD постоянно меняются. Дата последнего обновления " +
                                    "вычисляется путем получения StatisticsStartTime из [net statistics workstation]. " +
                                    "Если она недоступна, решение PingCastle будет использовать атрибут lastLogonTimestamp, " +
                                    "который обновляется на основе атрибута LastLogon. Обратите внимание, что существует максимальная задержка обновления: 14 дней. " +
                                    "Уязвимые объекты: " + string.Join(", ", lists),
                                Recommendations =
                                    "Частое обновление DC должно быть частью политик AD, поскольку для серверов должно " +
                                    "быть выделено время для перезагрузки и применения исправлений безопасности",
                                CVSSv2 = "AV:N/AC:M/Au:S/C:P/I:P/A:P",
                                Level = "6.0",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                                    "https://attack.mitre.org/mitigations/M1051"
                                }
                            };
                            ParseJson.AppendToJsonFile(jsonData);
                        }
                    }

                    Console.WriteLine();
                }
            }
            catch (ArgumentOutOfRangeException)
            {
                ConsoleHelper.WriteColoredLine("\t[X] Unable to determine latest DC update!\n", ConsoleColor.Red);
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Использование аттрибута PASSWD_NOTREQD
        public static void CheckNoPasswordRequired(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] No Password Required", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {

                    // Установка фильтра для поиска пользователей с флагом PASSWD_NOTREQD
                    Filter =
                        "(&(objectClass=user)(samAccountType=805306368)(!(sAMAccountName=guest))(!(sAMAccountName=гость))(userAccountControl:1.2.840.113556.1.4.803:=32))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No users found to NoPasswordRequired!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} users with PASSWD_NOTREQD:",
                            ConsoleColor.Green);

                        List<string> lists = new List<string>();

                        foreach (SearchResult result in results)
                        {
                            lists.Add(result.Properties["sAMAccountName"][0].ToString());

                            Console.WriteLine("\t- " + result.Properties["sAMAccountName"][0]);
                        }

                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                        {
                            IpAddress = dc,
                            VulnerabilityName = "Аттрибут PASSWD_NOTREQD включен",
                            Description =
                                "Учетная запись может быть установлена без пароля, если в атрибуте 'useraccountcontrol' флаг 'PASSWD_NOTREQD' установлен как 'True'. " +
                                "Это представляет собой высокий риск безопасности, поскольку без пароля учетная запись не имеет какой-либо защиты. Уязвимые пользователи: " +
                                string.Join(", ", lists),
                            Recommendations =
                                "Установить значение 'False' во флаге 'PASSWD_NOTREQD' для всех перечисленных учетных записей",
                            CVSSv2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            Level = "7.5",
                            CVE = new String[] { },
                            Links = new String[]
                            {
                                "https://docs.microsoft.com/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties",
                                "https://www.ssi.gouv.fr/uploads/IMG/pdf/NP_ActiveDirectory_NoteTech.pdf#subsection.3.6",
                                "https://attack.mitre.org/mitigations/M1015/"
                            }
                        };
                        ParseJson.AppendToJsonFile(jsonData);
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Бессрочный пароль у пользователей
        public static void CheckPasswordNeverExpires(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Password Never Expires", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {

                    // Установка фильтра для поиска пользователей с флагом "DONT_EXPIRE_PASSWORD"
                    Filter = "(&(objectClass=user)(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No users found to PasswordNeverExires!",
                            ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} users with DONT_EXPIRE_PASSWORD:",
                            ConsoleColor.Green);
                        List<string> lists = new List<string>();

                        if (results.Count > 20)
                        {
                            string fileName = $"{domain}_PasswordNeverExipres.csv";
                            using (StreamWriter file = new StreamWriter(fileName))
                            {
                                foreach (SearchResult result in results)
                                {
                                    string username = result.Properties["sAMAccountName"][0].ToString();
                                    lists.Add(username);
                                    file.WriteLine(username);
                                }
                            }

                            Console.WriteLine($"\t- Data written to file {domain}_PasswordNeverExipres.csv\n");
                        }
                        else
                        {
                            foreach (SearchResult result in results)
                            {
                                string username = result.Properties["sAMAccountName"][0].ToString();
                                lists.Add(username);
                                Console.WriteLine("\t- " + username);
                            }
                        }

                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                        {
                            IpAddress = dc,
                            VulnerabilityName = "Бессрочный пароль у пользователей",
                            Description = "Учетные записи имеют пароли, срок действия которых никогда не истекает. " +
                                          "Если злоумышленник скомпрометирует одну из таких учетных записей, он сможет сохранить долгосрочный доступ в домене. " +
                                          "Пользователи: " + string.Join(", ", lists),
                            Recommendations = "Убрать флаг 'Password never expiries' для учетных записей. Изменить пароли пользователей",
                            CVSSv2 = "AV:N/AC:M/Au:N/C:P/I:N/A:N",
                            Level = "4.3",
                            CVE = new String[] { },
                            Links = new String[]
                            {
                        "https://adsecurity.org/?p=4115",
                        "https://access.redhat.com/discussions/1283873",
                        "https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html",
                        "https://attack.mitre.org/mitigations/M1015/"
                            }
                        };
                        ParseJson.AppendToJsonFile(jsonData);
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Добавление пользователями компьютеров в домен
        public static void CheckMachineAccountQuota(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Add computer to domain", ConsoleColor.Yellow);

            PropertyValueCollection valueCollection = ldapConnection.Properties["ms-DS-MachineAccountQuota"];

            // Проверка наличия значения
            if (Convert.ToInt16(valueCollection.Value) != 0)
            {
                ConsoleHelper.WriteColoredLine("\tAttribute ms-DS-MachineAccountQuota:", ConsoleColor.Green);
                Console.WriteLine($"\t- Value: {valueCollection.Value}\n");
                
                ParseJson.JsonData jsonData = new ParseJson.JsonData()
                {
                    IpAddress = dc,
                    VulnerabilityName  = "Добавление пользователями компьютеров в домен",
                    Description = "По умолчанию обычный пользователь может зарегистрировать до 10 компьютеров в домене. Эта конфигурация по умолчанию представляет " +
                                  "собой проблему безопасности, поскольку обычные пользователи не должны иметь такой возможности. " +
                                  "Значение атрибута ms-DS-MachineAccountQuota: " + valueCollection.Value,
                    Recommendations = "Для решения проблемы ограничьте количество дополнительных компьютеров, которые может зарегистрировать " +
                                      "обычный пользователь. Его можно уменьшить, изменив значение ms-DS-MachineAccountQuota на ноль (0)",
                    CVSSv2 = "AV:N/AC:M/Au:S/C:P/I:P/A:P",
                    Level = "6.0",
                    CVE = new String[] {},
                    Links = new String[]
                    {
                        "https://docs.microsoft.com/troubleshoot/windows-server/identity/default-workstation-numbers-join-domain",
                        "http://prajwaldesai.com/allow-domain-user-to-add-computer-to-domain/",
                        "http://blog.backslasher.net/preventing-users-from-adding-computers-to-a-domain.html",
                        "https://attack.mitre.org/mitigations/M1018"
                    }
                };
                ParseJson.AppendToJsonFile(jsonData);
            }
            else
            {
                ConsoleHelper.WriteColoredLine("\t[X] No attribute ms-DS-MachineAccountQuota!\n", ConsoleColor.Red);
            }
        }
        
        // Использование слабого алгоритма DES
        public static void CheckDES(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Support DES Encrypt", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    // Установка фильтра для поиска объектов со слабым алгоритмом DES
                    // msDs-supportedEncryptionTypes:1.2.840.113556.1.4.803:=3 - означает использование: DES_CBC_CRC (1) и/или DES_CBC_MD5 (2)
                    Filter = "(&(|(msDs-supportedEncryptionTypes:1.2.840.113556.1.4.803:=3)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No objects found to support DES!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} objects with support DES:",
                            ConsoleColor.Green);

                        List<string> lists = new List<string>();

                        foreach (SearchResult result in results)
                        {
                            lists.Add(result.Properties["sAMAccountName"][0].ToString());

                            Console.WriteLine("\t- " + result.Properties["sAMAccountName"][0]);
                        }

                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                        {
                            IpAddress = dc,
                            VulnerabilityName = "Использование слабого алгоритма DES",
                            Description =
                                "DES — очень слабый алгоритм, и после присвоения учетной записи его можно использовать в запросах билетов Kerberos. " +
                                "Использование данного алгоритма значительно снижает надежность выдаваемых билетов Kerberos и упрощает атаки методом перебора. " +
                                "Уязвимые объекты: " + string.Join(", ", lists),
                            Recommendations =
                                "Рекомендуется отключить DES в качестве алгоритма шифрования в диалоге конфигурации пользователя или в атрибуте " +
                                "'msDS-SupportedEncryptionTypes' на уровне LDAP",
                            CVSSv2 = "AV:N/AC:M/Au:S/C:P/I:P/A:P",
                            Level = "6.0",
                            CVE = new String[] { },
                            Links = new String[]
                            {
                                "https://docs.microsoft.com/en-us/archive/blogs/openspecification/msds-supportedencryptiontypes-episode-1-computer-accounts",
                                "https://docs.microsoft.com/en-us/services-hub/health/remediation-steps-ad/remove-the-highly-insecure-des-encryption-from-user-accounts",
                                "https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#kerberos_properties_deskey",
                                "https://attack.mitre.org/techniques/T1558/004"
                            }
                        };
                        ParseJson.AppendToJsonFile(jsonData);
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
        
        // LDAP null session
        public static void CheckLdapNullSession(string domain, string dc)
        {
            ConsoleHelper.WriteColoredLine("[*] LDAP null session", ConsoleColor.Yellow);

            string ldapPath = "LDAP://" + domain + "/DC=" + domain.Replace(".", ",DC=");

            using (DirectoryEntry ldapConnection = new DirectoryEntry(ldapPath))
            {
                try
                {
                    DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                    {
                        Filter = "(objectClass=*)",
                        PropertiesToLoad = { "displayName" },
                        SizeLimit = 1,
                        PageSize = 1
                    };

                    ds.FindOne();

                    ConsoleHelper.WriteColoredLine("\tSuccess LDAP null session", ConsoleColor.Green);

                    ParseJson.JsonData jsonData = new ParseJson.JsonData()
                    {
                        IpAddress = dc,
                        VulnerabilityName = "Анонимная аутентификация LDAP",
                        Description =
                            "Сервер LDAP разрешает анонимное подключение. Это позволяет злоумышленникам выполнять сбор информации о структуре сети, " +
                            "пользователях и других объектах",
                        Recommendations =
                            "Настроить службу так, чтобы требовалась обязательная аутентификация",
                        CVSSv2 = "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                        Level = "5.0",
                        CVE = new String[] { },
                        Links = new String[]
                        {
                            "https://securitysynapse.blogspot.com/2013/09/dangers-of-ldap-null-base-and-bind.html"
                        }
                    };
                    ParseJson.AppendToJsonFile(jsonData);

                    Console.WriteLine();
                }
                catch (DirectoryServicesCOMException)
                {
                    ConsoleHelper.WriteColoredLine("\t[X] No LDAP null session!\n", ConsoleColor.Red);
                }
                catch (Exception)
                {
                    ConsoleHelper.WriteColoredLine("\t[X] No LDAP null session!\n", ConsoleColor.Red);
                }
            }
        }
    }
}