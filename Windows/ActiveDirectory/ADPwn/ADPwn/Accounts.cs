using System;
using System.DirectoryServices;
using System.Collections.Generic;

namespace ADPwn
{
    public static class Accounts
    {
        // Можно делегировать как минимум одну учетную запись администратора
        public static void CheckProtectedUser(string domain, string dc, List<string> admins, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Privileged Accounts", ConsoleColor.Blue);
            
            ConsoleHelper.WriteColoredLine("[*] Admin can be delegated", ConsoleColor.Yellow);

            try
            {
                using (DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    // Установка фильтра для поиска пользователей с флагом NOT_DELEGATED
                    Filter = "(&(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=1048576))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                })

                using (SearchResultCollection results = ds.FindAll())
                {
                    List<string> lists = new List<string>();
                    string[] dcParts = domain.Split('.');
                    string dn = "DC=" + string.Join(",DC=", dcParts);
                    string protectedUsersDN = $"CN=Protected Users,CN=Users,{dn}";

                    DirectorySearcher protectedUsersSearcher = new DirectorySearcher(ldapConnection)
                    {
                        // Установка фильтра для поиска членов группы Protected Users
                        Filter = $"(&(samAccountType=805306368)(memberOf={protectedUsersDN}))",
                        PropertiesToLoad = { "sAMAccountName" },
                        PageSize = 1000
                    };

                    using (SearchResultCollection protectedUsersResults = protectedUsersSearcher.FindAll())
                    {
                        List<string> protectedUsersLists = new List<string>();

                        foreach (SearchResult result in protectedUsersResults)
                        {
                            protectedUsersLists.Add(result.Properties["sAMAccountName"][0].ToString());
                        }

                        foreach (string admin in admins)
                        {
                            bool notDelegated = false;

                            // Проверка, имеет ли администратор флаг NOT_DELEGATED
                            foreach (SearchResult result in results)
                            {
                                if (result.Properties["samAccountName"][0].ToString()
                                    .Equals(admin, StringComparison.OrdinalIgnoreCase))
                                {
                                    notDelegated = true;
                                    break;
                                }
                            }

                            // Проверка, входит ли администратор в группу Protected Users
                            if (!notDelegated && protectedUsersLists.Contains(admin))
                            {
                                notDelegated = true;
                            }

                            // Если нет флага и не входит в группу, то добавляем в список
                            if (!notDelegated)
                            {
                                lists.Add(admin);
                            }
                        }

                        if (lists.Count > 0)
                        {
                            ConsoleHelper.WriteColoredLine($"\tFound {lists.Count} user(s) can be delegated:",
                                ConsoleColor.Green);
                            // Выводим пользователей и добавляем в lists
                            foreach (string list in lists)
                            {
                                Console.WriteLine("\t- " + list);
                            }

                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = dc,
                                VulnerabilityName = "Разрешено делегирование администратора домена",
                                Description =
                                    "Разрешение делегирования учетных записей администраторов домена дает возможность повышения привилегий из скомпрометированной " +
                                    "системы. Уязвимые объекты: " + string.Join(", ", lists),
                                Recommendations =
                                    "Присвоить флаг 'Account is sensitive and cannot be delegated', либо добавить в группу 'Protected Users' все учетные записи администраторов домена",
                                CVSSv2 = "AV:N/AC:M/Au:S/C:P/I:P/A:P",
                                Level = "6.0",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                                    "https://attack.mitre.org/mitigations/M1015/"
                                }
                            };
                            ParseJson.AppendToJsonFile(jsonData);
                        }
                        else
                        {
                            ConsoleHelper.WriteColoredLine("\t[X] All admins have NOT_DELEGATED flag!",
                                ConsoleColor.Red);
                        }
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Проверка неограниченного делегирования
        public static void CheckUnconstrained(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Unconstrained delegation", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)" +
                             "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No unconstrained delegation!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine(
                            $"\tFound {results.Count} computer(s) with unconstrained delegation:", ConsoleColor.Green);

                        List<string> lists = new List<string>();
                        
                        foreach (SearchResult result in results)
                        {
                            lists.Add(result.Properties["sAMAccountName"][0].ToString());

                            string sAMAccountName = result.Properties.Contains("sAMAccountName") &&
                                                   result.Properties["sAMAccountName"].Count > 0
                                ? result.Properties["sAMAccountName"][0].ToString()
                                : null;

                            string hostName = $"{sAMAccountName.TrimEnd('$')}.{domain}";

                            string ip = ConsoleHelper.GetIPAddress(hostName, dc);
                            
                            Console.WriteLine($"\t- IP-Address: {ip} / Name: {hostName}");

                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = ip,
                                HostName = hostName,
                                VulnerabilityName = "Неограниченное делегирование",
                                Description =
                                    "При неограниченном делегировании можно перехватить билет Kerberos TGT. Этот TGT предоставляет пользователю доступ к любой службе, " +
                                    "к которой он имеет доступ. Если злоумышленник получит административный доступ на уязвимом хосте, то домен может быть " +
                                    "скомпрометирован",
                                Recommendations =
                                    "Заменить неограниченное делегирование на ограниченное. У объекта во вкладке 'Делегирование', заменить 'Доверять компьютеру " +
                                    "делегирование любых служб' на 'Доверять компьютеру делегирование указанных служб'",
                                CVSSv2 = "AV:N/AC:M/Au:S/C:C/I:C/A:C",
                                Level = "8.5",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                                    "https://learn.microsoft.com/ru-ru/archive/blogs/389thoughts/get-rid-of-accounts-that-use-kerberos-unconstrained-delegation",
                                    "https://adsecurity.org/?p=1667",
                                    "https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html",
                                    "https://attack.mitre.org/techniques/T1187/",
                                    "https://attack.mitre.org/mitigations/M1015/"
                                }
                            };
                            ParseJson.AppendToJsonFile(jsonData);
                        }
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
        
        // Проверка LAPS
        public static void CheckLAPS(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] LAPSv2", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))",
                    PropertiesToLoad = { "msLAPS-EncryptedPassword", "msLAPS-Password", "ms-MCS-AdmPwd", "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No LAPS or current user not admin!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} LAPS:", ConsoleColor.Green);
                        
                        string description = null;

                        foreach (SearchResult result in results)
                        {
                            string sAMAccountName = result.Properties.Contains("sAMAccountName") &&
                                                   result.Properties["sAMAccountName"].Count > 0
                                ? result.Properties["sAMAccountName"][0].ToString()
                                : null;

                            string msLapsEncryptedPassword = result.Properties.Contains("msLAPS-EncryptedPassword") &&
                                                            result.Properties["msLAPS-EncryptedPassword"].Count > 0
                                ? Convert.ToBase64String((byte[])result.Properties["msLAPS-EncryptedPassword"][0])
                                : null;

                            string msLapsPassword = result.Properties.Contains("msLAPS-Password") &&
                                                   result.Properties["msLAPS-Password"].Count > 0
                                ? result.Properties["msLAPS-Password"][0].ToString()
                                : null;

                            string msMcsAdmPwd = result.Properties.Contains("ms-MCS-AdmPwd") &&
                                                result.Properties["ms-MCS-AdmPwd"].Count > 0
                                ? result.Properties["ms-MCS-AdmPwd"][0].ToString()
                                : null;
                            
                            if (msLapsEncryptedPassword != null)
                            {
                                description = $"Computer: {sAMAccountName}, Password: {msLapsEncryptedPassword}";
                            }

                            if (msLapsPassword != null)
                            {
                                description = $"Computer: {sAMAccountName}, Password: {msLapsPassword}";
                            }

                            if (msMcsAdmPwd != null)
                            {
                                description = $"Computer: {sAMAccountName}, Password: {msMcsAdmPwd}";
                            }
                            
                            Console.WriteLine($"\t- {description}");
                            
                            string hostName = $"{sAMAccountName.TrimEnd('$')}.{domain}";

                            string ip = ConsoleHelper.GetIPAddress(hostName, dc);
                            
                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = ip,
                                HostName = hostName,
                                VulnerabilityName = "Пароли LAPSv2",
                                Description =
                                    "Скомпрометировав пользователя с разрешением на чтение паролей LAPS, можно скомпрометировать большинство хостов домена. " + description,
                                Recommendations =
                                    "Проанализировать группу пользователей, которым разрешено чтение паролей LAPS",
                                CVSSv2 = "AV:N/AC:M/Au:S/C:C/I:C/A:C",
                                Level = "8.5",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                                    "https://adsecurity.org/?p=3164"
                                }
                            };
                            ParseJson.AppendToJsonFile(jsonData);
                        }
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
    }
}