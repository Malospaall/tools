using System;
using System.DirectoryServices;
using System.Collections.Generic;

namespace ADPwn
{
    public static class Roast
    {
        // AS-REP Roasting. Предварительная аутентификация Kerberos не используется
        public static void CheckASREPRoast(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Roast", ConsoleColor.Blue);
            
            ConsoleHelper.WriteColoredLine("[*] ASREPRoast", ConsoleColor.Yellow);

            try
            {
                // Создание объекта DirectorySearcher для выполнения запроса
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {

                    // Установка фильтра для поиска уязвимых пользователей для ASREPRoast
                    Filter = "(&(objectClass=user)(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No users found to ASREPRoast!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} users with DONT_REQ_PREAUTH:", ConsoleColor.Green);

                        List<string> lists = new List<string>();

                        foreach (SearchResult result in results)
                        {
                            lists.Add(result.Properties["sAMAccountName"][0].ToString());

                            Console.WriteLine("\t- " + result.Properties["sAMAccountName"][0]);
                        }

                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                        {
                            IpAddress = dc,
                            VulnerabilityName =
                                "AS-REP Roasting. Предварительная аутентификация Kerberos не используется",
                            Description =
                                "Без предварительной аутентификации Kerberos злоумышленник может запросить данные Kerberos у контроллера домена и использовать" +
                                "эти данные для взлома пароля учетной записи. Уязвимые объекты: " + string.Join(", ", lists),
                            Recommendations =
                                "Снять флаг 'Do not require Kerberos preauthentication' у учетных записей",
                            CVSSv2 = "AV:N/AC:M/Au:N/C:P/I:C/A:C",
                            Level = "9.0",
                            CVE = new String[] { },
                            Links = new String[]
                            {
                                "https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html",
                                "https://attack.mitre.org/techniques/T1558/004/"
                            }
                        };
                        // Сохранение данных в JSON
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

        // Kerberoasting
        public static void CheckKERBERoast(string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] KERBERoast", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    // Установка фильтра для поиска уязвимых пользователей для KERBERoast
                    Filter =
                        "(&(samAccountType=805306368)(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
                    PropertiesToLoad = { "sAMAccountName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No users found to KERBERoast!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} users vulnerable to KERBERoast:",
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
                            VulnerabilityName = "Kerberoasting",
                            Description =
                                "Аутентифицированные пользователи домена могут запросить сервисные билеты для учетной записи, указав ее Service Principal Name (SPN). " +
                                "Сервер выдачи билетов (Ticket Granting Service, TGS) на контроллере домена вернет билет, зашифрованный с помощью " +
                                "NTLM-хэша пароля учетной записи. Уязвимые объекты: " + string.Join(", ", lists),
                            Recommendations =
                                "Включить шифрование AES Kerberos (или другой более надежный алгоритм шифрования). Не использовать алгоритм шифрования RC4. " +
                                "Обеспечить надежную длину пароля (в идеале более 25 символов), а также периодическое истечение срока действия этих паролей. " +
                                "Ограничить учетные записи служб минимальными привилегиями. Исключить членство в привилегированных группах, таких как " +
                                "администраторы домена. Злоумышленник может использовать эти данные для взлома пароля учетной записи.",
                            CVSSv2 = "AV:N/AC:M/Au:S/C:P/I:N/A:N",
                            Level = "3.5",
                            CVE = new String[] { },
                            Links = new String[]
                            {
                                "https://attack.mitre.org/techniques/T1558/003/",
                                "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"
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
    }
}