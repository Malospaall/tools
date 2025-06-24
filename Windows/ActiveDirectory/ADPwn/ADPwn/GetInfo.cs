using System;
using System.IO;
using System.Linq;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;

namespace ADPwn
{
    public static class GetInfo
    {
        // Получение хостов в домене
        public static void GetHost(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Information", ConsoleColor.Blue);
            ConsoleHelper.WriteColoredLine("[*] Host", ConsoleColor.Yellow);
            
            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(objectCategory=computer)",
                    PropertiesToLoad = { "sAMAccountName", "operatingSystem", "OperatingSystemVersion" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No computer(s)!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} computer(s):", ConsoleColor.Green);
                        
                        using (StreamWriter file = new StreamWriter($"{domain}_hosts.csv"))
                        {
                            file.WriteLine("hostName,ip,operatingSystem");
                            
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

                                string hostName = $"{sAMAccountName.TrimEnd('$')}.{domain}";

                                string ip = ConsoleHelper.GetIPAddress(hostName, dc);
                                
                                string outputLine = $"{hostName},{ip},{operatingSystem} {operatingSystemVersion}";
                                file.WriteLine(outputLine);
                                
                                ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                {
                                    IpAddress = ip,
                                    HostName = hostName,
                                    OperatingSystem = operatingSystem + " " + operatingSystemVersion
                                };
                                // Сохранение данных в JSON
                                ParseJson.AppendToJsonFile(jsonData);
                            }
                            
                            Console.WriteLine($"\t- Data written to file {domain}_hosts.csv");
                        }
                    }

                    Console.WriteLine();
                }
            }
            // Проверка валидных учетных данных, DNS-сервера, имени домена
            catch (Exception ex)
            {
                Console.WriteLine("Ошибка! Проверьте:\n1. Указанные учетные данные\n2. Имя указанного домена\n3. IP-адрес контроллера домена\n4. Доступность хоста и службы LDAP\n");
                Console.WriteLine(ex);
                Environment.Exit(1);
            }
        }
        
        // Получение контроллеров домена
        public static void GetDC(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] DC", ConsoleColor.Yellow);
            
            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    PropertiesToLoad = { "sAMAccountName", "operatingSystem", "OperatingSystemVersion" },
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
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} DC:", ConsoleColor.Green);

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

                            string hostName = $"{sAMAccountName.TrimEnd('$')}.{domain}";

                            string ip = ConsoleHelper.GetIPAddress(hostName, dc);
                            
                            Console.WriteLine($"\t- IP-Address: {ip} / Name: {hostName} / OS: {operatingSystem} {operatingSystemVersion}");
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
        
        // Получение открытых портов
        public static void GetPort(string domain, string dc, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Open port", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(servicePrincipalName=*/*)",
                    PropertiesToLoad = { "cn", "servicePrincipalName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No open port(s)!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine("\tFound open port(s):", ConsoleColor.Green);

                        HashSet<string> uniquePorts = new HashSet<string>();
                        List<(string Ip, string Port, string ServiceName)> portList = new List<(string, string, string)>();

                        foreach (SearchResult result in results)
                        {
                            string user = result.Properties["cn"][0].ToString();

                            foreach (string spn in result.Properties["servicePrincipalName"])
                            {
                                string[] spnParts = spn.Split('/');
                                if (spnParts.Length < 2) continue;

                                string service = spnParts[0];
                                string hostName = spnParts[1];
                                string[] ports = null;
                                string[] serviceName = null;

                                if (hostName.Contains('.') && !hostName.Contains(':'))
                                {
                                    switch (service.ToLower())
                                    {
                                        case "ftp":
                                            ports = new[] { "21" };
                                            serviceName = new[] { "FTP" };
                                            break;
                                        case "smtp":
                                            ports = new[] { "25", "465", "587" };
                                            serviceName = new[] { "SMTP" };
                                            break;
                                        case "dns":
                                            ports = new[] { "53" };
                                            serviceName = new[] { "DNS" };
                                            break;
                                        case "http":
                                            ports = new[] { "80" };
                                            serviceName = new[] { "HTTP" };
                                            break;
                                        case "rpc":
                                            ports = new[] { "135" };
                                            serviceName = new[] { "RPC" };
                                            break;
                                        case "ldap":
                                            ports = new[] { "88", "389", "636", "3268", "3269" };
                                            serviceName = new[] { "KERBEROS", "LDAP", "LDAPS", "LDAP", "LDAPS" };
                                            break;
                                        case "https":
                                            ports = new[] { "443" };
                                            serviceName = new[] { "HTTPS" };
                                            break;
                                        case "host":
                                        case "cifs":
                                            ports = new[] { "139", "445" };
                                            serviceName = new[] { "NETBIOS-SSN", "SMB" };
                                            break;
                                        case "termserv":
                                        case "termsrv":
                                            ports = new[] { "3389" };
                                            serviceName = new[] { "RDP" };
                                            break;
                                        case "wsman":
                                            ports = new[] { "5985", "5986" };
                                            serviceName = new[] { "WINRM-HTTP", "WINRM-HTTPS" };
                                            break;
                                        case "mssql":
                                        case "mssqlsvc":
                                            ports = new[] { "1433" };
                                            serviceName = new[] { "MSSQL" };
                                            break;
                                        case "vnc":
                                            ports = new[] { "5900" };
                                            serviceName = new[] { "vnc" };
                                            break;
                                    }

                                    string ip = ConsoleHelper.GetIPAddress(hostName, dc);

                                    if (ports != null && ip != null)
                                    {
                                        for (int i = 0; i < ports.Length; i++)
                                        {
                                            string uniqueKey = $"{user}-{ports[i]}";

                                            // Проверяем, есть ли такая комбинация в HashSet
                                            if (uniquePorts.Add(uniqueKey))
                                            {
                                                portList.Add((ip, ports[i], serviceName[i]));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Сортировка по возрастанию портов
                        List<(string Ip, string Port, string ServiceName)> sortedPorts = portList
                            .OrderBy(p => int.Parse(p.Port))
                            .ToList();

                        // Запись в CSV
                        using (StreamWriter file = new StreamWriter($"{domain}_ports.csv"))
                        {
                            file.WriteLine("ip,port,serviceName");
                            foreach ((string Ip, string Port, string ServiceName) portData in sortedPorts)
                            {
                                string outputLine = $"{portData.Ip},{portData.Port},{portData.ServiceName}";
                                file.WriteLine(outputLine);
                            }
                        }

                        // Запись в JSON
                        foreach ((string Ip, string Port, string ServiceName) portData in sortedPorts)
                        {
                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = portData.Ip,
                                Port = $"tcp/{portData.Port}",
                                ServiceName = portData.ServiceName
                            };
                            // Сохранение данных в JSON
                            ParseJson.AppendToJsonFile(jsonData);
                        }

                        Console.WriteLine($"\t- Data written to file {domain}_ports.csv");
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Получение пользователей в домене
        public static void GetUser(ref bool currentIsAdmin, string username, List<string> users, List<string> admins, string domain, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] User", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(samAccountType=805306368)",
                    PropertiesToLoad = { "sAMAccountName", "memberOf" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No user(s)!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} User(s):", ConsoleColor.Green);

                        using (StreamWriter file = new StreamWriter($"{domain}_users.csv"))
                        {
                            foreach (SearchResult result in results)
                            {
                                string sAMAccountName = result.Properties.Contains("sAMAccountName") && 
                                                        result.Properties["sAMAccountName"].Count > 0 
                                    ? result.Properties["sAMAccountName"][0].ToString()
                                    : null;

                                // Проверяем, входит ли пользователь в группу администраторов (на английском или на русском)
                                bool isAdmin = ConsoleHelper.IsUserInGroups(result.Properties["memberOf"], domain);
                            
                                if (isAdmin)
                                {
                                    admins.Add(sAMAccountName);
                                    file.WriteLine(sAMAccountName + " - admin");
                                    if (string.Equals(sAMAccountName, username.Split('\\')[1], StringComparison.CurrentCultureIgnoreCase))
                                    {
                                        currentIsAdmin = true;
                                    }
                                }
                                else
                                {
                                    users.Add(sAMAccountName);
                                    file.WriteLine(sAMAccountName);
                                }
                            }

                            Console.WriteLine($"\t- Data written to file {domain}_users.csv\n");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
        
        // Получение групп
        public static void GetGroup(string domain, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Group", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(objectClass=group)",
                    PropertiesToLoad = { "name" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No group(s)!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} group(s):", ConsoleColor.Green);
                        using (StreamWriter file = new StreamWriter($"{domain}_groups.csv"))
                        {
                            foreach (SearchResult result in results)
                            {
                                file.WriteLine(result.Properties["name"][0].ToString());
                            }
                        }
                        Console.WriteLine($"\t- Data written to file {domain}_groups.csv");
                    }

                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }

        // Получение GPO
        public static void GetGPO(DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] GPO", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(objectClass=groupPolicyContainer)",
                    PropertiesToLoad = { "displayName", "name" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No GPO!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} GPO:", ConsoleColor.Green);
                        foreach (SearchResult result in results)
                        {
                            Console.WriteLine($"\t- Name: {result.Properties["displayName"][0]} / GUID: {result.Properties["name"][0]}");
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

        // Получение подразделений
        public static void GetOU(DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] OU", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(objectClass=organizationalUnit)",
                    PropertiesToLoad = { "name", "distinguishedName" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No OU!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} OU:", ConsoleColor.Green);
                        foreach (SearchResult result in results)
                        {
                            Console.WriteLine("\t- " + result.Properties["name"][0]);
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

        // Проверка делегирований
        public static void GetDelegation(DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Delegation", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    // проверить работу SecurityMasks в RBCD. С помощью нее должен читаться SecurityDescriptor от пользователя с низкими привилегиями
                    Filter =
                        "(&(|(UserAccountControl:1.2.840.113556.1.4.803:=524288)" +
                        "(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)" +
                        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))" +
                        "(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))",
                    PropertiesToLoad =
                    {
                        "sAMAccountName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        "userAccountControl", "DelegatedName"
                    },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No delegation!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine("\tFound delegation:", ConsoleColor.Green);

                        string sAMAccountName, delegationType, delegationRightsTo;

                        foreach (SearchResult result in results)
                        {
                            sAMAccountName = result.Properties.Contains("sAMAccountName") &&
                                             result.Properties["sAMAccountName"].Count > 0
                                ? result.Properties["sAMAccountName"][0].ToString()
                                : "N/A";

                            // Constrained w/ Protocol Transition и Constrained
                            if (result.Properties.Contains("msDS-AllowedToDelegateTo") &&
                                result.Properties["msDS-AllowedToDelegateTo"].Count > 0)
                            {
                                delegationRightsTo = result.Properties["msDS-AllowedToDelegateTo"][0].ToString();

                                // Извлекаем из атрибута userAccountControl число 16777216 и сравниаем с TRUSTED_TO_AUTH_FOR_DELEGATION
                                if ((Convert.ToInt32(result.Properties["userAccountControl"][0]) & 0x1000000) != 0)
                                {
                                    delegationType = "Constrained w/ Protocol Transition";
                                    Console.WriteLine($"\t - Account Name: {sAMAccountName} / DelegationType: {delegationType} / DelegationRightsTo: {delegationRightsTo}");
                                }
                                
                                // Constrained
                                else
                                {
                                    delegationType = "Constrained";
                                    Console.WriteLine($"\t - Account Name: {sAMAccountName} / DelegationType: {delegationType} / DelegationRightsTo: {delegationRightsTo}");
                                }
                            }

                            // Resource-Based Constrained
                            if (result.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") &&
                                result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count > 0)
                            {
                                try
                                {
                                    // Не работает на Linux прямое преобразование объекта в byte array. Так как в Linux данные по умолчанию передаются с типом string, а на Windows с оригинальным типо
                                    byte[] sidBytes = (byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                                    var sd = new ActiveDirectorySecurity();
                                    sd.SetSecurityDescriptorBinaryForm(sidBytes);

                                    foreach (ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                                    {
                                        // Поиск объекта по SID и получение его sAMAccountName
                                        string sid = rule.IdentityReference.Value;

                                        using (var sidSearcher = new DirectorySearcher(ldapConnection)
                                               {
                                                   Filter = $"(objectSid={sid})",
                                                   PropertiesToLoad = { "sAMAccountName" }
                                               })
                                        {
                                            SearchResult sidResult = sidSearcher.FindOne();
                                            
                                            delegationRightsTo = sidResult?.Properties.Contains("sAMAccountName") == true &&
                                                                 sidResult.Properties["sAMAccountName"]?.Count > 0
                                                ? sidResult.Properties["sAMAccountName"][0].ToString() : "N/A";
                                        }

                                        Console.WriteLine($"\t - Account Name: {delegationRightsTo} / DelegationType: Resource-Based Constrained / DelegationRightsTo: {sAMAccountName}");
                                    }
                                }
                                catch (InvalidCastException ex)
                                {
                                    ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
                                }
                            }
                            // Unconstrained
                            else if ((Convert.ToInt32(result.Properties["userAccountControl"][0]) & 0x80000) != 0)
                            {
                                delegationRightsTo = "N/A";
                                delegationType = "Unconstrained";
                                Console.WriteLine(
                                    $"\t - Account Name: {sAMAccountName} / DelegationType: {delegationType} / DelegationRightsTo: {delegationRightsTo}");
                            }
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
        
        // Проверка трастов
        public static void GetTrust(DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Trust", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = "(objectClass=trustedDomain)",
                    PropertiesToLoad = { "trustPartner", "trustDirection", "trustAttributes" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No trust(s)!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} trust(s):", ConsoleColor.Green);
                        
                        foreach (SearchResult result in results)
                        {
                            string direction;
                            string trustDirection = result.Properties["trustDirection"][0].ToString();
                            string trustPartner = result.Properties["trustPartner"][0].ToString();
                            string trustAttributesDescription = "";
                            int trustAttributesValue = Convert.ToInt32(result.Properties["trustAttributes"][0]);
                            
                            switch (trustDirection)
                            {
                                case "1":
                                    direction = "Inbound";
                                    break;
                                case "2":
                                    direction = "Outbound";
                                    break;
                                case "3":
                                    direction = "Bidirectional";
                                    break;
                                default:
                                    direction = "N/A";
                                    break;
                            }

                            if ((trustAttributesValue & 0x1) != 0) trustAttributesDescription = "Non-Transitive";
                            if ((trustAttributesValue & 0x2) != 0) trustAttributesDescription = "Uplevel-Only";
                            if ((trustAttributesValue & 0x4) != 0) trustAttributesDescription = "Quarantined Domain";
                            if ((trustAttributesValue & 0x8) != 0) trustAttributesDescription = "Forest Transitive";
                            if ((trustAttributesValue & 0x10) != 0) trustAttributesDescription = "Cross Organization";
                            if ((trustAttributesValue & 0x20) != 0) trustAttributesDescription = "Within Forest";
                            if ((trustAttributesValue & 0x40) != 0) trustAttributesDescription = "Treat as External";
                            if ((trustAttributesValue & 0x80) != 0) trustAttributesDescription = "Uses RC4 Encryption";
                            if ((trustAttributesValue & 0x100) != 0) trustAttributesDescription = "Cross Organization No TGT Delegation";
                            if ((trustAttributesValue & 0x2000) != 0) trustAttributesDescription = "PAM Trust";
                            
                            Console.WriteLine("\t- " + trustPartner + " -> " + direction + " -> " + trustAttributesDescription);
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
    }
}