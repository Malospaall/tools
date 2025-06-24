using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using DnsClient;

namespace ADPwn
{
    public static class ConsoleHelper
    {
        public static void ParseArgs(ref string username, ref string password, ref string domain, ref string dc, string[] args)
        {
            // Парсинг аргументов
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-u":
                        if (i + 1 < args.Length)
                        {
                            username = args[++i];
                        }
                        break;
                    case "-p":
                        if (i + 1 < args.Length)
                        {
                            password = args[++i];
                        }
                        break;
                    case "-d":
                        if (i + 1 < args.Length)
                        {
                            domain = args[++i].ToUpper();
                        }
                        break;
                    case "-dc-ip":
                        if (i + 1 < args.Length)
                        {
                            dc = args[++i];
                        }
                        break;
                    default:
                        WriteColoredLine("Unknown argument: " + args[i], ConsoleColor.Red);
                        break;
                }
            }
        }
        
        public static class DomainProvider
        {
            public static string Domain { get; set; }
        }
        
        // Установка цвета для текста
        public static void WriteColoredLine(string message, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public static string ConvertUsername(string domain, string username)
        {
            // Проверяем, есть ли уже обратная косая черта в имени пользователя и удаление части после первой точки
            string shortDomain = domain.Split('.')[0].ToUpper();

            if (username.Contains("\\"))
            {
                string[] usernameParts = username.Split('\\');
                string usernameDomain = usernameParts[0];
                string user = usernameParts[1];

                if (usernameDomain.Contains("."))
                {
                    usernameDomain = usernameDomain.Split('.')[0]; // Удаление части после первой точки
                }

                username = usernameDomain.ToUpper() + "\\" + user;
            }
            else
            {
                // Если обратная косая черта не найдена, добавляем короткое имя домена
                username = shortDomain + "\\" + username;
            }

            return username;
        }

        // Метод для получения IP-адресов хостов в домене с пользовательским DNS сервером
        public static string GetIPAddress(string hostName, string dc)
        {
            try
            {
                // Создание запроса с пользовательским DNS сервером
                var resolver = new LookupClient(IPAddress.Parse(dc));
                var queryResult = resolver.Query(hostName, QueryType.A);
        
                string addresses = "";

                // Проходим по списку полученных IP-адресов
                foreach (var address in queryResult.Answers)
                {
                    if (address is DnsClient.Protocol.ARecord aRecord)
                    {
                        // Проверяем, является ли адрес IPv4
                        if (aRecord.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            // Добавляем IP-адрес в виде строки в список
                            addresses = aRecord.Address.ToString();
                        }
                    }
                }

                // Возвращаем список IP-адресов
                if (addresses == "")
                {
                    return null;
                }

                return addresses;
            }
            catch (Exception ex)
            {
                // Логируем ошибку и возвращаем пустой список IP-адресов, так как разрешение не удалось
                WriteColoredLine($"\tОшибка при разрешении DNS: {ex.Message}", ConsoleColor.Red);
                return null;
            }
        }
        
        // Вспомогательный метод принимает список групп, к которым принадлежит пользователь
        // Проверяет наличие в этом списке DN двух групп администраторов (на английском и на русском языке)
        public static bool IsUserInGroups(ResultPropertyValueCollection memberOf, string domain)
        {
            string[] dcParts = domain.Split('.');
            string dn = "DC=" + string.Join(",DC=", dcParts);
            string[] groupDNs = {
                $"CN=Domain Admins,CN=Users,{dn}",
                $"CN=Администраторы домена,CN=Users,{dn}",
                $"CN=Administrators,CN=Builtin,{dn}",
                $"CN=Администраторы,CN=Builtin,{dn}"
            };
            
            if (memberOf != null)
            {
                foreach (string member in memberOf)
                {
                    foreach (string groupDn in groupDNs)
                    {
                        if (member.Equals(groupDn, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
        
        public static string ConvertSidToName(string sid, DirectoryEntry ldapConnection)
        {
            switch (sid)
            {
                case "S-1-0":
                    return "Null Authority";
                case "S-1-0-0":
                    return "Nobody";
                case "S-1-1":
                    return "World Authority";
                case "S-1-1-0":
                    return "Everyone";
                case "S-1-2":
                    return "Local Authority";
                case "S-1-2-0":
                    return "Local";
                case "S-1-2-1":
                    return "Console Logon";
                case "S-1-3":
                    return "Creator Authority";
                case "S-1-3-0":
                    return "Creator Owner";
                case "S-1-3-1":
                    return "Creator Group";
                case "S-1-3-2":
                    return "Creator Owner Server";
                case "S-1-3-3":
                    return "Creator Group Server";
                case "S-1-3-4":
                    return "Owner Rights";
                case "S-1-4":
                    return "Non-unique Authority";
                case "S-1-5":
                    return "NT Authority";
                case "S-1-5-1":
                    return "Dialup";
                case "S-1-5-2":
                    return "Network";
                case "S-1-5-3":
                    return "Batch";
                case "S-1-5-4":
                    return "Interactive";
                case "S-1-5-6":
                    return "Service";
                case "S-1-5-7":
                    return "Anonymous";
                case "S-1-5-8":
                    return "Proxy";
                case "S-1-5-9":
                    return "Enterprise Domain Controllers";
                case "S-1-5-10":
                    return "Principal Self";
                case "S-1-5-11":
                    return "Authenticated Users";
                case "S-1-5-12":
                    return "Restricted Code";
                case "S-1-5-13":
                    return "Terminal Server Users";
                case "S-1-5-14":
                    return "Remote Interactive Logon";
                case "S-1-5-15":
                    return "This Organization";
                case "S-1-5-17":
                    return "IUSR";
                case "S-1-5-18":
                    return "Local System";
                case "S-1-5-19":
                    return "NT Authority";
                case "S-1-5-20":
                    return "Network Service";
                case "S-1-5-80-0":
                    return "All Services";
                case "S-1-5-32-544":
                    return "Administrators";
                case "S-1-5-32-545":
                    return "Users";
                case "S-1-5-32-546":
                    return "Guests";
                case "S-1-5-32-547":
                    return "Power Users";
                case "S-1-5-32-548":
                    return "Account Operators";
                case "S-1-5-32-549":
                    return "Server Operators";
                case "S-1-5-32-550":
                    return "Print Operators";
                case "S-1-5-32-551":
                    return "Backup Operators";
                case "S-1-5-32-552":
                    return "Replicators";
                case "S-1-5-32-554":
                    return "Pre-Windows 2000 Compatible Access";
                case "S-1-5-32-555":
                    return "Remote Desktop Users";
                case "S-1-5-32-556":
                    return "Network Configuration Operators";
                case "S-1-5-32-557":
                    return "Incoming Forest Trust Builders";
                case "S-1-5-32-558":
                    return "Performance Monitor Users";
                case "S-1-5-32-559":
                    return "Performance Log Users";
                case "S-1-5-32-560":
                    return "Windows Authorization Access Group";
                case "S-1-5-32-561":
                    return "Terminal Server License Servers";
                case "S-1-5-32-562":
                    return "Distributed COM Users";
                case "S-1-5-32-568":
                    return "IIS_IUSRS";
                case "S-1-5-32-569":
                    return "Cryptographic Operators";
                case "S-1-5-32-573":
                    return "Event Log Readers";
                case "S-1-5-32-574":
                    return "Certificate Service DCOM Access";
                case "S-1-5-32-575":
                    return "RDS Remote Access Servers";
                case "S-1-5-32-576":
                    return "RDS Endpoint Servers";
                case "S-1-5-32-577":
                    return "RDS Management Servers";
                case "S-1-5-32-578":
                    return "Hyper-V Administrators";
                case "S-1-5-32-579":
                    return "Access Control Assistance Operators";
                case "S-1-5-32-580":
                    return "Access Control Assistance Operators";
            }

            using (var sidSearcher = new DirectorySearcher(ldapConnection))
            {
                sidSearcher.Filter = $"(objectSid={sid})";
                sidSearcher.PropertiesToLoad.Add("name");
                
                SearchResult sidResult = sidSearcher.FindOne();
                return sidResult?.Properties.Contains("name") == true && sidResult.Properties["name"]?.Count > 0
                    ? sidResult.Properties["name"][0].ToString()
                    : sid;
            }
        }
        
        // Получение SID текущего пользователя
        public static void GetSid(ref string userSid, string username, DirectoryEntry ldapConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] Current User", ConsoleColor.Blue);

            ConsoleHelper.WriteColoredLine("[*] User SID", ConsoleColor.Yellow);

            username = username.Split('\\')[1];

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = $"(samAccountName={username})",
                    PropertiesToLoad = { "objectSid" }
                };

                SearchResult result = ds.FindOne();

                byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                
                SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                userSid = sid.Value;

                Console.WriteLine("\t- " + userSid);
            }
            catch (InvalidCastException ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }

            Console.WriteLine();
        }
        
        // Получение SID групп текущего пользователя
        public static void GetGroupSids(string userSid, List<string> userGroupSids, DirectoryEntry ldapConnection, string domain, string username, string password)
        {
            ConsoleHelper.WriteColoredLine("[*] User groups", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    Filter = $"(objectSid={userSid})",
                    PropertiesToLoad = { "sAMAccountName", "memberOf", "primaryGroupID" }
                };

                SearchResult result = ds.FindOne();

                if (result == null)
                {
                    ConsoleHelper.WriteColoredLine("\t[X] User not found!", ConsoleColor.Red);
                }
                else
                {
                    // Перебираем все группы, в которых состоит пользователь
                    foreach (string dn in result.Properties["memberOf"])
                    {
                        DirectoryEntry ldapMemberOfConnection = LdapConnect.CreateMemberOfDirectoryEntry(dn, domain, username, password);

                        DirectorySearcher groupEntry = new DirectorySearcher(ldapMemberOfConnection)
                        {
                            PropertiesToLoad = { "objectSid" }
                        };

                        using (SearchResultCollection results = groupEntry.FindAll())
                        {
                            foreach (SearchResult groupresult in results)
                            {
                                byte[] sidBytes = (byte[])groupresult.Properties["objectSid"][0];
                                SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                                
                                userGroupSids.Add(sid.Value);
                            }
                        }
                    }
                    
                    // Проверяем Primary Group
                    if (result.Properties.Contains("primaryGroupID"))
                    {
                        string primaryGroupID = result.Properties["primaryGroupID"][0].ToString();
                        string domainSid = userSid.Substring(0, userSid.LastIndexOf('-'));
                        string primaryGroupSid = $"{domainSid}-{primaryGroupID}";

                        userGroupSids.Add(primaryGroupSid);
                    }

                    foreach (string userGroupSid in userGroupSids)
                    {
                        Console.WriteLine("\t- " + userGroupSid);
                    }
                }

                Console.WriteLine();
            }
            catch (InvalidCastException ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
    }
}