using System;
using System.DirectoryServices;
using System.Collections.Generic;

namespace ADPwn
{
    class Program
    {
        private static void Main(string[] args)
        {
            string username = null;
            string password = null;
            string domain = null;
            string dc = null;
            
            // Парсинг аргументов
            ConsoleHelper.ParseArgs(ref username, ref password, ref domain, ref dc, args);

            if (username == null || password == null || domain == null || dc == null)
            {
                Console.WriteLine("Usage: ADPwn.exe -u <username> -p <password> -d <domain.local> -dc-ip <dc-ip>");
                return;
            }

            username = ConsoleHelper.ConvertUsername(domain, username);

            // Задает имя для файла jsonData.json
            ConsoleHelper.DomainProvider.Domain = domain;

            List<string> users = new List<string>();
            List<string> admins = new List<string>();

            List<string> userGroupSids = new List<string>();
            string userSid = null;
            bool adcs = false;
            string ipAdcs = null;
            
            // Нужен для ACL. Если текущий юзер админ, то проверяться ACL не будет
            bool currentIsAdmin = false;

            DirectoryEntry ldapConnection = LdapConnect.CreateRootDirectoryEntry(domain, username, password);
            DirectoryEntry ldapConfConnection = LdapConnect.CreateConfigurationPartitionEntry(domain, username, password);
            
            GetInfo.GetHost(domain, dc, ldapConnection);
            GetInfo.GetDC(domain, dc, ldapConnection);
            GetInfo.GetPort(domain, dc, ldapConnection);
            GetInfo.GetUser(ref currentIsAdmin, username, users, admins, domain, ldapConnection);
            GetInfo.GetGroup(domain, ldapConnection);
            GetInfo.GetGPO(ldapConnection);
            GetInfo.GetOU(ldapConnection);
            GetInfo.GetDelegation(ldapConnection);
            GetInfo.GetTrust(ldapConnection);
            
            StaleObject.CheckOutdatedOS(domain, dc, ldapConnection);
            StaleObject.CheckUpdateDC(dc, ldapConnection);
            StaleObject.CheckNoPasswordRequired(dc, ldapConnection);
            StaleObject.CheckPasswordNeverExpires(domain, dc, ldapConnection);
            StaleObject.CheckMachineAccountQuota(dc, ldapConnection);
            StaleObject.CheckDES(dc, ldapConnection);
            StaleObject.CheckLdapNullSession(domain, dc);
            
            Roast.CheckASREPRoast(dc, ldapConnection);
            Roast.CheckKERBERoast(dc, ldapConnection);
            
            Accounts.CheckProtectedUser(domain, dc, admins, ldapConnection);
            Accounts.CheckUnconstrained(domain, dc, ldapConnection);
            Accounts.CheckLAPS(domain, dc, ldapConnection);
            
            // Используются для ESC и ACL
            ConsoleHelper.GetSid(ref userSid, username, ldapConnection);
            ConsoleHelper.GetGroupSids(userSid, userGroupSids, ldapConnection, domain, username, password);
            
            ESC.CheckESC8(ref adcs, ref ipAdcs, dc, ldapConfConnection);
            
            if (adcs)
            {
                try
                {
                    ConsoleHelper.WriteColoredLine("[*] ESC", ConsoleColor.Yellow);
                    ESC.CheckESC(ipAdcs, userSid, userGroupSids, ldapConfConnection, ldapConnection);
                }
                catch (MissingMethodException ex)
                {
                    ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
                }
            }

            if (!currentIsAdmin)
            {
                try
                {
                    ConsoleHelper.WriteColoredLine("[*] ACL", ConsoleColor.Blue);
                    ACL.CheckACL(userSid, userGroupSids, dc, ldapConnection);
                }
                catch (MissingMethodException ex)
                {
                    ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
                }
            }
            else
            {
                ConsoleHelper.WriteColoredLine("[*] ACL", ConsoleColor.Blue);
                ConsoleHelper.WriteColoredLine("\t[*] Skipped. You have high privileges", ConsoleColor.Yellow);
            }
        }
    }
}