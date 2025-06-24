using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.AccessControl;

namespace ADPwn
{
    public class ACL
    {
        private static bool CheckObjectPermissions(ActiveDirectorySecurity sd, string username, List<string> vulnRights, string sAMAccountName, string userSid, List<string> userGroupSids)
        {
            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            
            bool isVulnerable = false;
            int count = 0;
            
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                // Проверяем, что правило относится к разрешениям (Allow)
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;

                var sid = rule.IdentityReference.ToString();

                // Проверяем, применимо ли правило к текущему пользователю или его группам
                if (sid == userSid || userGroupSids.Contains(sid))
                {
                    count++;
                    isVulnerable = true;
                    
                    if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        vulnRights.Add("GenericAll");
                    }
                    else
                    {
                        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                        {
                            vulnRights.Add("WriteDacl");
                        }

                        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                        {
                            vulnRights.Add("GenericWrite");
                        }
                        else
                        {
                            if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                            {
                                vulnRights.Add("WriteProperty");
                            }
                    
                            if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.Self) == ActiveDirectoryRights.Self)
                            {
                                vulnRights.Add("Self");
                            }
                        }

                        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                        {
                            vulnRights.Add("AllExtendedRights");
                        }
                        else
                        {
                            if (rule.ObjectType == new Guid("00299570-246d-11d0-a768-00aa006e0529")) // ForceChangePassword
                            {
                                vulnRights.Add("ForceChangePassword");
                            }
                        }
                    
                        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                        {
                            vulnRights.Add("WriteOwner");
                        }
                    }
                }
            }

            if (count > 0)
            {
                Console.WriteLine($"\t- User '{username}' or his group has rights to '{sAMAccountName}': {string.Join(", ", vulnRights)}");
            }

            return isVulnerable;
        }

        // Проверка ACL
        public static void CheckACL(string userSid, List<string> userGroupSids, string dc, DirectoryEntry ldapConnection)
        {
            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConnection)
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                    Filter = "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                    PropertiesToLoad = { "sAMAccountName", "nTSecurityDescriptor" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No ACL!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine("\tFound vulnerable ACL:", ConsoleColor.Green);

                        string username = ConsoleHelper.ConvertSidToName(userSid, ldapConnection);
                        
                        foreach (SearchResult result in results)
                        {
                            List<string> vulnRights = new List<string>();
                            string sAMAccountName = result.Properties["sAMAccountName"][0].ToString();

                            if (result.Properties.Contains("nTSecurityDescriptor") &&
                                result.Properties["nTSecurityDescriptor"].Count > 0)
                            {
                                byte[] nTSecurityDescriptorBytes = (byte[])result.Properties["nTSecurityDescriptor"][0];
                                var sd = new ActiveDirectorySecurity();
                                sd.SetSecurityDescriptorBinaryForm(nTSecurityDescriptorBytes);

                                // Проверка прав ACL
                                if (CheckObjectPermissions(sd, username, vulnRights, sAMAccountName, userSid, userGroupSids))
                                {
                                    ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                    {
                                        IpAddress = dc,
                                        VulnerabilityName = "ACL. Уязвимые права на объект",
                                        Description =
                                            "Обнаружен объект, к которому пользователь '" + username + "' имеет права. Эти права могут позволить завладеть данным объектом. " +
                                            "Уязвимый объект: '" + sAMAccountName + "'. Права: " + string.Join(", ", vulnRights),
                                        Recommendations =
                                            "Проверить необходимость прав " + string.Join(", ", vulnRights) + " для пользователя '" + username + "' к объекту '" + sAMAccountName + "'.",
                                        CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:P/A:N",
                                        Level = "7.5",
                                        CVE = new String[] { },
                                        Links = new String[]
                                        {
                                            "https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists",
                                            "https://habr.com/en/articles/809485/"
                                        }
                                    };
                                    ParseJson.AppendToJsonFile(jsonData);
                                }
                            }
                            else
                            {
                                ConsoleHelper.WriteColoredLine("\t[X] Не удалось получить nTSecurityDescriptor для объекта", ConsoleColor.Red);
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
    }
}