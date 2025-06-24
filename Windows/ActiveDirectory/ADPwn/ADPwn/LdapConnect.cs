using System.DirectoryServices;

namespace ADPwn
{
    public static class LdapConnect
    {
        // Метод для соединения с корневым доменом
        public static DirectoryEntry CreateRootDirectoryEntry(string domain, string username, string password)
        {
            string ldapPath = "LDAP://" + domain + "/DC=" + domain.Replace(".", ",DC=");

            return new DirectoryEntry(ldapPath, username, password, AuthenticationTypes.Secure);
        }
        
        // Метод для соединения с конфигурационным разделом
        public static DirectoryEntry CreateConfigurationPartitionEntry(string domain, string username, string password)
        {
            // Разделение имени домена на части для составления Path DN и удаление child домена
            string[] dcParts = domain.Split('.');
            string dn = dcParts.Length > 2 ? "DC=" + string.Join(",DC=", dcParts, dcParts.Length - 2, 2) : "DC=" + string.Join(",DC=", dcParts);
            string ldapPath = $"LDAP://{domain}/CN=Configuration,{dn}";
            
            return new DirectoryEntry(ldapPath, username, password, AuthenticationTypes.Secure);
        }
        
        // Метод для поиск групп текущего пользователя
        public static DirectoryEntry CreateMemberOfDirectoryEntry(string dn, string domain, string username, string password)
        {
            string ldapPath = $"LDAP://{domain}/{dn}";

            return new DirectoryEntry(ldapPath, username, password, AuthenticationTypes.Secure);
        }
    }
}