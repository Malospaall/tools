using System;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.DirectoryServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.AccessControl;

namespace ADPwn
{
    public class ESC
    {
        private static void PrintMsPKICertificateNameFlag(SearchResult result, List<string> msPKICertificateNameFlag)
        {
            
            // Certificate Name Flag
            int certNameFlag = Convert.ToInt32(result.Properties["msPKI-Certificate-Name-Flag"][0]);

            if ((certNameFlag & 0x00000001) != 0)
                msPKICertificateNameFlag.Add("ENROLLEE_SUPPLIES_SUBJECT");
            if ((certNameFlag & 0x00000002) != 0)
                msPKICertificateNameFlag.Add("ADD_EMAIL");
            if ((certNameFlag & 0x00000004) != 0)
                msPKICertificateNameFlag.Add("ADD_OBJ_GUID");
            if ((certNameFlag & 0x00000008) != 0)
                msPKICertificateNameFlag.Add("OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME");
            if ((certNameFlag & 0x00000100) != 0)
                msPKICertificateNameFlag.Add("ADD_DIRECTORY_PATH");
            if ((certNameFlag & 0x00010000) != 0)
                msPKICertificateNameFlag.Add("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME");
            if ((certNameFlag & 0x00400000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_DOMAIN_DNS");
            if ((certNameFlag & 0x00800000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_SPN");
            if ((certNameFlag & 0x01000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_DIRECTORY_GUID");
            if ((certNameFlag & 0x02000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_UPN");
            if ((certNameFlag & 0x04000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_EMAIL");
            if ((certNameFlag & 0x08000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_ALT_REQUIRE_DNS");
            if ((certNameFlag & 0x10000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_REQUIRE_DNS_AS_CN");
            if ((certNameFlag & 0x20000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_REQUIRE_EMAIL");
            if ((certNameFlag & 0x40000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_REQUIRE_COMMON_NAME");
            if ((certNameFlag & 0x80000000) != 0)
                msPKICertificateNameFlag.Add("SUBJECT_REQUIRE_DIRECTORY_PATH");

            if (msPKICertificateNameFlag.Count > 0)
            {
                Console.WriteLine($"\t    Certificate Name Flag           : {string.Join(", ", msPKICertificateNameFlag)}");
            }
        }

        private static void PrintMsPKIEnrollmentFlag(SearchResult result, List<string> msPKIEnrollmentFlag)
        {
            // Enrollment Flag
            int enrollmentFlag = Convert.ToInt32(result.Properties["msPKI-Enrollment-Flag"][0]);

            if ((enrollmentFlag & 0x00000000) != 0)
                msPKIEnrollmentFlag.Add("NONE");
            if ((enrollmentFlag & 0x00000001) != 0)
                msPKIEnrollmentFlag.Add("INCLUDE_SYMMETRIC_ALGORITHMS");
            if ((enrollmentFlag & 0x00000002) != 0)
                msPKIEnrollmentFlag.Add("PEND_ALL_REQUESTS");
            if ((enrollmentFlag & 0x00000004) != 0)
                msPKIEnrollmentFlag.Add("PUBLISH_TO_KRA_CONTAINER");
            if ((enrollmentFlag & 0x00000008) != 0)
                msPKIEnrollmentFlag.Add("PUBLISH_TO_DS");
            if ((enrollmentFlag & 0x00000010) != 0)
                msPKIEnrollmentFlag.Add("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE");
            if ((enrollmentFlag & 0x00000020) != 0)
                msPKIEnrollmentFlag.Add("AUTO_ENROLLMENT");
            if ((enrollmentFlag & 0x80) != 0)
                msPKIEnrollmentFlag.Add("CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED");
            if ((enrollmentFlag & 0x00000040) != 0)
                msPKIEnrollmentFlag.Add("PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT");
            if ((enrollmentFlag & 0x00000100) != 0)
                msPKIEnrollmentFlag.Add("USER_INTERACTION_REQUIRED");
            if ((enrollmentFlag & 0x200) != 0)
                msPKIEnrollmentFlag.Add("ADD_TEMPLATE_NAME");
            if ((enrollmentFlag & 0x00000400) != 0)
                msPKIEnrollmentFlag.Add("REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE");
            if ((enrollmentFlag & 0x00000800) != 0)
                msPKIEnrollmentFlag.Add("ALLOW_ENROLL_ON_BEHALF_OF");
            if ((enrollmentFlag & 0x00001000) != 0)
                msPKIEnrollmentFlag.Add("ADD_OCSP_NOCHECK");
            if ((enrollmentFlag & 0x00002000) != 0)
                msPKIEnrollmentFlag.Add("ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL");
            if ((enrollmentFlag & 0x00004000) != 0)
                msPKIEnrollmentFlag.Add("NOREVOCATIONINFOINISSUEDCERTS");
            if ((enrollmentFlag & 0x00008000) != 0)
                msPKIEnrollmentFlag.Add("INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS");
            if ((enrollmentFlag & 0x00010000) != 0)
                msPKIEnrollmentFlag.Add("ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT");
            if ((enrollmentFlag & 0x00020000) != 0)
                msPKIEnrollmentFlag.Add("ISSUANCE_POLICIES_FROM_REQUEST");
            if ((enrollmentFlag & 0x00040000) != 0)
                msPKIEnrollmentFlag.Add("SKIP_AUTO_RENEWAL");
            if ((enrollmentFlag & 0x00080000) != 0)
                msPKIEnrollmentFlag.Add("NO_SECURITY_EXTENSION");

            if (msPKIEnrollmentFlag.Count > 0)
            {
                Console.WriteLine($"\t    Enrollment Flag                 : {string.Join(", ", msPKIEnrollmentFlag)}");
            }
        }

        private static void PrintExtendedKeyUsage(SearchResult result, List<string> extendedKeyUsage)
        {
            // Extended Key Usage
            foreach (string extendedKeyUsageItem in result.Properties["pKIExtendedKeyUsage"])
            {
                switch (extendedKeyUsageItem)
                {
                    case "2.5.29.37.0":
                        extendedKeyUsage.Add("Any Purpose");
                        break;
                    case "1.3.6.1.5.5.7.3.2":
                        extendedKeyUsage.Add("Client Authentication");
                        break;
                    case "1.3.6.1.5.2.3.4":
                        extendedKeyUsage.Add("PKINIT Client Authentication");
                        break;
                    case "1.3.6.1.4.1.311.20.2.2":
                        extendedKeyUsage.Add("Smart Card Logon");
                        break;
                    case "1.3.6.1.4.1.311.20.2.1":
                        extendedKeyUsage.Add("Certificate Request Agent");
                        break;
                    case "1.3.6.1.4.1.311.10.3.1":
                        extendedKeyUsage.Add("Microsoft Trust List Signing");
                        break;
                    case "1.3.6.1.4.1.311.21.5":
                        extendedKeyUsage.Add("Private Key Archival");
                        break;
                    case "1.3.6.1.4.1.311.21.6":
                        extendedKeyUsage.Add("Key Recovery Agent");
                        break;
                    case "1.3.6.1.4.1.311.21.19":
                        extendedKeyUsage.Add("Directory Service Email Replication");
                        break;
                    case "1.3.6.1.5.5.7.3.9":
                        extendedKeyUsage.Add("OCSP Signing");
                        break;
                    case "1.3.6.1.5.5.7.3.3":
                        extendedKeyUsage.Add("Code Signing");
                        break;
                    case "1.3.6.1.5.5.7.3.4":
                        extendedKeyUsage.Add("Secure Email");
                        break;
                    case "1.3.6.1.4.1.311.10.3.4":
                        extendedKeyUsage.Add("Encrypting File System");
                        break;
                    case "1.3.6.1.4.1.311.10.3.4.1":
                        extendedKeyUsage.Add("File Recovery");
                        break;
                    case "1.3.6.1.5.5.7.3.7":
                        extendedKeyUsage.Add("IP security use");
                        break;
                    case "1.3.6.1.5.5.8.2.2":
                        extendedKeyUsage.Add("IP security IKE intermediate");
                        break;
                    case "1.3.6.1.5.5.7.3.1":
                        extendedKeyUsage.Add("Server Authentication");
                        break;
                    case "1.3.6.1.5.2.3.5":
                        extendedKeyUsage.Add("KDC Authentication");
                        break;
                }
            }

            if (extendedKeyUsage.Count > 0)
            {
                Console.WriteLine($"\t    Extended Key Usage              : {string.Join(", ", extendedKeyUsage)}");
            }
        }

        private static void PrintAllowPermissions(ref bool enrollPermission, ref bool writePropertyPermission, string userSid, List<string> userGroupSids, ActiveDirectorySecurity sd, DirectoryEntry ldapConnection, HashSet<string> enrollmentPrincipals, HashSet<string> allExtendedRightsPrincipals, HashSet<string> fullControlPrincipals, HashSet<string> writeOwnerPrincipals, HashSet<string> writeDaclPrincipals, HashSet<string> writePropertyPrincipals)
        {
            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;

                var sid = rule.IdentityReference.ToString();
                string userName = ConsoleHelper.ConvertSidToName(sid, ldapConnection);

                if (sid == userSid || userGroupSids.Contains(sid))
                {
                    enrollPermission = true;
                }
                
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                {
                    switch ($"{rule.ObjectType}")
                    {
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55": // Certificates-Enrollment right
                            enrollmentPrincipals.Add(userName);
                            break;
                        case "00000000-0000-0000-0000-000000000000": // All extended rights
                            allExtendedRightsPrincipals.Add(userName);
                            break;
                    }
                }

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    fullControlPrincipals.Add(userName);
                }

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    writeOwnerPrincipals.Add(userName);
                }

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    writeDaclPrincipals.Add(userName);
                }

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                {
                    writePropertyPrincipals.Add(userName);

                    if (sid == userSid || userGroupSids.Contains(sid))
                    {
                        writePropertyPermission = true;
                    }
                }
            }

            Console.WriteLine("\t    Enrollment Permissions");
            
            if (enrollmentPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tEnrollment Rights           : {string.Join(", ", enrollmentPrincipals)}");
            }

            if (allExtendedRightsPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tAll Extended Rights         : {string.Join(", ", allExtendedRightsPrincipals)}");
            }

            Console.WriteLine("\t    Object Control Permissions");

            if (fullControlPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tFull Control Principals     : {string.Join(", ", fullControlPrincipals)}");
            }

            if (writeOwnerPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tWriteOwner Principals       : {string.Join(", ", writeOwnerPrincipals)}");
            }

            if (writeDaclPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tWriteDacl Principals        : {string.Join(", ", writeDaclPrincipals)}");
            }

            if (writePropertyPrincipals.Count > 0)
            {
                Console.WriteLine($"\t\tWriteProperty Principals    : {string.Join(", ", writePropertyPrincipals)}\n");
            }
        }
        
        public static void CheckESC8(ref bool adcs, ref string ipAdcs, string dc, DirectoryEntry ldapConfConnection)
        {
            ConsoleHelper.WriteColoredLine("[*] ADCS", ConsoleColor.Blue);
            ConsoleHelper.WriteColoredLine("[*] ADCS Info", ConsoleColor.Yellow);

            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConfConnection)
                {
                    Filter = "(objectClass=pKIEnrollmentService)",
                    PropertiesToLoad = { "dNSHostName", "cn", "certificateTemplates" },
                    PageSize = 1000
                };

                SearchResult result = ds.FindOne();

                if (result == null)
                {
                    ConsoleHelper.WriteColoredLine("\t[X] No ADCS!", ConsoleColor.Red);
                }
                else
                {
                    ConsoleHelper.WriteColoredLine("\tFound ADCS:", ConsoleColor.Green);

                    adcs = true;

                    string caName = result.Properties["cn"][0].ToString();
                    string hostName = result.Properties["dNSHostName"][0].ToString();

                    Console.WriteLine("\t    CA Name                         : " + caName);
                    Console.WriteLine("\t    DNS Name                        : " + hostName);

                    // Проверка ESC8
                    try
                    {
                        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                        {
                            ipAdcs = ConsoleHelper.GetIPAddress(hostName, dc);

                            socket.Connect(new IPEndPoint(IPAddress.Parse(ipAdcs), 80));

                            string request = $"HEAD /certsrv/ HTTP/1.1\r\nHost: {hostName}\r\n\r\n";
                            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
                            socket.Send(requestBytes);

                            byte[] buffer = new byte[256];
                            int received = socket.Receive(buffer);
                            string response = Encoding.ASCII.GetString(buffer, 0, received);

                            string head = response.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
                            if (!head.Contains(" 404 "))
                            {
                                Console.WriteLine("\t    Web Enrollment                  : Enabled");
                                ConsoleHelper.WriteColoredLine("\t[+] ESC8: Web Enrollment is enabled and Request Disposition is set to Issue", ConsoleColor.Green);
                                
                                ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                {
                                    IpAddress = ipAdcs,
                                    VulnerabilityName = "ESC8. Настройка службы веб-регистрации по умолчанию",
                                    Description =
                                        "Настройка службы веб-регистрации по умолчанию позволяет объектам домена выполнять заявки на выдачу сертификата на сайте. " +
                                        "Злоумышленник может принудительно заставить учетную запись домена пройти аутентификацию на своем компьютере, тем самым передать " +
                                        "учетные данные жертвы в центр сертификации для получения сертификата от его имени",
                                    Recommendations =
                                        "Отключить веб-регистрацию ADCS, если она не нужна. Отключить NTLM-аутентификацию. Использовать HTTPS для аутентификации.",
                                    CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                    Level = "9.0",
                                    CVE = new String[] { },
                                    Links = new String[]
                                    {
                                        "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment"
                                    }
                                };
                                ParseJson.AppendToJsonFile(jsonData);
                            }
                            else
                            {
                                Console.WriteLine("\t    Web Enrollment                  : Disabled");
                            }
                        }
                    }
                    catch (SocketException ex)
                    {
                        Console.WriteLine("Connection failed: " + ex.Message);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Got error while trying to check for web enrollment: {ex.Message}");
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message}\n", ConsoleColor.Red);
            }
        }
        
        // Проверка ESC
        public static void CheckESC(string ipAdcs, string userSid, List<string> userGroupSids, DirectoryEntry ldapConfConnection, DirectoryEntry ldapConnection)
        {            
            try
            {
                DirectorySearcher ds = new DirectorySearcher(ldapConfConnection)
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                    Filter = "(objectclass=pkicertificatetemplate)",
                    PropertiesToLoad = { "cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage",
                        "msPKI-Certificate-Application-Policy", "nTSecurityDescriptor", "mspki-certificate-policy" },
                    PageSize = 1000
                };

                using (SearchResultCollection results = ds.FindAll())
                {
                    if (results.Count == 0)
                    {
                        ConsoleHelper.WriteColoredLine("\t[X] No Template!", ConsoleColor.Red);
                    }
                    else
                    {
                        ConsoleHelper.WriteColoredLine($"\tFound {results.Count} template(s):", ConsoleColor.Green);

                        string username = ConsoleHelper.ConvertSidToName(userSid, ldapConnection);
                        
                        foreach (SearchResult result in results)
                        {
                            try
                            {
                                List<string> msPKICertificateNameFlag = new List<string>();
                                List<string> msPKIEnrollmentFlag = new List<string>();
                                List<string> extendedKeyUsage = new List<string>();
                                
                                HashSet<string> enrollmentPrincipals = new HashSet<string>();
                                HashSet<string> allExtendedRightsPrincipals = new HashSet<string>();
                                HashSet<string> fullControlPrincipals = new HashSet<string>();
                                HashSet<string> writeOwnerPrincipals = new HashSet<string>();
                                HashSet<string> writeDaclPrincipals = new HashSet<string>();
                                HashSet<string> writePropertyPrincipals = new HashSet<string>();
                                
                                bool enrollPermission = false;
                                bool writePropertyPermission = false;
                                
                                // Template Name
                                string templateName = result.Properties["cn"][0].ToString();
                                Console.WriteLine("\t-   Template Name                   : " + templateName);
                                
                                // Certificate Name Flag
                                PrintMsPKICertificateNameFlag(result, msPKICertificateNameFlag);
                                
                                // Enrollment Flag
                                PrintMsPKIEnrollmentFlag(result, msPKIEnrollmentFlag);
                                
                                // Authorized Signatures Required
                                string msPKIRASignature = result.Properties["msPKI-RA-Signature"][0].ToString();
                                Console.WriteLine("\t    Authorized Signatures Required  : " + msPKIRASignature);
                                
                                // Extended Key Usage
                                PrintExtendedKeyUsage(result, extendedKeyUsage);

                                if (result.Properties.Contains("nTSecurityDescriptor") &&
                                    result.Properties["nTSecurityDescriptor"].Count > 0)
                                {
                                    byte[] nTSecurityDescriptorBytes =
                                        (byte[])result.Properties["nTSecurityDescriptor"][0];
                                    var sd = new ActiveDirectorySecurity();
                                    sd.SetSecurityDescriptorBinaryForm(nTSecurityDescriptorBytes);
                                    PrintAllowPermissions(ref enrollPermission, ref writePropertyPermission, userSid,
                                        userGroupSids, sd, ldapConnection, enrollmentPrincipals,
                                        allExtendedRightsPrincipals, fullControlPrincipals, writeOwnerPrincipals,
                                        writeDaclPrincipals, writePropertyPrincipals);

                                    // ESC1
                                    if (enrollPermission && !msPKIEnrollmentFlag.Contains("PEND_ALL_REQUESTS") &&
                                        msPKIRASignature == "0" &&
                                        (extendedKeyUsage.Contains("Client Authentication") ||
                                         extendedKeyUsage.Contains("PKINIT Client Authentication") ||
                                         extendedKeyUsage.Contains("Smart Card Logon")) &&
                                        msPKICertificateNameFlag.Contains("ENROLLEE_SUPPLIES_SUBJECT"))
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC1: {username} can enroll, enrollee supplies subject and template allows client authentication\n",
                                            ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName = "ESC1. Запрос сертификата произвольных пользователей",
                                            Description =
                                                "Обнаружен шаблон, который позволяет текущему пользователю с правами Enrollment указать SubjectAltName для любого " +
                                                "другого пользователя или компьютера, тем самым получить его сертификат и выполнить под ним аутентификацию. " +
                                                "Уязвимый шаблон: " + templateName + ". Объект с правами Enrollment: " + username,
                                            Recommendations =
                                                "Удалить права Enrollment для доменных пользователей и компьютеров с низкими привилегиями.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[]
                                            {
                                                "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-prevent-users-request-certificate"
                                            }
                                        };
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }

                                    // ESC2
                                    if (enrollPermission && !msPKIEnrollmentFlag.Contains("PEND_ALL_REQUESTS") &&
                                        msPKIRASignature == "0" && extendedKeyUsage.Contains("Any Purpose"))
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC2: {username} can enroll and template can be used for any purpose\n",
                                            ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName = "ESC2. Шаблон сертификата содержит EKU Any Purpose",
                                            Description =
                                                "Обнаружен шаблон, у которого значение параметра EKU Any Purpose. Это означает, что сертификат можно использовать для " +
                                                "любых целей, таких как: аутентификация клиента или сервера, подписание кода и так далее. " +
                                                "Уязвимый шаблон: " + templateName + ". Объект с правами Enrollment: " + username,
                                            Recommendations =
                                                "Удалить EKU Any Purpose и выдать конкретное значение для EKU. Удалить права Enrollment для доменных пользователей и " +
                                                "компьютеров с низкими привилегиями.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[]
                                            {
                                                "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-edit-overly-permissive-template"
                                            }
                                        };
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }

                                    // ESC3
                                    if (enrollPermission && !msPKIEnrollmentFlag.Contains("PEND_ALL_REQUESTS") &&
                                        msPKIRASignature == "0" &&
                                        extendedKeyUsage.Contains("Certificate Request Agent"))
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC3: {username} can enroll and template has Certificate Request Agent EKU set\n",
                                            ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName =
                                                "ESC3. Неправильно настроенный шаблон агента регистрации",
                                            Description =
                                                "Обнаружен шаблон агента регистрации, который позволяет регистрировать сертификаты для любого пользователя. " +
                                                "Уязвимый шаблон: " + templateName + ". Объект с правами Enrollment: " + username,
                                            Recommendations =
                                                "Удалить EKU агента запроса сертификата. Удалить права на регистрацию для доменных пользователей и компьютеров с низкими привилегиями.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[]
                                            {
                                                "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-edit-misconfigured-enrollment-agent"
                                            }
                                        };
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }

                                    // ESC4
                                    if (writePropertyPermission)
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC4: {username} has dangerous permissions", ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName =
                                                "ESC4. Неправильно настроенный шаблон сертификатов ACL",
                                            Description =
                                                "Если есть запись в ACL, которая предоставляет непривилегированным пользователям разрешения на изменение параметров шаблона, " +
                                                "злоумышленник сможет повысить привилегии и скомпрометировать весь домен. " +
                                                "Уязвимый шаблон: " + templateName + ". Объект, у которого есть права: " + username,
                                            Recommendations =
                                                "Удалить права, которые предоставляют разрешения на изменение шаблона для доменных пользователей и компьютеров с низкими привилегиями.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[]
                                            {
                                                "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-edit-misconfigured-acl",
                                                "https://learn.microsoft.com/ru-ru/defender-for-identity/security-assessment-edit-misconfigured-owner"
                                            }
                                        };
                                        // Сохранение данных в JSON
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }
                                    
                                    // ESC9
                                    // Не тестировался
                                    if (enrollPermission && msPKIEnrollmentFlag.Contains("NO_SECURITY_EXTENSION") &&
                                        msPKIRASignature == "0" &&
                                        (extendedKeyUsage.Contains("Client Authentication") ||
                                         extendedKeyUsage.Contains("PKINIT Client Authentication") ||
                                         extendedKeyUsage.Contains("Smart Card Logon")))
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC9: {username} can enroll and template has no security extension\n",
                                            ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName = "ESC9. Отсутствует расширение безопасности",
                                            Description =
                                                "Обнаружен шаблон, у которого в атрибуте 'msPKI-Enrollment-Flag' выставлено значение 'CT_FLAG_NO_SECURITY_EXTENSION', " +
                                                "которое предотвращает встраивание расширение безопасонсти в сертификат. " +
                                                "Уязвимый шаблон: " + templateName + ". Объект с правами Enrollment: " + username,
                                            Recommendations =
                                                "Удалить значение 'CT_FLAG_NO_SECURITY_EXTENSION' из атрибута 'msPKI-Enrollment-Flag'.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[] { }
                                        };
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }

                                    // ESC13
                                    // Не тестировалось
                                    // Пример запроса взят из: https://sploitus.com/exploit?id=MSF:AUXILIARY-GATHER-LDAP_ESC_VULNERABLE_CERT_FINDER-
                                    // https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1
                                    // https://www.bulletproof.co.uk/blog/abusing-esc13-from-linux
                                    // Найти уязвимую машину и доработать
                                    /*if (enrollPermission && !msPKIEnrollmentFlag.Contains("PEND_ALL_REQUESTS") &&
                                        msPKIRASignature == "0" &&
                                        (extendedKeyUsage.Contains("Client Authentication") ||
                                         extendedKeyUsage.Contains("PKINIT Client Authentication") ||
                                         extendedKeyUsage.Contains("Smart Card Logon")) &&
                                        msPKICertificateNameFlag.Contains("ENROLLEE_SUPPLIES_SUBJECT"))
                                    {
                                        ConsoleHelper.WriteColoredLine(
                                            $"\t[+] ESC13: {username} can enroll, template allows client authentication and issuance policy is linked to group ['CN=esc13group,CN=Users,DC=domain,DC=local']\n",
                                            ConsoleColor.Green);

                                        ParseJson.JsonData jsonData = new ParseJson.JsonData()
                                        {
                                            IpAddress = ipAdcs,
                                            VulnerabilityName = "ESC13. Неправильно настроенная политика шаблона сертификатов",
                                            Description =
                                                "Обнаружен шаблон, у которого политика выдачи сертификата имеет ссылку на группу OID. " +
                                                "Такая конфигурация заставляет AD рассматривать принципалов, проходящих проверку подлинности " +
                                                "с помощью сертификата этого шаблона, как членов группы, даже если на самом деле принципалы не являются ее членами. " +
                                                "Уязвимый шаблон: " + templateName + ". Уязвимый объект: " + username,
                                            Recommendations =
                                                "Исправить политику шаблона сертификатов.",
                                            CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                            Level = "9.0",
                                            CVE = new String[] { },
                                            Links = new String[]
                                            {
                                                "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"
                                            }
                                        };
                                        ParseJson.AppendToJsonFile(jsonData);
                                    }*/
                                }
                                else
                                {
                                    ConsoleHelper.WriteColoredLine("\t    [X] Current user can't read attribute nTSecurityDescriptor\n", ConsoleColor.Red);
                                }
                            }
                            catch (InvalidCastException ex)
                            {
                                ConsoleHelper.WriteColoredLine($"\t[X] Error: {ex.Message} Linux не может обработать Security Descriptor", ConsoleColor.Red);
                            }
                        }
                        
                        // ESC5
                        if (userGroupSids.Contains("S-1-5-32-574"))
                        {
                            ConsoleHelper.WriteColoredLine($"\t[+] ESC5: {username} member of 'Certificate Service DCOM Access' group", ConsoleColor.Green);

                            ParseJson.JsonData jsonData = new ParseJson.JsonData()
                            {
                                IpAddress = ipAdcs,
                                VulnerabilityName = "ESC5. Пользователь входит в группу 'Certificate Service DCOM Access'",
                                Description =
                                    "Текущий пользователь '" + username + "' входит в группу 'Certificate Service DCOM Access', " +
                                    "которая дает право на регистрацию шаблонов сертификатов и на выпуск сертификатов",
                                Recommendations = "Удалить пользователя '" + username + "' из группы 'Certificate Service DCOM Access'.",
                                CVSSv2 = "AV:N/AC:L/Au:S/C:C/I:C/A:C",
                                Level = "9.0",
                                CVE = new String[] { },
                                Links = new String[]
                                {
                                    "https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c"
                                }
                            };
                            ParseJson.AppendToJsonFile(jsonData);
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