using System.IO;
using Newtonsoft.Json;

namespace ADPwn
{
    public abstract class ParseJson
    {
        public class JsonData
        {
            public string IpAddress { get; set; }
            public string Port { get; set; }
            public string ServiceName { get; set; }
            public string HostName { get; set; }
            public string OperatingSystem { get; set; }
            public string VulnerabilityName { get; set; }
            public string Description { get; set; }
            public string Recommendations { get; set; }
            public string CVSSv2 { get; set; }
            public string Level { get; set; }
            public string[] CVE { get; set; }
            public string[] Links { get; set; }
        }

        public static void AppendToJsonFile(object jsonData)
        {
            string domain = ConsoleHelper.DomainProvider.Domain;
            string filePath = $"{domain}_jsonData.json";
            
            // Проверка на существование файла и создание начальной структуры массива, если файл не существует
            if (!File.Exists(filePath)) {
                File.WriteAllText(filePath, "[]");
            }

            string existingJson = File.ReadAllText(filePath);
            string newJson = JsonConvert.SerializeObject(jsonData);

            // Удаление последней закрывающей скобки массива
            existingJson = existingJson.TrimEnd(']');
            // Добавление запятой перед новым объектом, если это не первый объект в массиве
            if (existingJson.Length > 1) {
                existingJson += ",";
            }
            // Добавление нового объекта и закрывающей скобки
            existingJson += newJson + "]";

            File.WriteAllText(filePath, existingJson);
        }
    }
}