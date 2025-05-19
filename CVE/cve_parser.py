import requests
import pandas as pd
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.styles import Alignment, Font
import argparse

# Парсинг аргументов
parser = argparse.ArgumentParser(description="Парсинг CVE по ключевым словам и сохранение в Excel.")
parser.add_argument("keywords", help="Ключевые слова через запятую (например, 'mikrotik,routeros,winbox')")
args = parser.parse_args()

# Разбиваем по запятой и убираем пробелы
keywords = [kw.strip() for kw in args.keywords.split(",") if kw.strip()]

results = []

# Обработка каждого ключевого слова
for keyword in keywords:
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 2000
    }

    response = requests.get(API_URL, params=params)
    data = response.json()

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # Описание
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Модели
        models = set()
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    uri = cpe.get("criteria", "")
                    if uri.startswith("cpe:2.3"):
                        parts = uri.split(":")
                        if len(parts) > 4:
                            models.add(parts[4])

        # Оценка критичности
        score = None
        metrics = cve.get("metrics", {})
        if "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", None)
        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", None)
        elif "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", None)

        results.append({
            "Модель": "\n".join(sorted(models)) if models else "Не указано",
            "Критичность": score if score is not None else "Нет данных",
            "CVE": cve_id,
            "Описание": description
        })

# Создание DataFrame
df = pd.DataFrame(results, columns=["Модель", "Критичность", "CVE", "Описание"])
df.drop_duplicates(inplace=True)

# Сохранение в Excel
wb = Workbook()
ws = wb.active
ws.title = "CVE Report"

for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), 1):
    for c_idx, value in enumerate(row, 1):
        cell = ws.cell(row=r_idx, column=c_idx, value=value)
        cell.alignment = Alignment(vertical="top", wrap_text=True)
        if r_idx == 1:
            cell.font = Font(bold=True)

filename = "_".join(keywords) + ".xlsx"
wb.save(filename)
print(f"Файл сохранен как {filename}")