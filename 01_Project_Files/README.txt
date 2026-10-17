Cybersecurity Threat Intelligence Dashboard
===========================================
dashboard.html        Interactive dashboard. Double-click to open in Chrome or Edge (no internet needed).
                      Use the year buttons (2020-2026) and the four tabs: Threat Categories,
                      Geographically, Detection Process, Incident Status. Hover for tooltips.
                      2026 is marked with an asterisk: it covers January to September only (year to date).
threat_intel_workbook.xlsx   Excel workbook: Raw_Data (81,403 rows), Processed_Data (80,200 rows) and
                      KPI, category and monthly summary sheets (live formulas on the 80,200 cleaned rows).
threat_intel_sql.sql         Table schema and 13 KPI / data-quality queries (tested on SQLite).
data_generation_and_cleaning.py   Python script that generates the raw data and cleans it.
                      2020-2024 = original batch (seed 2026, unchanged), 2025-2026 = extension batch (seed 2027).

Dataset: synthetic (seeded random generation), 81,403 raw rows -> 80,200 cleaned rows, 2020 to Sep 2026.
2020-2025 are full years; 2026 is year to date (incidents detected 1 Jan - 30 Sep 2026), so compare it with
full years using rates and averages, not totals. The 2020-2024 records and figures are identical to the
previous version of this package; 2025 (16,000 incidents) and 2026 YTD (12,600 incidents) were added.
No real organisations or people. Results demonstrate the method, not real-world statistics.

Other files: raw_threat_incidents.csv, processed_threat_incidents.csv, Project_Report.pdf,
Dashboard_Screenshots.pdf (10 pages), the PNG screenshots 01-10, dashboard_demo.mp4 and the PowerPoint deck.

Note: this package does not include a Power BI .pbix file. The same measures and layout can be rebuilt in
Power BI Desktop from 02_Dataset_Files/Processed_Dataset/processed_threat_incidents.csv.
