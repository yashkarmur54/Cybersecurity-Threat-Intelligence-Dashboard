-- =====================================================================
-- Cybersecurity Threat Intelligence Dashboard  |  SQL script
-- Table: threat_incidents  (80,200 cleaned rows, 2020 to Sep 2026, synthetic data)
-- NOTE: 2026 is year-to-date (1 Jan - 30 Sep 2026). Use rates / averages, not totals, to compare it with full years.
-- Tested on SQLite; standard SQL (works on MySQL / PostgreSQL / SQL Server
-- with small date-function changes noted inline).
-- Load data: import 02_Dataset_Files/Processed_Dataset/processed_threat_incidents.csv
-- =====================================================================

-- 1) Schema --------------------------------------------------------------
DROP TABLE IF EXISTS threat_incidents;
CREATE TABLE threat_incidents (
    Incident_ID          VARCHAR(12) PRIMARY KEY,
    Detected_Date        DATE,
    Threat_Category      VARCHAR(30),   -- Phishing, Malware, Ransomware, DDoS, Insider Threat, Web App Attack
    Sub_Type             VARCHAR(40),
    Severity             VARCHAR(10),   -- Critical, High, Medium, Low
    Source_Country       VARCHAR(30),
    Target_Industry      VARCHAR(30),
    Attack_Origin        VARCHAR(10),   -- External / Internal
    Detection_Source     VARCHAR(25),   -- SIEM, EDR, IDS/IPS, Threat Intel Feed, User Report, Firewall
    Status               VARCHAR(25),   -- Mitigated, Contained, Under Investigation, Open
    Detection_Time_Min   INT,
    Response_Time_Min    INT,
    Affected_Systems     INT,
    Data_Compromised_MB  DECIMAL(12,1),
    Financial_Impact_USD DECIMAL(14,2),
    Analyst_Team         VARCHAR(20),
    Year                 INT,
    Month                INT,
    Month_Name           VARCHAR(3),
    SLA_Target_Min       INT,
    SLA_Met              VARCHAR(3),
    Is_Mitigated         INT
);
-- SQLite : .mode csv  /  .import --skip 1 processed_threat_incidents.csv threat_incidents
-- MySQL  : LOAD DATA INFILE ... IGNORE 1 LINES;   PostgreSQL: \copy threat_incidents FROM '...' CSV HEADER

-- 2) Headline KPIs by year (matches the left panel + centre ring) --------
--    (2026 = Jan-Sep only, so avg_response_hrs, mitigation_rate_pct and sla_met_pct stay comparable)
SELECT Year,
       COUNT(*)                                         AS total_incidents,
       SUM(Is_Mitigated)                                AS mitigated,
       ROUND(100.0*SUM(Is_Mitigated)/COUNT(*),1)        AS mitigation_rate_pct,
       ROUND(AVG(Response_Time_Min)/60.0,2)             AS avg_response_hrs,
       ROUND(AVG(Detection_Time_Min),1)                 AS avg_detection_min,
       ROUND(100.0*SUM(CASE WHEN SLA_Met='Yes' THEN 1 ELSE 0 END)/COUNT(*),1) AS sla_met_pct,
       ROUND(SUM(Financial_Impact_USD)/1000000.0,2)     AS est_impact_musd
FROM threat_incidents GROUP BY Year ORDER BY Year;

-- 3) Threat category bubbles (share + mitigation rate) --------------------
SELECT Year, Threat_Category,
       COUNT(*) AS incidents,
       ROUND(100.0*COUNT(*)/SUM(COUNT(*)) OVER (PARTITION BY Year),1) AS share_pct,
       ROUND(100.0*SUM(Is_Mitigated)/COUNT(*),1) AS mitigation_rate_pct
FROM threat_incidents GROUP BY Year, Threat_Category ORDER BY Year, incidents DESC;

-- 4) Sub-type hubs (percent of parent category), latest year = 2026 YTD -----
SELECT Threat_Category, Sub_Type, COUNT(*) AS incidents,
       ROUND(100.0*COUNT(*)/SUM(COUNT(*)) OVER (PARTITION BY Threat_Category),0) AS pct_of_category
FROM threat_incidents WHERE Year = 2026
GROUP BY Threat_Category, Sub_Type ORDER BY Threat_Category, incidents DESC;

-- 5) Monthly trend (sparkline) and mean time to respond (right card) -------
SELECT Year, Month, Month_Name, COUNT(*) AS incidents,
       ROUND(AVG(Response_Time_Min)/60.0,2) AS mttr_hrs
FROM threat_incidents GROUP BY Year, Month, Month_Name ORDER BY Year, Month;

-- 6) Severity split (left panel list) -------------------------------------
SELECT Year, Severity, COUNT(*) AS incidents,
       ROUND(100.0*COUNT(*)/SUM(COUNT(*)) OVER (PARTITION BY Year),0) AS pct
FROM threat_incidents GROUP BY Year, Severity
ORDER BY Year, CASE Severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END;

-- 7) Geography: top attack source countries (2026 YTD) ---------------------
SELECT Source_Country, COUNT(*) AS incidents,
       ROUND(100.0*COUNT(*)/(SELECT COUNT(*) FROM threat_incidents WHERE Year=2026),1) AS pct
FROM threat_incidents WHERE Year = 2026 AND Source_Country <> 'Unknown'
GROUP BY Source_Country ORDER BY incidents DESC LIMIT 10;

-- 8) Targeted industries (all years, 2020 to Sep 2026) --------------------
SELECT Target_Industry, COUNT(*) AS incidents, ROUND(SUM(Financial_Impact_USD)/1000000.0,2) AS impact_musd
FROM threat_incidents WHERE Target_Industry <> 'Unknown'
GROUP BY Target_Industry ORDER BY incidents DESC;

-- 9) Response funnel: detected -> triaged -> contained -> mitigated ---------
SELECT Year,
       COUNT(*)                                                         AS detected,
       SUM(CASE WHEN Status <> 'Open' THEN 1 ELSE 0 END)                AS triaged,
       SUM(CASE WHEN Status IN ('Contained','Mitigated') THEN 1 ELSE 0 END) AS contained,
       SUM(Is_Mitigated)                                                AS mitigated
FROM threat_incidents GROUP BY Year ORDER BY Year;

-- 10) Detection source performance ----------------------------------------
SELECT Detection_Source, COUNT(*) AS incidents,
       ROUND(AVG(Detection_Time_Min),1) AS avg_detection_min
FROM threat_incidents GROUP BY Detection_Source ORDER BY incidents DESC;

-- 11) Severity x status heat grid (2026 YTD) ------------------------------
SELECT Severity, Status, COUNT(*) AS incidents
FROM threat_incidents WHERE Year = 2026 GROUP BY Severity, Status ORDER BY Severity, Status;

-- 12) External vs internal origin (right ring card) -----------------------
SELECT Year, Attack_Origin, COUNT(*) AS incidents,
       ROUND(100.0*COUNT(*)/SUM(COUNT(*)) OVER (PARTITION BY Year),2) AS pct
FROM threat_incidents GROUP BY Year, Attack_Origin ORDER BY Year, Attack_Origin;

-- 13) Data-quality checks (should return 0 rows / 0) -----------------------
SELECT COUNT(*) - COUNT(DISTINCT Incident_ID) AS duplicate_ids FROM threat_incidents;
SELECT COUNT(*) AS bad_response_times FROM threat_incidents WHERE Response_Time_Min <= 0 OR Response_Time_Min > 5000;
