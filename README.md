FinVerify


FinVerify is an automated, high-performance .NET Background Worker Service designed to scrape, extract, and synchronize the Reserve Bank of India (RBI) Non-Banking Financial Company (NBFC) registries. It dynamically processes structured Excel data streams and maintains up-to-date compliance records directly within a SQL Server database, serving as a reliable data source for real-time risk mitigation and background credit validation workflows.

🚀 Key Features
Automated Background Ingestion: Runs continuously as a lightweight .NET background service (BackgroundService) with a configurable synchronization interval.

Smart Schema Routing: Detects spreadsheet layouts at runtime by evaluating specific row definitions to cleanly split records into dedicated active (RbiRegisteredNbfc) and cancelled (RbiCancelledNbfc) database tables.

WAF & Anti-Bot Resilience: Implements customized HttpClient network footprints, browser header emulation, and dynamic throttling delays to gracefully bypass enterprise Web Application Firewall (WAF) rate limits.

Fault-Tolerant File Parsing: Employs byte-signature validation checks to intercept corrupt HTML challenge pages or network drops before they reach the data extraction layer.

High-Performance Streaming: Utilizes ExcelDataReader to read heavy spreadsheet matrices directly from streams, optimizing memory allocation.

🏗️ Architecture & Data Pipeline
Scraping Phase: The service queries the RBI registry index page, using HtmlAgilityPack to extract relative anchor points for active and cancelled document links.

Validation Phase: Incoming data bytes are inspected for universal magic number file signatures (PK zip wrappers or OLE formats) to filter out deceptive firewall interception text.

Dynamic Mapping Layer: Column index matrices are computed dynamically from header row texts, ensuring columns like Sr. No. are skipped and valuable data layers match internal destination rules natively.

Database Storage Phase: Structured records are transactionally committed to SQL Server using parameter-driven queries to protect against SQL injection vulnerabilities.

🛠️ Tech Stack & Dependencies
Runtime environment: .NET 8.0+

Database Provider: SQL Server / Azure SQL

Core Libraries:

Microsoft.Data.SqlClient - Production-grade SQL Server data client connection management.

ExcelDataReader - Lightweight, low-memory binary Excel file stream reader.

HtmlAgilityPack - HTML document object parser for web scraping.


🗄️ Database Schema Initialization
Execute the following SQL script to create the structured target entities inside your database:

SQL
-- Table for Case 1: Active Registered NBFCs
CREATE TABLE dbo.RbiRegisteredNbfc (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    NbfcName NVARCHAR(500) NOT NULL,
    RegionalOffice NVARCHAR(250) NULL,
    WhetherHaveCoRForHoldingAcceptingPublicDeposits NVARCHAR(100) NULL,
    Classification NVARCHAR(250) NULL,
    CorporateIdentificationNumber NVARCHAR(100) NULL,
    Layer NVARCHAR(100) NULL,
    Address NVARCHAR(MAX) NULL,
    EmailID NVARCHAR(250) NULL,
    SourceUrl NVARCHAR(1000) NULL,
    ImportedAt DATETIME2 DEFAULT SYSUTCDATETIME()
);

-- Table for Case 2: Cancelled CoR Companies
CREATE TABLE dbo.RbiCancelledNbfc (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    NameOfTheCompany NVARCHAR(500) NOT NULL,
    RegionalOffice NVARCHAR(250) NULL,
    Address NVARCHAR(MAX) NULL,
    SourceUrl NVARCHAR(1000) NULL,
    ImportedAt DATETIME2 DEFAULT SYSUTCDATETIME()
);
