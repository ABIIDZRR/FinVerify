using System.Net;
using HtmlAgilityPack;
using ExcelDataReader;
using Microsoft.Data.SqlClient;

namespace FinVerify.API.BackgroundServices
{
    public class RbiScraperWorker : BackgroundService
    {
        private readonly ILogger<RbiScraperWorker> _logger;
        private readonly HttpClient _httpClient;
        private const string RbiPageUrl = "https://rbi.org.in/Scripts/BS_NBFCList.aspx";
        private readonly string _connectionString;

        // Using 10 seconds for local debugging; change to TimeSpan.FromHours(24) for production
        private readonly TimeSpan _runInterval = TimeSpan.FromHours(5);

        public RbiScraperWorker(ILogger<RbiScraperWorker> logger, IConfiguration configuration)
        {
            _logger = logger;

            // 1. Setup a persistent cookie container to capture and reply to firewall tokens
            var cookieContainer = new CookieContainer();

            _connectionString = configuration.GetConnectionString("DefaultConnection");

            var handler = new HttpClientHandler()
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
                UseCookies = true,
                CookieContainer = cookieContainer,
                AllowAutoRedirect = true
            };

            // 2. Instantiate client with the configured handler
            _httpClient = new HttpClient(handler);

            // 3. Emulate a standard Windows Desktop Chrome footprint to clear security checks
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");

            // Explicitly ask for the OpenXML spreadsheet types along with HTML targets
            _httpClient.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,*/*;q=0.8");
            _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
            _httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua", "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\"");
            _httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua-Mobile", "?0");
            _httpClient.DefaultRequestHeaders.Add("Sec-Ch-Ua-Platform", "\"Windows\"");

            // 🔥 NEW CRITICAL WAF METRICS: Tell the security engine this is a safe, browser-driven click tracking navigation
            _httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "document");
            _httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "navigate");
            _httpClient.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
            _httpClient.DefaultRequestHeaders.Add("Sec-Fetch-User", "?1");
            _httpClient.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");

            // Register encoding provider to handle legacy Excel formatting (.xls) natively     
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("RBI Scraper Background Service Started.");

            // First run on startup
            await ScrapeAndProcessRbiDataAsync();

            using var timer = new PeriodicTimer(_runInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken) && !stoppingToken.IsCancellationRequested)
            {
                await ScrapeAndProcessRbiDataAsync();
            }
        }

        private async Task ScrapeAndProcessRbiDataAsync()
        {
            _logger.LogInformation("Initiating automated scraping on RBI NBFC repository...");

            try
            {
                _httpClient.DefaultRequestHeaders.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };

                string htmlContent = await _httpClient.GetStringAsync(RbiPageUrl);

                if (string.IsNullOrEmpty(htmlContent))
                {
                    _logger.LogError("Scraper stopped: Received empty HTML response from the server.");
                    return;
                }

                var htmlDoc = new HtmlDocument();
                htmlDoc.LoadHtml(htmlContent);

                // CASE-INSENSITIVE XPATH: Targets any casing variants of .xls or .xlsx documents
                var excelNodes = htmlDoc.DocumentNode.SelectNodes(
                    "//a[contains(translate(@href, 'XLS', 'xls'), '.xlsx') or contains(translate(@href, 'XLS', 'xls'), '.xls')]"
                );

                if (excelNodes == null || excelNodes.Count == 0)
                {
                    _logger.LogWarning("Scraper suspended: 0 Excel links discovered. HTML Length: {Length}.", htmlContent.Length);
                    return;
                }

                _logger.LogInformation("Successfully extracted {Count} live Excel nodes from layout.", excelNodes.Count);

                int processedCount = 0;
                foreach (var node in excelNodes)
                {
                    string relativeUrl = node.GetAttributeValue("href", "");
                    if (string.IsNullOrEmpty(relativeUrl)) continue;

                    string absoluteExcelUrl = new Uri(new Uri(RbiPageUrl), relativeUrl).AbsoluteUri;
                    string nodeText = node.InnerText.ToLower().Trim();
                    string lowerUrl = relativeUrl.ToLower();

                    // 1. Explicitly isolate the target groups you want to process
                    bool isNonDeposit = nodeText.Contains("not accepting") ||
                                        nodeText.Contains("non-deposit") ||
                                        lowerUrl.Contains("non_deposit") ||
                                        lowerUrl.Contains("not_accepting");

                    bool isDeposit = nodeText.Contains("accepting public") ||
                                     nodeText.Contains("permitted") ||
                                     lowerUrl.Contains("accept_deposit");

                    bool isCancelled = nodeText.Contains("cancelled") ||
                                       lowerUrl.Contains("cancelled");

                    // 2. Route only valid datasets and ignore random noise links on the page
                    if (isNonDeposit || isDeposit || isCancelled)
                    {
                        if (isCancelled)
                        {
                            _logger.LogInformation("🎯 Routing Target -> Cancelled CoR Registry Sheet.");
                        }
                        else
                        {
                            _logger.LogInformation("🎯 Routing Target -> Active Registered NBFC Sheet.");
                        }

                        // Execute the processing handler
                        await DownloadAndParseExcelAsync(absoluteExcelUrl);
                        processedCount++;

                        // 3. 🔥 THE CRITICAL ANTI-BOT THROTTLE
                        // Pause the thread for a random window between 4 to 8 seconds to mimic human navigation spacing
                        int dynamicDelay = new Random().Next(4000, 8000);
                        _logger.LogInformation("⏳ Cooling down for {Seconds}s to protect the IP profile from WAF thresholds...", dynamicDelay / 1000.0);
                        await Task.Delay(dynamicDelay);
                    }
                    else
                    {
                        _logger.LogDebug("Skipping un-targeted document link layout: {Url}", relativeUrl);
                    }
                }

                _logger.LogInformation("Scraping complete. Processed and parsed {Count} data streams.", processedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "The master scraping execution cycle failed.");
            }
        }

        private async Task DownloadAndParseExcelAsync(string excelUrl)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, excelUrl);
                request.Headers.Add("Referer", RbiPageUrl);

                using var response = await _httpClient.SendAsync(request);

                // Log the status code immediately to see what the server is doing
                _logger.LogInformation("📡 HTTP Response Code for {Url}: {StatusCode}", excelUrl, response.StatusCode);

                if (response.StatusCode == HttpStatusCode.Forbidden || response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    _logger.LogError("⛔ The RBI server actively rejected the connection (403 Forbidden). IP block is still active.");
                    return;
                }

                response.EnsureSuccessStatusCode();
                byte[] fileBytes = await response.Content.ReadAsByteArrayAsync();

                // 🛑 GUARD CLAUSE: Detect if the file is an HTML block rather than an Excel file
                if (fileBytes.Length >= 4 && fileBytes[0] == 0x3C && fileBytes[1] == 0x21 && fileBytes[2] == 0x44)
                {
                    _logger.LogWarning("⚠️ Encountered WAF challenge page. Attempting direct fallback route for Cancelled Registry...");

                    // The raw binary files on RBI's content server often use lowercase extension handling 
                    // or live inside the 'Documents' directory instead of 'rdocs'. Let's switch to the direct secure asset path:
                    if (excelUrl.Contains("List_of_NBFCs_and_ARCs_whose_CoR_has_been_cancelled_by_the_RBI", StringComparison.OrdinalIgnoreCase))
                    {
                        // Force the URL to point directly to the static asset mirror bypass link
                        excelUrl = "https://rbi.org.in/Scripts/bs_viewcontent.aspx?Id=3465"; // Permanent view link for cancelled assets

                        _logger.LogInformation("🔄 Rerouting request path to static asset portal: {Url}", excelUrl);

                        // Re-issue a clean browser request to the direct viewer link
                        using var fallbackRequest = new HttpRequestMessage(HttpMethod.Get, excelUrl);
                        fallbackRequest.Headers.Add("Referer", RbiPageUrl);
                        using var fallbackResponse = await _httpClient.SendAsync(fallbackRequest);
                        fileBytes = await fallbackResponse.Content.ReadAsByteArrayAsync();
                    }

                    // Double-check if the fallback also failed
                    if (fileBytes[0] == 0x3C && fileBytes[1] == 0x21 && fileBytes[2] == 0x44)
                    {
                        _logger.LogError("🛑 WAF block remains active on the network interface. Skipping parsing for this file.");
                        return;
                    }
                }

                string folderPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Downloads", "RbiFiles");
                Directory.CreateDirectory(folderPath);

                string safeTimestamp = DateTime.Now.ToString("yyyyMMdd_HHmmssfff");
                string fileExtension = excelUrl.ToLower().Contains(".xlsx") ? ".xlsx" : ".xls";
                string filename = $"RBI_RawPayload_{safeTimestamp}{fileExtension}";
                string fullFilePath = Path.Combine(folderPath, filename);

                await File.WriteAllBytesAsync(fullFilePath, fileBytes);

                using FileStream fileStream = new FileStream(fullFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var reader = ExcelReaderFactory.CreateReader(fileStream);

                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // Execution Routing Flags
                int fileCaseType = 0; // 1 = Registered, 2 = Cancelled
                int rowCount = 0;
                int insertedCount = 0;

                // Dynamic Mapping Arrays to find exact column numbers based on Row 2 definitions
                int idxName = -1, idxRegional = -1, idxDeposit = -1, idxClassification = -1;
                int idxCin = -1, idxLayer = -1, idxAddress = -1, idxEmail = -1;

                while (reader.Read())
                {
                    rowCount++;

                    // ==========================================
                    // STRICT CONDITION 1: EVALUATE ROW 1 HEADING
                    // ==========================================
                    if (rowCount == 1)
                    {
                        string row1Col1 = reader.GetValue(0)?.ToString()?.Trim() ?? "";
                        string row1Col2 = reader.GetValue(1)?.ToString()?.Trim() ?? "";

                        // Case 1 Check
                        if (row1Col1.Contains("List of NBFCs registered with the RBI", StringComparison.OrdinalIgnoreCase))
                        {
                            fileCaseType = 1;
                            _logger.LogInformation("🎯 Strictly Identified [CASE 1]: Registered NBFC Master Sheet.");

                            // Clear older table records before streaming fresh data
                            using var truncateCmd = new SqlCommand("TRUNCATE TABLE dbo.RbiRegisteredNbfc;", connection);
                            await truncateCmd.ExecuteNonQueryAsync();
                        }
                        // Case 2 Check: As per note, heading shifts to 2nd column
                        else if (row1Col2.Contains("List of NBFCs and ARCs whose CoR has been cancelled", StringComparison.OrdinalIgnoreCase))
                        {
                            fileCaseType = 2;
                            _logger.LogInformation("🎯 Strictly Identified [CASE 2]: Cancelled CoR Master Sheet.");

                            // Clear older table records before streaming fresh data
                            using var truncateCmd = new SqlCommand("TRUNCATE TABLE dbo.RbiCancelledNbfc;", connection);
                            await truncateCmd.ExecuteNonQueryAsync();
                        }

                        if (fileCaseType == 0)
                        {
                            _logger.LogWarning("Skipping non-matching spreadsheet asset payload: {Url}", excelUrl);
                            return; // Terminates execution if Row 1 doesn't exactly match your rules
                        }
                        continue;
                    }

                    // ==========================================
                    // STRICT CONDITION 2: EVALUATE ROW 2 HEADERS
                    // ==========================================
                    if (rowCount == 2)
                    {
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (i == 0) continue; // Rules check: Skip first column (Index 0) as it is Sl number

                            string headerText = reader.GetValue(i)?.ToString()?.Trim() ?? "";

                            if (fileCaseType == 1)
                            {
                                if (headerText.Equals("NBFC Name", StringComparison.OrdinalIgnoreCase)) idxName = i;
                                else if (headerText.Equals("Regional Office", StringComparison.OrdinalIgnoreCase)) idxRegional = i;
                                else if (headerText.Equals("Whether have CoR for holding/ Accepting Public Deposits", StringComparison.OrdinalIgnoreCase)) idxDeposit = i;
                                else if (headerText.Equals("Classification", StringComparison.OrdinalIgnoreCase)) idxClassification = i;
                                else if (headerText.Equals("Corporate Identification Number", StringComparison.OrdinalIgnoreCase)) idxCin = i;
                                else if (headerText.Equals("Layer", StringComparison.OrdinalIgnoreCase)) idxLayer = i;
                                else if (headerText.Equals("Address", StringComparison.OrdinalIgnoreCase)) idxAddress = i;
                                else if (headerText.Equals("Email ID", StringComparison.OrdinalIgnoreCase)) idxEmail = i;
                            }
                            else if (fileCaseType == 2)
                            {
                                if (headerText.Equals("Name of the company", StringComparison.OrdinalIgnoreCase)) idxName = i;
                                else if (headerText.Equals("Regional Office", StringComparison.OrdinalIgnoreCase)) idxRegional = i;
                                else if (headerText.Equals("Address", StringComparison.OrdinalIgnoreCase)) idxAddress = i;
                            }
                        }
                        continue;
                    }

                    // ==========================================
                    // ROW 3+: STRICT DATA INGESTION & INSERTION
                    // ==========================================
                    string companyName = idxName != -1 ? reader.GetValue(idxName)?.ToString()?.Trim() : null;
                    if (string.IsNullOrEmpty(companyName) || companyName.Equals("NBFC Name", StringComparison.OrdinalIgnoreCase) || companyName.Equals("Name of the company", StringComparison.OrdinalIgnoreCase))
                        continue; // Skip padding/empty lines

                    if (fileCaseType == 1)
                    {
                        string insertSql1 = @"
                    INSERT INTO dbo.RbiRegisteredNbfc (NbfcName, RegionalOffice, WhetherHaveCoRForHoldingAcceptingPublicDeposits, Classification, CorporateIdentificationNumber, Layer, Address, EmailID, SourceUrl)
                    VALUES (@NbfcName, @RegionalOffice, @WhetherHaveCoRForHoldingAcceptingPublicDeposits, @Classification, @CorporateIdentificationNumber, @Layer, @Address, @EmailID, @SourceUrl);";

                        using var cmd = new SqlCommand(insertSql1, connection);
                        cmd.Parameters.AddWithValue("@NbfcName", companyName);
                        cmd.Parameters.AddWithValue("@RegionalOffice", (object)(idxRegional != -1 ? reader.GetValue(idxRegional)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@WhetherHaveCoRForHoldingAcceptingPublicDeposits", (object)(idxDeposit != -1 ? reader.GetValue(idxDeposit)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@Classification", (object)(idxClassification != -1 ? reader.GetValue(idxClassification)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@CorporateIdentificationNumber", (object)(idxCin != -1 ? reader.GetValue(idxCin)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@Layer", (object)(idxLayer != -1 ? reader.GetValue(idxLayer)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@Address", (object)(idxAddress != -1 ? reader.GetValue(idxAddress)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@EmailID", (object)(idxEmail != -1 ? reader.GetValue(idxEmail)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@SourceUrl", excelUrl);

                        await cmd.ExecuteNonQueryAsync();
                        insertedCount++;
                    }
                    else if (fileCaseType == 2)
                    {
                        string insertSql2 = @"
                    INSERT INTO dbo.RbiCancelledNbfc (NameOfTheCompany, RegionalOffice, Address, SourceUrl)
                    VALUES (@NameOfTheCompany, @RegionalOffice, @Address, @SourceUrl);";

                        using var cmd = new SqlCommand(insertSql2, connection);
                        cmd.Parameters.AddWithValue("@NameOfTheCompany", companyName);
                        cmd.Parameters.AddWithValue("@RegionalOffice", (object)(idxRegional != -1 ? reader.GetValue(idxRegional)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@Address", (object)(idxAddress != -1 ? reader.GetValue(idxAddress)?.ToString()?.Trim() : null) ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@SourceUrl", excelUrl);

                        await cmd.ExecuteNonQueryAsync();
                        insertedCount++;
                    }
                }

                _logger.LogInformation("✅ Completed. Case Processing Type: {Case} | Records Added: {Count}", fileCaseType, insertedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed executing structural processing loop for: {Url}", excelUrl);
            }
        }
    }
}
