const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    // SSRF Protection: Allowlist of permitted stock API domains
    const ALLOWED_DOMAINS = [
        "finance.yahoo.com",
        "query1.finance.yahoo.com",
        "query2.finance.yahoo.com"
    ];

    /**
     * Validates URL to prevent SSRF attacks
     * @param {string} urlString - The URL to validate
     * @returns {boolean} - True if URL is safe, false otherwise
     */
    function isValidStockApiUrl(urlString) {
        try {
            const url = new URL(urlString);

            // Only allow HTTPS protocol for security
            if (url.protocol !== "https:") {
                return false;
            }

            // Check if hostname is in allowlist
            if (!ALLOWED_DOMAINS.includes(url.hostname)) {
                return false;
            }

            // Prevent access to private/internal IP ranges
            const hostname = url.hostname;

            // Block localhost variations
            if (hostname === "localhost" || hostname === "127.0.0.1" ||
                hostname === "0.0.0.0" || hostname.startsWith("127.") ||
                hostname === "::1" || hostname === "[::1]") {
                return false;
            }

            // Block private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
            const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            const ipMatch = hostname.match(ipv4Regex);
            if (ipMatch) {
                const [, oct1, oct2] = ipMatch.map(Number);
                if (oct1 === 10 ||
                    (oct1 === 172 && oct2 >= 16 && oct2 <= 31) ||
                    (oct1 === 192 && oct2 === 168)) {
                    return false;
                }
            }

            return true;
        } catch (e) {
            // Invalid URL format
            return false;
        }
    }

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            const url = req.query.url + req.query.symbol;

            // Validate URL to prevent SSRF attacks
            if (!isValidStockApiUrl(url)) {
                res.writeHead(400, {
                    "Content-Type": "text/html"
                });
                res.write("<h1>Invalid stock API URL. Only trusted stock data providers are allowed.</h1>");
                return res.end();
            }

            return needle.get(url, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
