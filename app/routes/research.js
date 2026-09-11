const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

// Allowlist of permitted hosts for outbound stock-quote requests.
// Only these hostnames may be contacted — user-supplied URL base values are ignored.
const ALLOWED_STOCK_HOSTS = ["finance.yahoo.com"];

// The fixed base URL used for all stock-quote lookups.
const STOCK_BASE_URL = "https://finance.yahoo.com/quote/";

// Stock ticker symbols: 1–10 uppercase or lowercase ASCII letters only.
// This matches NYSE/NASDAQ/etc. ticker conventions and rejects any path-traversal
// or injection characters before the value is used in the URL.
const SYMBOL_PATTERN = /^[A-Za-z]{1,10}$/;

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            const symbol = req.query.symbol;

            // Validate the symbol against the strict allowlist pattern.
            // Reject anything that does not look like a real stock ticker.
            if (!SYMBOL_PATTERN.test(symbol)) {
                return res.status(400).send("Invalid stock symbol.");
            }

            // Build the outbound URL from the fixed base — never from user-supplied input.
            // Using new URL() with a hard-coded base ensures the stdlib URL parser
            // resolves the path; only the validated symbol is appended.
            const parsedUrl = new URL(symbol, STOCK_BASE_URL);

            // Confirm the resolved host is in the allowlist (defence-in-depth).
            if (!ALLOWED_STOCK_HOSTS.includes(parsedUrl.hostname)) {
                return res.status(400).send("Request target is not permitted.");
            }

            const url = parsedUrl.toString();

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
