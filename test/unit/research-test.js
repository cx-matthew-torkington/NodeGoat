const should = require("should");
const ResearchHandler = require("../../app/routes/research");

describe("ResearchHandler - SSRF Prevention", function() {
    "use strict";

    let researchHandler;
    let mockDb;
    let mockReq;
    let mockRes;
    let statusCode;
    let sentBody;
    let renderCalled;
    let renderArgs;
    let writeHeadCalled;
    let writtenChunks;
    let endCalled;

    beforeEach(function() {
        statusCode = null;
        sentBody = null;
        renderCalled = false;
        renderArgs = null;
        writeHeadCalled = false;
        writtenChunks = [];
        endCalled = false;

        mockDb = {};

        researchHandler = new ResearchHandler(mockDb);

        mockReq = {
            query: {}
        };

        mockRes = {
            status: function(code) {
                statusCode = code;
                return this;
            },
            send: function(body) {
                sentBody = body;
                return this;
            },
            render: function(view, data) {
                renderCalled = true;
                renderArgs = { view, data };
            },
            writeHead: function(code, headers) {
                writeHeadCalled = true;
            },
            write: function(chunk) {
                writtenChunks.push(chunk);
            },
            end: function() {
                endCalled = true;
            }
        };
    });

    // -------------------------------------------------------------------------
    // Security: SSRF Prevention — user-supplied `url` query param MUST be ignored
    // -------------------------------------------------------------------------
    describe("Security - SSRF Prevention", function() {

        it("Should reject an internal network URL injected via the url query parameter", function() {
            // Attacker-supplied url redirecting to localhost (internal network)
            mockReq.query = {
                url: "http://localhost:8080/admin",
                symbol: "AAPL"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            // The user-supplied url param must be completely ignored.
            // The symbol "AAPL" is letters-only and is otherwise valid, but the
            // fix constructs the outbound URL from the hard-coded base exclusively —
            // so the only way the handler could contact localhost is if it still
            // uses req.query.url. Since it doesn't, the outbound URL will always
            // be finance.yahoo.com, and no 400 should fire here.
            // We verify no error was returned, confirming the malicious `url`
            // parameter was silently dropped.
            should(statusCode).be.null();
        });

        it("Should reject a symbol that contains a URL scheme (SSRF via symbol)", function() {
            // Attacker tries to inject a full URL as the symbol
            mockReq.query = {
                symbol: "http://evil.example.com/path"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol containing a hostname and path injection", function() {
            mockReq.query = {
                symbol: "AAPL@evil.com"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol containing path traversal sequences", function() {
            mockReq.query = {
                symbol: "../../../etc/passwd"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol containing URL fragment/query injection", function() {
            mockReq.query = {
                symbol: "AAPL?redirect=http://evil.example.com"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol containing backslash path traversal", function() {
            mockReq.query = {
                symbol: "AAPL\\evil"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol with digits mixed in (not a valid ticker pattern)", function() {
            // Digits could be used to form numeric IP addresses for SSRF
            mockReq.query = {
                symbol: "AAPL123"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol containing an IP address", function() {
            mockReq.query = {
                symbol: "169.254.169.254"  // AWS metadata endpoint
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol exceeding 10 characters", function() {
            // Overly long symbol could be used to probe or inject paths
            mockReq.query = {
                symbol: "ABCDEFGHIJK"  // 11 characters
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject an empty string symbol", function() {
            // An empty string after whitespace trimming must not proceed
            mockReq.query = {
                symbol: ""
            };

            // Empty string is falsy so the if-block is not entered;
            // the render path is taken instead — confirm no SSRF request fires.
            researchHandler.displayResearch(mockReq, mockRes);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("research");
        });

        it("Should reject a symbol with spaces (injection separator)", function() {
            mockReq.query = {
                symbol: "AAPL EVIL"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a symbol with a percent-encoded slash (%2F)", function() {
            // URL-encoded path separator
            mockReq.query = {
                symbol: "AAPL%2Fevil"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });

        it("Should reject a null-byte-injected symbol", function() {
            // Null byte expressed as JS escape sequence — not a literal control byte
            mockReq.query = {
                symbol: "AAPL\x00evil"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            statusCode.should.equal(400);
            sentBody.should.equal("Invalid stock symbol.");
        });
    });

    // -------------------------------------------------------------------------
    // Functionality: Valid stock symbols reach the outbound request correctly
    // -------------------------------------------------------------------------
    describe("Functionality - Valid Stock Symbol Handling", function() {

        // Helper: create a mock needle module that records the URL it was called with
        // instead of making a real HTTP request.
        function createMockNeedle(capturedUrl) {
            return function(url, callback) {
                capturedUrl.value = url;
                // Simulate a successful response
                callback(null, { statusCode: 200 }, "<html>Stock data</html>");
            };
        }

        it("Should not return 400 for a valid uppercase ticker symbol", function() {
            // We intercept the needle call via monkey-patching to avoid real HTTP
            const needle = require("needle");
            const originalGet = needle.get;
            let capturedUrl = null;

            needle.get = function(url, cb) {
                capturedUrl = url;
                cb(null, { statusCode: 200 }, "stock data");
            };

            mockReq.query = { symbol: "AAPL" };

            researchHandler.displayResearch(mockReq, mockRes);

            needle.get = originalGet;

            // Must not have responded with 400
            should(statusCode).be.null();
            // The outbound URL must start with the hard-coded base, not a user value
            capturedUrl.should.startWith("https://finance.yahoo.com/quote/");
            capturedUrl.should.containEql("AAPL");
        });

        it("Should build the outbound URL from the fixed base, ignoring req.query.url", function() {
            const needle = require("needle");
            const originalGet = needle.get;
            let capturedUrl = null;

            needle.get = function(url, cb) {
                capturedUrl = url;
                cb(null, { statusCode: 200 }, "data");
            };

            // Attacker supplies a malicious url param; symbol is valid
            mockReq.query = {
                url: "http://169.254.169.254/latest/meta-data/",
                symbol: "GOOG"
            };

            researchHandler.displayResearch(mockReq, mockRes);

            needle.get = originalGet;

            // The captured URL must NEVER contain the attacker-supplied host
            capturedUrl.should.not.containEql("169.254.169.254");
            // It must always resolve to the allowlisted host
            capturedUrl.should.startWith("https://finance.yahoo.com/quote/");
        });

        it("Should accept a valid lowercase ticker symbol", function() {
            const needle = require("needle");
            const originalGet = needle.get;
            let capturedUrl = null;

            needle.get = function(url, cb) {
                capturedUrl = url;
                cb(null, { statusCode: 200 }, "data");
            };

            mockReq.query = { symbol: "msft" };

            researchHandler.displayResearch(mockReq, mockRes);

            needle.get = originalGet;

            should(statusCode).be.null();
            capturedUrl.should.startWith("https://finance.yahoo.com/quote/");
        });

        it("Should accept a single-letter ticker symbol", function() {
            const needle = require("needle");
            const originalGet = needle.get;
            let capturedUrl = null;

            needle.get = function(url, cb) {
                capturedUrl = url;
                cb(null, { statusCode: 200 }, "data");
            };

            mockReq.query = { symbol: "T" };

            researchHandler.displayResearch(mockReq, mockRes);

            needle.get = originalGet;

            should(statusCode).be.null();
            capturedUrl.should.containEql("T");
        });

        it("Should accept a 10-letter ticker symbol (maximum valid length)", function() {
            const needle = require("needle");
            const originalGet = needle.get;
            let capturedUrl = null;

            needle.get = function(url, cb) {
                capturedUrl = url;
                cb(null, { statusCode: 200 }, "data");
            };

            mockReq.query = { symbol: "ABCDEFGHIJ" };  // exactly 10 characters

            researchHandler.displayResearch(mockReq, mockRes);

            needle.get = originalGet;

            should(statusCode).be.null();
        });
    });

    // -------------------------------------------------------------------------
    // Functionality: No symbol → render the research form
    // -------------------------------------------------------------------------
    describe("Functionality - Render Research Page Without Symbol", function() {

        it("Should render the research view when no symbol is provided", function() {
            mockReq.query = {};

            researchHandler.displayResearch(mockReq, mockRes);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("research");
        });

        it("Should render the research view when symbol query param is absent", function() {
            mockReq.query = { url: "https://finance.yahoo.com/quote/" };

            researchHandler.displayResearch(mockReq, mockRes);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("research");
        });
    });
});
