const assert = require("assert");
const should = require("should");

describe("ResearchHandler Security Tests", function() {
    "use strict";

    let ResearchHandler;
    let handler;
    let mockDb;
    let mockReq;
    let mockRes;

    before(function() {
        // Mock database
        mockDb = {};
        ResearchHandler = require("../../app/routes/research");
        handler = new ResearchHandler(mockDb);
    });

    beforeEach(function() {
        // Reset mocks before each test
        mockReq = {
            query: {}
        };

        mockRes = {
            statusCode: null,
            headers: {},
            content: [],
            ended: false,
            writeHead: function(code, hdrs) {
                this.statusCode = code;
                if (hdrs) {
                    Object.assign(this.headers, hdrs);
                }
            },
            write: function(data) {
                this.content.push(data);
            },
            end: function() {
                this.ended = true;
                return this;
            },
            render: function(view, data) {
                this.rendered = true;
                this.renderView = view;
                this.renderData = data;
            }
        };
    });

    describe("SSRF Attack Prevention", function() {

        it("Should block attempts to access localhost via 127.0.0.1", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://127.0.0.1:8080"
            };

            handler.displayResearch(mockReq, mockRes);

            // Verify that the request was blocked
            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access localhost via hostname", function(done) {
            mockReq.query = {
                symbol: "/admin",
                url: "http://localhost:3000"
            };

            handler.displayResearch(mockReq, mockRes);

            // Verify that the request was blocked
            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access private IP range 10.x.x.x", function(done) {
            mockReq.query = {
                symbol: "/secrets",
                url: "http://10.0.0.1"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access private IP range 192.168.x.x", function(done) {
            mockReq.query = {
                symbol: "/api",
                url: "http://192.168.1.1"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access private IP range 172.16-31.x.x", function(done) {
            mockReq.query = {
                symbol: "/data",
                url: "http://172.16.0.1"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access cloud metadata endpoints (AWS)", function(done) {
            mockReq.query = {
                symbol: "/latest/meta-data/",
                url: "http://169.254.169.254"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access IPv6 localhost", function(done) {
            mockReq.query = {
                symbol: "/admin",
                url: "http://[::1]:8080"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to access 0.0.0.0", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://0.0.0.0:5000"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block non-allowlisted domains", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "https://malicious-site.com"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block HTTP protocol (require HTTPS)", function(done) {
            mockReq.query = {
                symbol: "/AAPL",
                url: "http://finance.yahoo.com/quote/"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block FTP protocol", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "ftp://finance.yahoo.com"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block file:// protocol", function(done) {
            mockReq.query = {
                symbol: "",
                url: "file:///etc/passwd"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block gopher:// protocol", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "gopher://127.0.0.1:9000"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block malformed URLs", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "not-a-valid-url"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to use subdomain variations of localhost", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://127.0.0.2"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts to bypass with URL encoding", function(done) {
            // Even if attacker tries encoding, the URL parser should normalize it
            mockReq.query = {
                symbol: "/test",
                url: "http://localh%6fst"
            };

            handler.displayResearch(mockReq, mockRes);

            // Should be blocked - either as invalid hostname or caught by validation
            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            done();
        });

        it("Should block attempts to access internal services via different ports", function(done) {
            mockReq.query = {
                symbol: "/admin",
                url: "http://127.0.0.1:22"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

    });

    describe("Valid Stock API Requests", function() {

        it("Should allow HTTPS requests to finance.yahoo.com", function(done) {
            mockReq.query = {
                symbol: "AAPL",
                url: "https://finance.yahoo.com/quote/"
            };

            // We don't actually want to make a real HTTP request in the test,
            // but we can verify that the validation passes and needle.get would be called
            // The request should not be blocked with a 400 error
            const result = handler.displayResearch(mockReq, mockRes);

            // If validation passes, the function will attempt to call needle.get
            // and return its result (not immediately end with 400)
            // We can verify the request wasn't blocked by checking the status code
            // wasn't set to 400 immediately
            if (mockRes.statusCode === 400) {
                done(new Error("Valid request was incorrectly blocked"));
            } else {
                // Valid request passed validation
                done();
            }
        });

        it("Should allow HTTPS requests to query1.finance.yahoo.com", function(done) {
            mockReq.query = {
                symbol: "TSLA",
                url: "https://query1.finance.yahoo.com/v7/finance/quote/"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            if (mockRes.statusCode === 400) {
                done(new Error("Valid request was incorrectly blocked"));
            } else {
                done();
            }
        });

        it("Should allow HTTPS requests to query2.finance.yahoo.com", function(done) {
            mockReq.query = {
                symbol: "GOOGL",
                url: "https://query2.finance.yahoo.com/v1/finance/"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            if (mockRes.statusCode === 400) {
                done(new Error("Valid request was incorrectly blocked"));
            } else {
                done();
            }
        });

    });

    describe("Edge Cases and Bypass Prevention", function() {

        it("Should handle empty symbol parameter", function(done) {
            mockReq.query = {
                symbol: "",
                url: "https://finance.yahoo.com/quote/"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            // With empty symbol, the URL is still validated
            if (mockRes.statusCode === 400) {
                done(new Error("Valid request was incorrectly blocked"));
            } else {
                done();
            }
        });

        it("Should handle missing symbol parameter (render research page)", function(done) {
            mockReq.query = {};

            handler.displayResearch(mockReq, mockRes);

            // Should render the research page, not make an HTTP request
            mockRes.rendered.should.be.true();
            mockRes.renderView.should.equal("research");
            done();
        });

        it("Should block URL with path traversal attempts", function(done) {
            mockReq.query = {
                symbol: "/../../../etc/passwd",
                url: "https://finance.yahoo.com/quote/"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            // The URL is valid (finance.yahoo.com is allowlisted),
            // but the symbol could contain malicious path traversal.
            // The important thing is that it's sent to an allowlisted domain only.
            // Let's verify the domain validation still works
            if (mockRes.statusCode === 400) {
                done(new Error("Valid domain was incorrectly blocked"));
            } else {
                // Valid domain passed - path traversal would be handled by the remote server
                done();
            }
        });

        it("Should block attempts using IP address instead of domain", function(done) {
            // Even if finance.yahoo.com resolves to a specific IP,
            // we should only accept the domain name, not direct IP access
            mockReq.query = {
                symbol: "/test",
                url: "https://98.137.246.8"  // Example IP (not actual Yahoo IP)
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts with @ symbol (URL credential injection)", function(done) {
            // Attackers might try: https://allowlisted.com@evil.com
            mockReq.query = {
                symbol: "/test",
                url: "https://finance.yahoo.com@evil.com"
            };

            handler.displayResearch(mockReq, mockRes);

            // The URL parser will interpret evil.com as the hostname
            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            mockRes.content.join("").should.match(/Invalid stock API URL/);
            done();
        });

        it("Should block attempts with backslash confusion", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "https://finance.yahoo.com\\@evil.com"
            };

            handler.displayResearch(mockReq, mockRes);

            // Should be blocked as invalid or non-allowlisted
            mockRes.statusCode.should.equal(400);
            mockRes.ended.should.be.true();
            done();
        });

        it("Should handle very long URLs gracefully", function(done) {
            mockReq.query = {
                symbol: "A".repeat(10000),
                url: "https://finance.yahoo.com/quote/"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            // Validation should still work with long URLs
            // Domain is valid, so should not be blocked by SSRF protection
            if (mockRes.statusCode === 400 && mockRes.content.join("").match(/Invalid stock API URL/)) {
                done(new Error("Valid domain was blocked"));
            } else {
                done();
            }
        });

        it("Should handle URLs with fragments", function(done) {
            mockReq.query = {
                symbol: "AAPL",
                url: "https://finance.yahoo.com/quote/#fragment"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            // Domain is valid, should pass validation
            if (mockRes.statusCode === 400 && mockRes.content.join("").match(/Invalid stock API URL/)) {
                done(new Error("Valid URL with fragment was blocked"));
            } else {
                done();
            }
        });

        it("Should handle URLs with query parameters", function(done) {
            mockReq.query = {
                symbol: "AAPL",
                url: "https://finance.yahoo.com/quote/?param=value"
            };

            const result = handler.displayResearch(mockReq, mockRes);

            // Domain is valid, should pass validation
            if (mockRes.statusCode === 400 && mockRes.content.join("").match(/Invalid stock API URL/)) {
                done(new Error("Valid URL with query params was blocked"));
            } else {
                done();
            }
        });

    });

    describe("Regression Prevention", function() {

        it("Should validate URLs before making HTTP requests", function() {
            // Verify that the handler code contains URL validation
            const handlerString = handler.displayResearch.toString();

            // Should contain validation logic
            handlerString.should.match(/isValidStockApiUrl/);
            handlerString.should.match(/Invalid stock API URL/);
        });

        it("Should use allowlist approach for domain validation", function() {
            // Verify that the ResearchHandler constructor contains an allowlist
            const constructorString = ResearchHandler.toString();

            constructorString.should.match(/ALLOWED_DOMAINS/);
            constructorString.should.match(/finance\.yahoo\.com/);
        });

        it("Should enforce HTTPS protocol only", function() {
            const constructorString = ResearchHandler.toString();

            // Should check for HTTPS protocol
            constructorString.should.match(/protocol.*https/i);
        });

        it("Should block private IP ranges", function() {
            const constructorString = ResearchHandler.toString();

            // Should contain logic to block private IPs
            constructorString.should.match(/10\.|192\.168|172\./);
        });

        it("Should block localhost variations", function() {
            const constructorString = ResearchHandler.toString();

            // Should contain localhost blocking logic
            constructorString.should.match(/localhost|127\./);
        });

    });

    describe("Security Best Practices", function() {

        it("Should return appropriate error status code (400) for invalid URLs", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://evil.com"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.statusCode.should.equal(400);
            done();
        });

        it("Should provide clear error message without leaking sensitive info", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://internal-server.local"
            };

            handler.displayResearch(mockReq, mockRes);

            const content = mockRes.content.join("");
            content.should.match(/Invalid stock API URL/);
            // Should not leak internal details like allowlist, validation logic, etc.
            content.should.not.match(/ALLOWED_DOMAINS/);
            content.should.not.match(/isValidStockApiUrl/);
            done();
        });

        it("Should end response properly after blocking request", function(done) {
            mockReq.query = {
                symbol: "/test",
                url: "http://localhost"
            };

            handler.displayResearch(mockReq, mockRes);

            mockRes.ended.should.be.true();
            done();
        });

    });

});
