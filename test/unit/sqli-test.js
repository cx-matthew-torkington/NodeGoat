const should = require("should");
const SqliHandler = require("../../app/routes/sqli");

describe("SqliHandler - XSS Prevention", function() {
    "use strict";

    let sqliHandler;
    let mockDb;
    let mockReq;
    let mockRes;
    let renderCalled;
    let renderArgs;

    beforeEach(function() {
        // Reset state
        renderCalled = false;
        renderArgs = null;

        // Mock database (not actually used by SqliHandler constructor)
        mockDb = {};

        // Create handler instance
        sqliHandler = new SqliHandler(mockDb);

        // Mock request object
        mockReq = {
            query: {}
        };

        // Mock response object
        mockRes = {
            render: function(view, data) {
                renderCalled = true;
                renderArgs = { view, data };
            }
        };
    });

    describe("Security - XSS Prevention", function() {

        it("Should render empty searchName when no query parameter provided", function() {
            mockReq.query = {};

            sqliHandler.displaySearch(mockReq, mockRes);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("sqli");
            renderArgs.data.searchName.should.equal("");
            should.not.exist(renderArgs.data.results);
            should.not.exist(renderArgs.data.error);
        });

        it("Should encode basic XSS payload in searchName", function(done) {
            const xssPayload = "<script>alert('XSS')</script>";
            mockReq.query.name = xssPayload;

            // Mock SqliDAO to simulate successful search
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                // Simulate successful query with results
                callback(null, [
                    { id: 1, name: "Test User", department: "IT", email: "test@example.com" }
                ]);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            // Wait for async callback
            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // Verify that searchName is HTML-encoded
                renderArgs.data.searchName.should.not.equal(xssPayload);
                renderArgs.data.searchName.should.equal("&lt;script&gt;alert&#x28;&#x27;XSS&#x27;&#x29;&lt;&#x2f;script&gt;");

                // Restore original method
                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should encode XSS payload with img tag in searchName", function(done) {
            const xssPayload = "<img src=x onerror=alert('XSS')>";
            mockReq.query.name = xssPayload;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that searchName is HTML-encoded
                renderArgs.data.searchName.should.not.equal(xssPayload);
                renderArgs.data.searchName.should.not.containEql("<img");
                renderArgs.data.searchName.should.not.containEql("onerror");
                renderArgs.data.searchName.should.containEql("&lt;");
                renderArgs.data.searchName.should.containEql("&gt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should encode XSS payload with event handlers in searchName", function(done) {
            const xssPayload = "<div onload=alert('XSS')>Test</div>";
            mockReq.query.name = xssPayload;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that dangerous characters are encoded
                renderArgs.data.searchName.should.not.equal(xssPayload);
                renderArgs.data.searchName.should.not.containEql("<div");
                renderArgs.data.searchName.should.not.containEql("onload=");
                renderArgs.data.searchName.should.containEql("&lt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should encode XSS payload in searchName when error occurs", function(done) {
            const xssPayload = "<script>alert('XSS')</script>";
            mockReq.query.name = xssPayload;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                // Simulate database error
                callback(new Error("Database connection failed"), null);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // Verify that searchName is HTML-encoded even in error case
                renderArgs.data.searchName.should.not.equal(xssPayload);
                renderArgs.data.searchName.should.equal("&lt;script&gt;alert&#x28;&#x27;XSS&#x27;&#x29;&lt;&#x2f;script&gt;");
                renderArgs.data.error.should.containEql("Query error:");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should handle legitimate user input without corruption", function(done) {
            const legitimateInput = "John O'Brien";
            mockReq.query.name = legitimateInput;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, [
                    { id: 5, name: "John O'Brien", department: "Sales", email: "john@example.com" }
                ]);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify legitimate input is properly encoded for HTML context
                // Single quote should be encoded
                renderArgs.data.searchName.should.equal("John O&#x27;Brien");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should encode special HTML characters in searchName", function(done) {
            const specialChars = "Test & <Company> \"Products\"";
            mockReq.query.name = specialChars;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify all special HTML characters are encoded
                renderArgs.data.searchName.should.not.equal(specialChars);
                renderArgs.data.searchName.should.containEql("&amp;");
                renderArgs.data.searchName.should.containEql("&lt;");
                renderArgs.data.searchName.should.containEql("&gt;");
                renderArgs.data.searchName.should.containEql("&quot;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should prevent JavaScript URL XSS attempt", function(done) {
            const xssPayload = "javascript:alert('XSS')";
            mockReq.query.name = xssPayload;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that the colon and parentheses are encoded
                renderArgs.data.searchName.should.containEql("&#x3a;"); // colon
                renderArgs.data.searchName.should.containEql("&#x28;"); // (
                renderArgs.data.searchName.should.containEql("&#x29;"); // )

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should handle empty string searchName safely", function(done) {
            const emptyInput = "";
            mockReq.query.name = emptyInput;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.searchName.should.equal("");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should encode complex nested XSS payload", function(done) {
            const xssPayload = "<svg/onload=alert`1`>";
            mockReq.query.name = xssPayload;

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, []);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that all dangerous characters are encoded
                renderArgs.data.searchName.should.not.equal(xssPayload);
                renderArgs.data.searchName.should.not.containEql("<svg");
                renderArgs.data.searchName.should.not.containEql("onload");
                renderArgs.data.searchName.should.containEql("&lt;");
                renderArgs.data.searchName.should.containEql("&gt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });
    });

    describe("Functionality - Proper Rendering", function() {

        it("Should pass results correctly when query succeeds", function(done) {
            mockReq.query.name = "Alice";

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            const mockResults = [
                { id: 1, name: "Alice Johnson", department: "HR", email: "alice@example.com" },
                { id: 2, name: "Alice Smith", department: "IT", email: "asmith@example.com" }
            ];

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(null, mockResults);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");
                renderArgs.data.results.should.equal(mockResults);
                renderArgs.data.results.length.should.equal(2);
                should.not.exist(renderArgs.data.error);

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });

        it("Should handle database error gracefully", function(done) {
            mockReq.query.name = "test";

            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(name, callback) {
                callback(new Error("Connection timeout"), null);
            };

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");
                should.not.exist(renderArgs.data.results);
                renderArgs.data.error.should.equal("Query error: Connection timeout");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 50);
        });
    });
});
