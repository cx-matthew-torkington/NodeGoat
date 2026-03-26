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

        // Mock database (not really used by SqliHandler directly, but needed for constructor)
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

    describe("Security - Reflected XSS Prevention", function() {

        it("Should HTML-encode script tag in search parameter", function(done) {
            // Mock SqliDAO to return results
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                // Simulate successful query
                callback(null, [
                    { id: 1, name: "Test User", department: "IT", email: "test@example.com" }
                ]);
            };

            // Test with XSS payload
            mockReq.query.name = "<script>alert('XSS')</script>";

            sqliHandler.displaySearch(mockReq, mockRes);

            // Use setTimeout to allow async callback to complete
            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // Verify that the searchName is HTML-encoded
                renderArgs.data.searchName.should.not.containEql("<script>");
                renderArgs.data.searchName.should.not.containEql("</script>");
                // Should be encoded as HTML entities
                renderArgs.data.searchName.should.containEql("&lt;");
                renderArgs.data.searchName.should.containEql("&gt;");

                // Restore original method
                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should HTML-encode single quotes in search parameter", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with single quote XSS payload
            mockReq.query.name = "' onload='alert(1)";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that the searchName is HTML-encoded
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("onload=");
                // Single quotes should be encoded
                encodedName.should.match(/&#x27;|&#39;|&apos;/);

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should HTML-encode img tag with onerror in search parameter", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with img onerror XSS payload
            mockReq.query.name = '<img src=x onerror="alert(1)">';

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that the searchName is HTML-encoded
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("<img");
                encodedName.should.not.containEql("onerror");
                encodedName.should.containEql("&lt;");
                encodedName.should.containEql("&gt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should HTML-encode special HTML characters", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with various HTML special characters
            mockReq.query.name = '& < > " \' /';

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that special characters are HTML-encoded
                const encodedName = renderArgs.data.searchName;
                // Ampersand should be encoded
                encodedName.should.containEql("&amp;");
                // Less than and greater than should be encoded
                encodedName.should.containEql("&lt;");
                encodedName.should.containEql("&gt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should HTML-encode searchName even on database error", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                // Simulate database error
                callback(new Error("Database connection failed"));
            };

            // Test with XSS payload when error occurs
            mockReq.query.name = "<script>alert('XSS')</script>";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // Verify that the searchName is HTML-encoded even on error
                renderArgs.data.searchName.should.not.containEql("<script>");
                renderArgs.data.searchName.should.containEql("&lt;");
                renderArgs.data.searchName.should.containEql("&gt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should handle normal text input without breaking functionality", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, [
                    { id: 1, name: "Alice Johnson", department: "HR", email: "alice@example.com" }
                ]);
            };

            // Test with normal, benign input
            mockReq.query.name = "Alice Johnson";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // Normal text should still be readable (though it might have some encoding)
                renderArgs.data.searchName.should.equal("Alice Johnson");
                renderArgs.data.results.should.have.length(1);
                renderArgs.data.results[0].name.should.equal("Alice Johnson");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should handle empty query parameter", function() {
            // Test with no query parameter
            mockReq.query = {};

            sqliHandler.displaySearch(mockReq, mockRes);

            // This should execute synchronously
            renderCalled.should.be.true();
            renderArgs.view.should.equal("sqli");
            renderArgs.data.searchName.should.equal("");
            should.not.exist(renderArgs.data.results);
        });

        it("Should encode JavaScript event handlers in search parameter", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with event handler injection
            mockReq.query.name = '" onclick="alert(1)" x="';

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that quotes are encoded to prevent attribute breakout
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql('onclick=');
                // Double quotes should be encoded
                encodedName.should.match(/&quot;|&#34;|&#x22;/);

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should encode data URI XSS payload", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with data URI XSS payload
            mockReq.query.name = '<iframe src="data:text/html,<script>alert(1)</script>">';

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that tags are encoded
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("<iframe");
                encodedName.should.not.containEql("<script>");
                encodedName.should.containEql("&lt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should encode SVG-based XSS payload", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with SVG XSS payload
            mockReq.query.name = '<svg onload="alert(1)">';

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that SVG tags and event handlers are encoded
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("<svg");
                encodedName.should.not.containEql("onload");
                encodedName.should.containEql("&lt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });
    });

    describe("Edge Cases", function() {

        it("Should handle null-byte injection attempt", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with null byte
            mockReq.query.name = "test\x00<script>alert(1)</script>";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify encoding occurred
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("<script>");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should handle Unicode encoded XSS attempts", function(done) {
            const SqliDAO = require("../../app/data/sqli-dao");
            const originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Test with Unicode-encoded brackets (U+003C = <, U+003E = >)
            mockReq.query.name = "\u003cscript\u003ealert(1)\u003c/script\u003e";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();

                // Verify that the literal characters are encoded
                const encodedName = renderArgs.data.searchName;
                encodedName.should.not.containEql("script>");
                encodedName.should.containEql("&lt;");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });
    });
});
