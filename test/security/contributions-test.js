const assert = require("assert");
const should = require("should");

describe("ContributionsHandler Security Tests", function() {
    "use strict";

    let ContributionsHandler;
    let handler;
    let mockDb;
    let mockReq;
    let mockRes;
    let mockNext;

    before(function() {
        // Mock database and DAO
        mockDb = {};
        ContributionsHandler = require("../../app/routes/contributions");
        handler = new ContributionsHandler(mockDb);
    });

    beforeEach(function() {
        // Reset mocks before each test
        mockReq = {
            body: {},
            session: {
                userId: "testUser123"
            }
        };

        mockRes = {
            rendered: false,
            renderData: null,
            render: function(view, data) {
                this.rendered = true;
                this.renderData = data;
            }
        };

        mockNext = function(err) {
            mockNext.calledWith = err;
        };
        mockNext.calledWith = null;
    });

    describe("Code Injection Prevention", function() {

        it("Should safely parse valid numeric input without executing code", function() {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "5"
            };

            // Mock the contributionsDAO.update to verify the parsed values
            const originalDAO = handler.constructor.prototype;
            let capturedValues = null;

            // Temporarily mock the DAO update method
            const mockUpdate = function(userId, preTax, afterTax, roth, callback) {
                capturedValues = { preTax, afterTax, roth };
                callback(null, { preTax, afterTax, roth, userId });
            };

            // Inject mock DAO
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            ContributionsDAO.prototype.update = mockUpdate;

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify the values were correctly parsed as integers
            capturedValues.should.not.be.null();
            capturedValues.preTax.should.equal(10);
            capturedValues.afterTax.should.equal(10);
            capturedValues.roth.should.equal(5);

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should block code injection attempts via malicious afterTax input", function() {
            // Attempt to inject code via afterTax parameter (the vulnerability target)
            mockReq.body = {
                preTax: "10",
                afterTax: "process.exit(1)",  // Malicious code injection attempt
                roth: "5"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that the malicious input was parsed as NaN and rejected
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should block code injection attempts via malicious preTax input", function() {
            // Attempt to inject code via preTax parameter
            mockReq.body = {
                preTax: "require('fs').readFileSync('/etc/passwd')",  // File read attempt
                afterTax: "10",
                roth: "5"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that the malicious input was parsed as NaN and rejected
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should block code injection attempts via malicious roth input", function() {
            // Attempt to inject code via roth parameter
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "console.log('hacked')"  // Console injection attempt
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that the malicious input was parsed as NaN and rejected
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should block function invocation attempts", function() {
            // Attempt to invoke functions
            mockReq.body = {
                preTax: "Math.random()",
                afterTax: "10",
                roth: "5"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that the malicious input was parsed as NaN and rejected
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should block arithmetic expression injection attempts", function() {
            // Attempt to inject arithmetic expressions that could bypass validation
            mockReq.body = {
                preTax: "5+5",  // Would evaluate to 10 with eval()
                afterTax: "10",
                roth: "5"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // parseInt("5+5", 10) returns 5 (stops at the +), which is valid
            // This test ensures the behavior is predictable
            updateCalled.should.be.true();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

    });

    describe("Input Validation", function() {

        it("Should reject non-numeric string inputs", function() {
            mockReq.body = {
                preTax: "abc",
                afterTax: "10",
                roth: "5"
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject negative values", function() {
            mockReq.body = {
                preTax: "-10",
                afterTax: "10",
                roth: "5"
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject empty string inputs", function() {
            mockReq.body = {
                preTax: "",
                afterTax: "10",
                roth: "5"
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject contributions exceeding 30%", function() {
            mockReq.body = {
                preTax: "15",
                afterTax: "15",
                roth: "5"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Contribution percentages cannot exceed 30 %");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should accept valid contributions at exactly 30%", function() {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "10"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            updateCalled.should.be.true();
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateSuccess");

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should handle floating point numbers by truncating decimals", function() {
            mockReq.body = {
                preTax: "10.5",  // parseInt will truncate to 10
                afterTax: "9.9",  // parseInt will truncate to 9
                roth: "5.1"       // parseInt will truncate to 5
            };

            // Mock the contributionsDAO.update to capture values
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let capturedValues = null;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                capturedValues = { preTax, afterTax, roth };
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that parseInt truncated the decimals correctly
            capturedValues.should.not.be.null();
            capturedValues.preTax.should.equal(10);
            capturedValues.afterTax.should.equal(9);
            capturedValues.roth.should.equal(5);

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });
    });

    describe("Regression Prevention", function() {

        it("Should use parseInt instead of eval for parsing", function() {
            // This test ensures the fix remains in place
            const handlerString = handler.handleContributionsUpdate.toString();

            // Verify that parseInt is used
            handlerString.should.match(/parseInt/);

            // Verify that eval is NOT used (except in comments)
            const evalMatches = handlerString.match(/[^/]eval\(/g);
            should(evalMatches).be.null();
        });

        it("Should specify radix 10 in parseInt calls", function() {
            // This test ensures best practice of specifying radix
            const handlerString = handler.handleContributionsUpdate.toString();

            // Count parseInt calls with radix 10
            const parseIntMatches = handlerString.match(/parseInt\([^,]+,\s*10\)/g);
            should(parseIntMatches).not.be.null();
            parseIntMatches.length.should.be.greaterThanOrEqual(3);
        });
    });

    describe("XSS Prevention - Reflected Cross-Site Scripting", function() {

        it("Should encode userId with HTML entities when rendering error at line 50", function() {
            // Test the specific XSS vulnerability fix at line 50
            mockReq.body = {
                preTax: "15",
                afterTax: "15",
                roth: "5"  // Total exceeds 30%, triggering line 50
            };

            // Inject XSS payload into session userId
            mockReq.session.userId = "<script>alert('XSS')</script>";

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify the error was rendered
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Contribution percentages cannot exceed 30 %");

            // Verify userId is HTML-encoded
            mockRes.renderData.userId.should.equal("&lt;script&gt;alert&#x28;&#x27;XSS&#x27;&#x29;&lt;&#x2f;script&gt;");

            // Verify the XSS payload is not executable
            mockRes.renderData.userId.should.not.containEql("<script>");
            mockRes.renderData.userId.should.not.containEql("</script>");
        });

        it("Should prevent XSS via userId with img onerror payload", function() {
            mockReq.body = {
                preTax: "20",
                afterTax: "15",
                roth: "0"  // Total exceeds 30%
            };

            mockReq.session.userId = '<img src=x onerror="alert(1)">';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.equal("&lt;img&#x20;src&#x3d;x&#x20;onerror&#x3d;&quot;alert&#x28;1&#x29;&quot;&gt;");
            mockRes.renderData.userId.should.not.containEql("<img");
            mockRes.renderData.userId.should.not.containEql("onerror=");
        });

        it("Should prevent XSS via userId with iframe injection", function() {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "11"  // Total exceeds 30%
            };

            mockReq.session.userId = '<iframe src="javascript:alert(\'XSS\')"></iframe>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("<iframe");
            mockRes.renderData.userId.should.not.containEql("javascript:");
            // Verify proper encoding
            mockRes.renderData.userId.should.containEql("&lt;");
            mockRes.renderData.userId.should.containEql("&gt;");
        });

        it("Should prevent XSS via userId with svg onload payload", function() {
            mockReq.body = {
                preTax: "31",
                afterTax: "0",
                roth: "0"  // Total exceeds 30%
            };

            mockReq.session.userId = '<svg onload="alert(document.cookie)">';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("<svg");
            mockRes.renderData.userId.should.not.containEql("onload=");
            mockRes.renderData.userId.should.containEql("&lt;");
        });

        it("Should encode special HTML characters in userId", function() {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "15"  // Total exceeds 30%
            };

            mockReq.session.userId = '"><script>alert(String.fromCharCode(88,83,83))</script>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            // Verify double quotes are encoded
            mockRes.renderData.userId.should.not.containEql('">');
            mockRes.renderData.userId.should.containEql("&quot;");
            mockRes.renderData.userId.should.not.containEql("<script>");
        });

        it("Should handle userId with event handlers", function() {
            mockReq.body = {
                preTax: "0",
                afterTax: "0",
                roth: "31"  // Total exceeds 30%
            };

            mockReq.session.userId = '<div onmouseover="alert(1)">test</div>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("onmouseover=");
            mockRes.renderData.userId.should.not.containEql("<div");
        });

        it("Should encode userId with mixed case XSS attempt", function() {
            mockReq.body = {
                preTax: "100",
                afterTax: "0",
                roth: "0"  // Total exceeds 30%
            };

            mockReq.session.userId = '<ScRiPt>alert("XSS")</sCrIpT>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.containEql("&lt;");
            mockRes.renderData.userId.should.containEql("&gt;");
            // Should encode regardless of case
            mockRes.renderData.userId.should.not.match(/<[Ss][Cc][Rr][Ii][Pp][Tt]>/);
        });

        it("Should handle userId with JavaScript protocol", function() {
            mockReq.body = {
                preTax: "15",
                afterTax: "10",
                roth: "10"  // Total exceeds 30%
            };

            mockReq.session.userId = '<a href="javascript:alert(1)">click</a>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("javascript:");
            mockRes.renderData.userId.should.not.containEql("<a ");
        });

        it("Should encode userId with data URI XSS", function() {
            mockReq.body = {
                preTax: "20",
                afterTax: "5",
                roth: "10"  // Total exceeds 30%
            };

            mockReq.session.userId = '<object data="data:text/html,<script>alert(1)</script>"></object>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("<object");
            mockRes.renderData.userId.should.not.containEql("data:text/html");
            mockRes.renderData.userId.should.containEql("&lt;");
        });

        it("Should handle numeric userId values correctly", function() {
            mockReq.body = {
                preTax: "11",
                afterTax: "11",
                roth: "11"  // Total exceeds 30%
            };

            // Normal numeric userId (common case)
            mockReq.session.userId = "12345";

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            // Numeric values should pass through unchanged
            mockRes.renderData.userId.should.equal("12345");
        });

        it("Should handle alphanumeric userId without special characters", function() {
            mockReq.body = {
                preTax: "10",
                afterTax: "11",
                roth: "11"  // Total exceeds 30%
            };

            mockReq.session.userId = "user123abc";

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            // Alphanumeric without special chars should pass through
            mockRes.renderData.userId.should.equal("user123abc");
        });

        it("Should prevent XSS with null byte injection", function() {
            mockReq.body = {
                preTax: "31",
                afterTax: "1",
                roth: "1"  // Total exceeds 30%
            };

            mockReq.session.userId = '<script>\x00alert(1)</script>';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.not.containEql("<script>");
        });

        it("Should handle userId with HTML entities already present", function() {
            mockReq.body = {
                preTax: "15",
                afterTax: "15",
                roth: "5"  // Total exceeds 30%
            };

            mockReq.session.userId = '&lt;script&gt;alert(1)&lt;/script&gt;';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            // Should double-encode the ampersands
            mockRes.renderData.userId.should.containEql("&amp;");
        });

        it("Should prevent XSS with unicode escape sequences", function() {
            mockReq.body = {
                preTax: "40",
                afterTax: "0",
                roth: "0"  // Total exceeds 30%
            };

            mockReq.session.userId = '\u003cscript\u003ealert(1)\u003c/script\u003e';

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.userId.should.containEql("&lt;");
            mockRes.renderData.userId.should.not.containEql("<script>");
        });

    });

    describe("Edge Cases", function() {

        it("Should handle zero values correctly", function() {
            mockReq.body = {
                preTax: "0",
                afterTax: "0",
                roth: "0"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let capturedValues = null;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                capturedValues = { preTax, afterTax, roth };
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            capturedValues.should.not.be.null();
            capturedValues.preTax.should.equal(0);
            capturedValues.afterTax.should.equal(0);
            capturedValues.roth.should.equal(0);

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should handle very large numbers", function() {
            mockReq.body = {
                preTax: "999999",
                afterTax: "999999",
                roth: "999999"
            };

            // Mock the contributionsDAO.update
            const ContributionsDAO = require("../../app/data/contributions-dao").ContributionsDAO;
            const originalUpdate = ContributionsDAO.prototype.update;
            let updateCalled = false;

            ContributionsDAO.prototype.update = function(userId, preTax, afterTax, roth, callback) {
                updateCalled = true;
                callback(null, { preTax, afterTax, roth, userId });
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Should be rejected due to exceeding 30% limit
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            updateCalled.should.be.false();

            // Restore original
            ContributionsDAO.prototype.update = originalUpdate;
        });

        it("Should handle Unicode and special characters", function() {
            mockReq.body = {
                preTax: "10\u0000",  // Null byte
                afterTax: "10",
                roth: "5"
            };

            handler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // parseInt will parse up to the null byte
            // The behavior should be predictable and safe
            mockRes.rendered.should.be.true();
        });
    });
});
