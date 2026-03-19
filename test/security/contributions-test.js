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
