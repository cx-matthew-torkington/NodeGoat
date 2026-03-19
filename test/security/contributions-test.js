const assert = require("assert");
const should = require("should");
const ContributionsHandler = require("../../app/routes/contributions");

describe("Contributions Security Tests", function() {
    "use strict";

    let contributionsHandler;
    let mockDb;
    let mockReq;
    let mockRes;
    let mockNext;

    beforeEach(function() {
        // Mock database
        mockDb = {
            collection: function() {
                return {};
            }
        };

        contributionsHandler = new ContributionsHandler(mockDb);

        // Mock request object
        mockReq = {
            body: {},
            session: {
                userId: "testuser123"
            }
        };

        // Mock response object
        mockRes = {
            rendered: false,
            renderData: null,
            render: function(view, data) {
                this.rendered = true;
                this.renderData = data;
            }
        };

        // Mock next function
        mockNext = function(err) {
            if (err) throw err;
        };
    });

    describe("Code Injection Prevention", function() {

        it("Should reject code injection attempts in preTax field", function(done) {
            // Mock DAO to verify code injection doesn't reach the database
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    // This should NOT be called with malicious code executed
                    // If preTax is NaN due to injection attempt, validation should catch it
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            // Attempt code injection through eval
            mockReq.body.preTax = "process.exit(1)"; // Malicious code
            mockReq.body.afterTax = "5";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Verify that the malicious code was NOT executed
            // parseInt will return NaN for non-numeric strings
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });

        it("Should reject code injection with function calls in afterTax field", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "10";
            mockReq.body.afterTax = "require('fs').readFileSync('/etc/passwd')"; // Malicious code
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });

        it("Should reject code injection with arithmetic expressions in roth field", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "10";
            mockReq.body.afterTax = "5";
            mockReq.body.roth = "(function(){console.log('hacked')})()"; // Malicious code

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });

        it("Should reject multiple injection attempts across all fields", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "global.hacked = true";
            mockReq.body.afterTax = "require('child_process').exec('ls')";
            mockReq.body.roth = "console.log('pwned')";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });
    });

    describe("Valid Input Processing", function() {

        it("Should accept valid numeric strings and convert them to integers", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    // Verify values are properly converted to numbers
                    preTax.should.be.a.Number();
                    afterTax.should.be.a.Number();
                    roth.should.be.a.Number();
                    preTax.should.equal(10);
                    afterTax.should.equal(5);
                    roth.should.equal(5);

                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth,
                        updateSuccess: true
                    });
                }
            };

            mockReq.body.preTax = "10";
            mockReq.body.afterTax = "5";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateSuccess");
            mockRes.renderData.updateSuccess.should.be.true();

            done();
        });

        it("Should handle numeric values at boundaries correctly", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    preTax.should.equal(0);
                    afterTax.should.equal(15);
                    roth.should.equal(15);

                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth,
                        updateSuccess: true
                    });
                }
            };

            mockReq.body.preTax = "0";
            mockReq.body.afterTax = "15";
            mockReq.body.roth = "15";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateSuccess");

            done();
        });

        it("Should reject negative values", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "-5";
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });

        it("Should reject values exceeding 30% total", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "15";
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "10"; // Total = 35%

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Contribution percentages cannot exceed 30 %");

            done();
        });
    });

    describe("Input Edge Cases", function() {

        it("Should handle empty string inputs as invalid", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "";
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");

            done();
        });

        it("Should handle null/undefined inputs as invalid", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = null;
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");

            done();
        });

        it("Should handle special characters and SQL injection attempts", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "10' OR '1'='1";
            mockReq.body.afterTax = "5";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });

        it("Should safely handle very large numeric strings", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth
                    });
                }
            };

            mockReq.body.preTax = "999999999999999999999";
            mockReq.body.afterTax = "5";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Should still process but will fail the 30% validation
            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateError");

            done();
        });

        it("Should handle floating point numbers by truncating to integer", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    // parseInt truncates decimals, so 10.5 becomes 10
                    preTax.should.equal(10);
                    afterTax.should.equal(5);
                    roth.should.equal(5);

                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth,
                        updateSuccess: true
                    });
                }
            };

            mockReq.body.preTax = "10.5";
            mockReq.body.afterTax = "5.9";
            mockReq.body.roth = "5.1";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();

            done();
        });
    });

    describe("Regression Tests", function() {

        it("Should maintain backwards compatibility with valid integer inputs", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function(userId, preTax, afterTax, roth, callback) {
                    callback(null, {
                        preTax: preTax,
                        afterTax: afterTax,
                        roth: roth,
                        updateSuccess: true
                    });
                }
            };

            mockReq.body.preTax = "8";
            mockReq.body.afterTax = "7";
            mockReq.body.roth = "6";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.should.have.property("updateSuccess");
            mockRes.renderData.updateSuccess.should.be.true();

            done();
        });

        it("Should preserve existing validation logic for sum > 30%", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function() {
                    // Should not be called
                    assert.fail("DAO update should not be called for invalid total");
                }
            };

            mockReq.body.preTax = "20";
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "5"; // Total = 35%

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.updateError.should.equal("Contribution percentages cannot exceed 30 %");

            done();
        });

        it("Should preserve existing validation logic for NaN detection", function(done) {
            contributionsHandler.contributionsDAO = {
                update: function() {
                    // Should not be called
                    assert.fail("DAO update should not be called for NaN values");
                }
            };

            mockReq.body.preTax = "abc";
            mockReq.body.afterTax = "10";
            mockReq.body.roth = "5";

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            mockRes.rendered.should.be.true();
            mockRes.renderData.updateError.should.equal("Invalid contribution percentages");

            done();
        });
    });
});
