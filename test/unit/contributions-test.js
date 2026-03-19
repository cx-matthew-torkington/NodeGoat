const should = require("should");
const ContributionsHandler = require("../../app/routes/contributions");

describe("ContributionsHandler - Code Injection Prevention", function() {
    "use strict";

    let contributionsHandler;
    let mockDb;
    let mockReq;
    let mockRes;
    let mockNext;
    let updateCalled;
    let updateArgs;
    let renderCalled;
    let renderArgs;

    beforeEach(function() {
        // Reset state
        updateCalled = false;
        updateArgs = null;
        renderCalled = false;
        renderArgs = null;

        // Mock database
        mockDb = {
            collection: function() {
                return {
                    update: function(query, doc, options, callback) {
                        updateCalled = true;
                        updateArgs = { query, doc, options };
                        // Simulate successful update
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, {
                            preTax: 5,
                            afterTax: 5,
                            roth: 5
                        });
                    }
                };
            }
        };

        // Create handler instance
        contributionsHandler = new ContributionsHandler(mockDb);

        // Mock request object
        mockReq = {
            body: {},
            session: {
                userId: "1"
            }
        };

        // Mock response object
        mockRes = {
            render: function(view, data) {
                renderCalled = true;
                renderArgs = { view, data };
            }
        };

        // Mock next function
        mockNext = function(err) {
            // Error handler
        };
    });

    describe("Security - Code Injection Prevention", function() {

        it("Should safely parse numeric string input without executing code", function(done) {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "5"
            };

            // Mock the DAO to verify safe values are passed
            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        // Verify that numeric values are properly parsed
                        doc.preTax.should.equal(10);
                        doc.afterTax.should.equal(10);
                        doc.roth.should.equal(5);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            // Mock UserDAO
            const originalRequire = require;
            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

        it("Should block code injection attempt via preTax parameter", function() {
            // Attempt to inject code using eval-style payload
            mockReq.body = {
                preTax: "process.exit(1)", // Malicious payload
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            // Should render error because parseFloat returns NaN for malicious input
            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should block code injection attempt via afterTax parameter", function() {
            mockReq.body = {
                preTax: "5",
                afterTax: "require('fs').readFileSync('/etc/passwd')", // Malicious payload
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should block code injection attempt via roth parameter", function() {
            mockReq.body = {
                preTax: "5",
                afterTax: "5",
                roth: "console.log('pwned')" // Malicious payload
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should block code injection with function call syntax", function() {
            mockReq.body = {
                preTax: "(() => { return 10; })()", // Immediately invoked function
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should block code injection with mathematical expressions that include code", function() {
            mockReq.body = {
                preTax: "10 + process.exit()",
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should block injection attempts using global object access", function() {
            mockReq.body = {
                preTax: "global.process.mainModule.require('child_process').execSync('ls')",
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

    });

    describe("Functionality - Valid Input Handling", function() {

        it("Should accept valid positive integer strings", function(done) {
            mockReq.body = {
                preTax: "10",
                afterTax: "8",
                roth: "7"
            };

            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        doc.preTax.should.equal(10);
                        doc.afterTax.should.equal(8);
                        doc.roth.should.equal(7);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

        it("Should accept valid decimal numbers", function(done) {
            mockReq.body = {
                preTax: "5.5",
                afterTax: "3.2",
                roth: "1.3"
            };

            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        doc.preTax.should.equal(5.5);
                        doc.afterTax.should.equal(3.2);
                        doc.roth.should.equal(1.3);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

        it("Should accept zero as valid input", function(done) {
            mockReq.body = {
                preTax: "0",
                afterTax: "10",
                roth: "5"
            };

            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        doc.preTax.should.equal(0);
                        doc.afterTax.should.equal(10);
                        doc.roth.should.equal(5);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

    });

    describe("Validation - Negative Cases", function() {

        it("Should reject negative numbers", function() {
            mockReq.body = {
                preTax: "-5",
                afterTax: "10",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject when sum exceeds 30%", function() {
            mockReq.body = {
                preTax: "15",
                afterTax: "10",
                roth: "10"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Contribution percentages cannot exceed 30 %");
        });

        it("Should reject non-numeric strings", function() {
            mockReq.body = {
                preTax: "abc",
                afterTax: "10",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject empty strings", function() {
            mockReq.body = {
                preTax: "",
                afterTax: "10",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject null values", function() {
            mockReq.body = {
                preTax: null,
                afterTax: "10",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

        it("Should reject undefined values", function() {
            mockReq.body = {
                preTax: undefined,
                afterTax: "10",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

    });

    describe("Edge Cases - Boundary Testing", function() {

        it("Should accept exactly 30% total contribution", function(done) {
            mockReq.body = {
                preTax: "10",
                afterTax: "10",
                roth: "10"
            };

            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        (doc.preTax + doc.afterTax + doc.roth).should.equal(30);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

        it("Should reject 30.01% total contribution", function() {
            mockReq.body = {
                preTax: "10.01",
                afterTax: "10",
                roth: "10"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Contribution percentages cannot exceed 30 %");
        });

        it("Should handle very small positive decimal values", function(done) {
            mockReq.body = {
                preTax: "0.01",
                afterTax: "0.01",
                roth: "0.01"
            };

            mockDb.collection = function() {
                return {
                    update: function(query, doc, options, callback) {
                        doc.preTax.should.equal(0.01);
                        doc.afterTax.should.equal(0.01);
                        doc.roth.should.equal(0.01);
                        callback(null);
                    },
                    findOne: function(query, callback) {
                        callback(null, null);
                    }
                };
            };

            require("../../app/data/user-dao").UserDAO = function() {
                this.getUserById = function(id, callback) {
                    callback(null, {
                        userName: "testuser",
                        firstName: "Test",
                        lastName: "User"
                    });
                };
            };

            contributionsHandler = new ContributionsHandler(mockDb);
            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.updateSuccess.should.be.true();
                done();
            }, 50);
        });

        it("Should handle scientific notation as invalid (parseFloat behavior)", function() {
            mockReq.body = {
                preTax: "1e2", // This would parse to 100, which exceeds 30%
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            // Should fail because 100 + 5 + 5 > 30
            renderArgs.data.updateError.should.equal("Contribution percentages cannot exceed 30 %");
        });

        it("Should reject strings with leading/trailing whitespace containing code", function() {
            mockReq.body = {
                preTax: "  process.exit()  ",
                afterTax: "5",
                roth: "5"
            };

            contributionsHandler.handleContributionsUpdate(mockReq, mockRes, mockNext);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("contributions");
            renderArgs.data.updateError.should.equal("Invalid contribution percentages");
        });

    });

});
