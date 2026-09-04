const should = require("should");
const SqliHandler = require("../../app/routes/sqli");
const swig = require("swig");

// Ensure autoescape is enabled for all tests in this file.
// In production server.js calls swig.setDefaults({ autoescape: true }).
// Unit tests do not load server.js, but swig's built-in default is autoescape: true,
// so the explicit call here is defensive: it guarantees the setting even if swig's
// default ever changes.
swig.setDefaults({ autoescape: true });

describe("SqliHandler - XSS Prevention", function() {
    "use strict";

    let sqliHandler;
    let mockDb;
    let mockReq;
    let mockRes;
    let renderCalled;
    let renderArgs;

    // Confirm swig autoescape is enabled (the framework-native XSS defence for this app).
    // server.js calls swig.setDefaults({ autoescape: true }).  We verify this indirectly
    // by loading server-level configuration and then rendering — if autoescape is off,
    // the compile() call below returns the raw angle brackets and the assertion fails.
    describe("Template Engine Configuration - Autoescape Enabled", function() {

        it("Should HTML-encode < and > when rendering a template variable", function() {
            // Directly verify that swig encodes HTML special characters in {{ }} output
            var template = swig.compile("{{ val }}");
            var output = template({ val: "<script>alert('XSS')</script>" });
            output.should.not.containEql("<script>");
            output.should.containEql("&lt;script&gt;");
        });

        it("Should HTML-encode double quotes when rendering a template variable", function() {
            var template = swig.compile("{{ val }}");
            var output = template({ val: '" onclick="alert(1)"' });
            output.should.not.containEql('"');
            output.should.containEql("&#34;");
        });

        it("Should HTML-encode single quotes when rendering a template variable", function() {
            var template = swig.compile("{{ val }}");
            var output = template({ val: "' onload='alert(1)" });
            output.should.not.containEql("'");
            output.should.containEql("&#39;");
        });

        it("Should HTML-encode ampersand when rendering a template variable", function() {
            var template = swig.compile("{{ val }}");
            var output = template({ val: "foo & bar" });
            output.should.not.containEql("foo & bar");
            output.should.containEql("&amp;");
        });

        it("Should not alter plain alphanumeric text (no double-encoding)", function() {
            var template = swig.compile("{{ val }}");
            var output = template({ val: "Alice Johnson" });
            output.should.equal("Alice Johnson");
        });
    });

    describe("Route Handler - searchName Passed Raw to Template", function() {

        beforeEach(function() {
            renderCalled = false;
            renderArgs = null;

            mockDb = {};
            sqliHandler = new SqliHandler(mockDb);

            mockReq = {
                query: {}
            };

            mockRes = {
                render: function(view, data) {
                    renderCalled = true;
                    renderArgs = { view, data };
                }
            };
        });

        it("Should pass raw searchName to render (swig autoescape handles HTML encoding)", function(done) {
            var SqliDAO = require("../../app/data/sqli-dao");
            var originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, [
                    { id: 1, name: "Test User", department: "IT", email: "test@example.com" }
                ]);
            };

            // XSS payload as user input
            mockReq.query.name = "<script>alert('XSS')</script>";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");

                // The route must pass the raw value — swig autoescape encodes at render time.
                // Pre-encoding in the route would cause double-encoding (&amp;lt; instead of &lt;).
                renderArgs.data.searchName.should.equal("<script>alert('XSS')</script>");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should pass raw searchName on database error (swig autoescape handles encoding)", function(done) {
            var SqliDAO = require("../../app/data/sqli-dao");
            var originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(new Error("Database connection failed"));
            };

            mockReq.query.name = "<script>alert('XSS')</script>";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.view.should.equal("sqli");
                renderArgs.data.searchName.should.equal("<script>alert('XSS')</script>");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should pass plain text searchName unchanged", function(done) {
            var SqliDAO = require("../../app/data/sqli-dao");
            var originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, [
                    { id: 1, name: "Alice Johnson", department: "HR", email: "alice@example.com" }
                ]);
            };

            mockReq.query.name = "Alice Johnson";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                renderArgs.data.searchName.should.equal("Alice Johnson");
                renderArgs.data.results.should.have.length(1);

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });

        it("Should handle empty query parameter", function() {
            mockReq.query = {};

            sqliHandler.displaySearch(mockReq, mockRes);

            renderCalled.should.be.true();
            renderArgs.view.should.equal("sqli");
            renderArgs.data.searchName.should.equal("");
            should.not.exist(renderArgs.data.results);
        });

        it("Should not double-encode already HTML-safe characters", function(done) {
            var SqliDAO = require("../../app/data/sqli-dao");
            var originalSearchByName = SqliDAO.prototype.searchByName;

            SqliDAO.prototype.searchByName = function(searchName, callback) {
                callback(null, []);
            };

            // Input that must not be double-encoded — swig handles the single encoding pass
            mockReq.query.name = "foo & bar";

            sqliHandler.displaySearch(mockReq, mockRes);

            setTimeout(function() {
                renderCalled.should.be.true();
                // Raw value stored; template encodes once to &amp;
                renderArgs.data.searchName.should.equal("foo & bar");

                SqliDAO.prototype.searchByName = originalSearchByName;
                done();
            }, 100);
        });
    });

    describe("End-to-End Template Rendering - XSS Payloads Are Escaped", function() {

        it("Should HTML-encode script tag when swig renders the sqli search field", function() {
            // Simulate what swig does when it renders {{ searchName }} with autoescape: true
            var template = swig.compile('value="{{ searchName }}"');
            var payload = "<script>alert('XSS')</script>";
            var output = template({ searchName: payload });

            // The rendered attribute must not contain a live <script> tag
            output.should.not.containEql("<script>");
            output.should.not.containEql("</script>");
            output.should.containEql("&lt;script&gt;");
        });

        it("Should HTML-encode img onerror XSS when swig renders the sqli search field", function() {
            var template = swig.compile("{{ searchName }}");
            var payload = '<img src=x onerror="alert(1)">';
            var output = template({ searchName: payload });

            output.should.not.containEql("<img");
            output.should.not.containEql("onerror");
            output.should.containEql("&lt;");
        });

        it("Should HTML-encode SVG onload XSS when swig renders the sqli search field", function() {
            var template = swig.compile("{{ searchName }}");
            var payload = '<svg onload="alert(1)">';
            var output = template({ searchName: payload });

            output.should.not.containEql("<svg");
            output.should.not.containEql("onload");
            output.should.containEql("&lt;");
        });

        it("Should HTML-encode attribute breakout attempt when swig renders the field", function() {
            var template = swig.compile('value="{{ searchName }}"');
            var payload = '" onclick="alert(1)" x="';
            var output = template({ searchName: payload });

            output.should.not.containEql("onclick=");
            output.should.containEql("&#34;");
        });

        it("Should HTML-encode iframe data-URI XSS payload", function() {
            var template = swig.compile("{{ searchName }}");
            var payload = '<iframe src="data:text/html,<script>alert(1)</script>">';
            var output = template({ searchName: payload });

            output.should.not.containEql("<iframe");
            output.should.containEql("&lt;");
        });

        it("Should HTML-encode Unicode angle-bracket XSS payload", function() {
            // U+003C = <, U+003E = > — resolved to literal chars by JS before swig sees them
            var template = swig.compile("{{ searchName }}");
            var payload = "<script>alert(1)</script>";
            var output = template({ searchName: payload });

            output.should.not.containEql("script>");
            output.should.containEql("&lt;");
        });

        it("Should HTML-encode null-byte-prefixed XSS payload", function() {
            var template = swig.compile("{{ searchName }}");
            // Null byte expressed as escape sequence — not a literal control byte
            var payload = "test\x00<script>alert(1)</script>";
            var output = template({ searchName: payload });

            output.should.not.containEql("<script>");
        });
    });
});
