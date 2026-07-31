const { environmentalScripts } = require("../../config/config");
const pkg = require("../../package.json");

function StatusHandler(db) {
    "use strict";

    this.displayStatus = (req, res) => {
        db.command({ ping: 1 }, (err) => {
            const status = {
                appName: pkg.name,
                version: pkg.version,
                status: err ? "degraded" : "ok",
                database: err ? "unavailable" : "connected",
                uptimeSeconds: Math.floor(process.uptime()),
                timestamp: new Date().toISOString()
            };

            if (req.accepts(["html", "json"]) === "json") {
                return res.json(status);
            }

            return res.render("status", {
                environmentalScripts,
                status
            });
        });
    };
}

module.exports = StatusHandler;
