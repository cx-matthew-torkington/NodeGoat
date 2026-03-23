"use strict";

const SqliDAO = require("../data/sqli-dao");
const ESAPI = require("node-esapi");

function SqliHandler(db) {
    const sqliDAO = new SqliDAO();

    this.displaySearch = (req, res) => {
        const { environmentalScripts } = require("../../config/config");

        if (!req.query.name) {
            return res.render("sqli", {
                environmentalScripts,
                results: null,
                searchName: "",
                error: null
            });
        }

        const searchName = req.query.name;

        // VULNERABLE: SqliDAO.searchByName concatenates searchName directly into SQL
        sqliDAO.searchByName(searchName, (err, rows) => {
            if (err) {
                return res.render("sqli", {
                    environmentalScripts,
                    results: null,
                    searchName: ESAPI.encoder().encodeForHTML(searchName),
                    error: "Query error: " + err.message
                });
            }

            return res.render("sqli", {
                environmentalScripts,
                results: rows,
                searchName: ESAPI.encoder().encodeForHTML(searchName),
                error: null
            });
        });
    };
}

module.exports = SqliHandler;
