const MemosDAO = require("../data/memos-dao").MemosDAO;
const {
    environmentalScripts
} = require("../../config/config");
const esapi = require("node-esapi");

function MemosHandler(db) {
    "use strict";

    const memosDAO = new MemosDAO(db);

    this.addMemos = (req, res, next) => {

        memosDAO.insert(req.body.memo, (err, docs) => {
            if (err) return next(err);
            this.displayMemos(req, res, next);
        });
    };

    this.displayMemos = (req, res, next) => {

        const {
            userId
        } = req.session;

        memosDAO.getAllMemos((err, docs) => {
            if (err) return next(err);
            // Sanitize userId to prevent XSS attacks
            const sanitizedUserId = userId ? esapi.encoder().encodeForHTML(String(userId)) : '';
            return res.render("memos", {
                memosList: docs,
                userId: sanitizedUserId,
                environmentalScripts
            });
        });
    };

}

module.exports = MemosHandler;
