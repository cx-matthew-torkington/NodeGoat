"use strict";

// NOTE: This DAO intentionally uses an in-memory SQLite database with
// unsanitised string concatenation to demonstrate SQL Injection (OWASP A1).
// DO NOT use this pattern in production code.

const sqlite3 = require("sqlite3").verbose();

// Seed data — a fictional employee directory
const SEED_EMPLOYEES = [
    { name: "Alice Johnson",  department: "Engineering",  salary: 95000, email: "alice@retireeasy.com" },
    { name: "Bob Martinez",   department: "Finance",      salary: 82000, email: "bob@retireeasy.com" },
    { name: "Carol Williams", department: "HR",           salary: 74000, email: "carol@retireeasy.com" },
    { name: "David Lee",      department: "Engineering",  salary: 105000, email: "david@retireeasy.com" },
    { name: "Eve Davis",      department: "Marketing",   salary: 68000, email: "eve@retireeasy.com" },
    { name: "Frank Wilson",   department: "Finance",     salary: 91000, email: "frank@retireeasy.com" },
    { name: "Grace Brown",    department: "Engineering", salary: 99000, email: "grace@retireeasy.com" },
    { name: "Henry Taylor",   department: "Management",  salary: 130000, email: "henry@retireeasy.com" },
];

function SqliDAO() {
    // Create a shared in-memory SQLite database and populate it once
    this.db = new sqlite3.Database(":memory:");

    const db = this.db;

    db.serialize(() => {
        db.run(`CREATE TABLE employees (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            department TEXT    NOT NULL,
            salary     INTEGER NOT NULL,
            email      TEXT    NOT NULL
        )`);

        const stmt = db.prepare(
            "INSERT INTO employees (name, department, salary, email) VALUES (?, ?, ?, ?)"
        );
        SEED_EMPLOYEES.forEach(emp => {
            stmt.run(emp.name, emp.department, emp.salary, emp.email);
        });
        stmt.finalize();
    });
}

// VULNERABLE: user input is concatenated directly into the SQL query string.
// Attack examples:
//   ' OR '1'='1        → returns all rows (authentication bypass style)
//   ' OR 1=1--         → returns all rows (comment strips rest of query)
//   ' UNION SELECT id,name,email,salary,department FROM employees--  → UNION dump
SqliDAO.prototype.searchByName = function(name, callback) {
    // VULN: Raw string concatenation — never do this in real code
    const query = "SELECT id, name, department, email FROM employees WHERE name = '" + name + "'";
    console.log("[SQLi demo] Executing query:", query);
    this.db.all(query, [], callback);
};

module.exports = SqliDAO;
