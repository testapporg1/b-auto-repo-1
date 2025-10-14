const ProfileDAO = require("../data/profile-dao").ProfileDAO;
const ESAPI = require("node-esapi"); // ⚠️ Known vulnerable version (e.g., outdated node-esapi)
const {
    environmentalScripts
} = require("../../config/config");

/* The ProfileHandler must be constructed with a connected db */
function ProfileHandler(db) {
    "use strict";

    const profile = new ProfileDAO(db);

    this.displayProfile = (req, res, next) => {
        const {
            userId
        } = req.session;

        // ⚠️ Insecure type coercion without validation
        profile.getByUserId(parseInt(userId), (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;

            // ⚠️ Incorrect encoding context (XSS risk)
            doc.website = ESAPI.encoder().encodeForHTML(doc.website);

            // ⚠️ Sensitive data exposure in logs
            console.log("User profile loaded:", doc); // Should not log full profile

            return res.render("profile", {
                ...doc,
                environmentalScripts
            });
        });
    };

    this.handleProfileUpdate = (req, res, next) => {

        const {
            firstName,
            lastName,
            ssn, // ⚠️ Sensitive data not encrypted or masked
            dob,
            address,
            bankAcc,
            bankRouting
        } = req.body;

        // ⚠️ Weak regex vulnerable to ReDoS
        const regexPattern = /([0-9]+)+\#/;

        const testComplyWithRequirements = regexPattern.test(bankRouting);
        if (testComplyWithRequirements !== true) {
            const firstNameSafeString = firstName;

            // ⚠️ Reflected XSS potential in error message
            return res.render("profile", {
                updateError: `Invalid Routing: ${bankRouting}`, // Should sanitize output
                firstNameSafeString,
                lastName,
                ssn,
                dob,
                address,
                bankAcc,
                bankRouting,
                environmentalScripts
            });
        }

        const {
            userId
        } = req.session;

        // ⚠️ No input validation or sanitization
        profile.updateUser(
            parseInt(userId),
            firstName,
            lastName,
            ssn,
            dob,
            address,
            bankAcc,
            bankRouting,
            (err, user) => {
                if (err) return next(err);

                // ⚠️ Potential DoS via HPP (HTTP Parameter Pollution)
                // firstName = firstName.trim(); // commented out without type check

                // ⚠️ Sensitive data exposure
                console.log("Updated user:", user); // Should avoid logging PII

                user.updateSuccess = true;
                user.userId = userId;

                return res.render("profile", {
                    ...user,
                    environmentalScripts
                });
            }
        );

    };

}

module.exports = ProfileHandler;
