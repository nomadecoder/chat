const util = require("./util");
const userDB = require("./database");
const [user, password] = process.argv.slice(2);
const fs = require("fs");
const dbPath = "./database.js";
/**
 * Create a new user based on the provided username and password
 * @param {string} username
 * @param {string} password
 *
 */
const createUser = (username, password) => {
    console.log(userDB);
    const userAccount = userDB.find((account) => {
        //console.log(account.user.toLowerCase()===username.toLowerCase());
        return account.user.toLowerCase() === username.toLowerCase();
    });
    const accountExist = userAccount ? true : false;
    //console.log(JSON.stringify(accountExist));
    if (!accountExist) {
        const salt = util.saltGenerator(16);
        const hashedPassword = util.hashMessage(password, salt);
        const account = {
            user: username,
            password: hashedPassword.hashedMessage,
            salt: hashedPassword.salt,
        };
        userDB.push(account);
        const newDB = `module.exports = ${JSON.stringify(userDB)}`;
        fs.writeFileSync(dbPath, newDB, (err) => {
            if (!err) console.log(`user ${username}, successfuly created`);
            else console.log(`unable to create user ${username}, contact the administrator`);
        });
    } else {
        console.log(`\nAn account with the name ${user} already exists, chose another user name and try again;\n`);
    }
};

createUser(user, password);
const dbContent = JSON.stringify(userDB);
//console.log(JSON.parse(dbContent));

//usage node user.js username password
