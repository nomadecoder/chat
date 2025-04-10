//Imports

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const util = require("./util/util");

// General Variables
const port = 3349;
/**
 * Creates a Diffie-Hellman prime and generator pair and returns them in an object.
 * these values will be sent to the client to be used for key calculations and exchange
 * @param {number} bits - The number of bits for the prime number.
 * @returns {object} - An object containing the prime and generator values.
 * @prime {string} - The prime number in hexadecimal format.
 * @generator {string} - The generator in hexadecimal format.
 */
const dh = crypto.createDiffieHellman(512);
const dhParams = {
    prime: dh.getPrime().toString("hex"),
    generator: dh.getGenerator().toString("hex"),
};
const hashForSign = (data) => {
    //convert data to buffer 64 before hash
    console.log(data)
    const t64 = Buffer.from(JSON.stringify(data)).toString("base64");
    const hash = crypto.createHash("sha512");
    const dhash = hash.update(t64).digest("hex");
    console.log(dhash);
    return dhash;
    

};
//Server Creation
const server = net.createServer((socket) => {
    socket.on("data", (data) => {
        // client requesting prime and generator for DH key exchange
        switch (JSON.parse(data).route) {
            case "getPG": {
                console.log("Received getPG request");
                const v = JSON.parse(data);
                console.log(v);
                socket.write(JSON.stringify(dhParams));
                break;
            }
            case "getPG_": {
                console.log("Received getPG request");
                const v = JSON.parse(data);
                console.log(v);
                socket.write(JSON.stringify(dhParams));
                break;
            }
            // client authenticating to the server with their username and password
            case "validateUser": {
                console.log(`'Received Authentication Request'${data}`);
                const { user, password } = JSON.parse(data).message;
                //return to the caller the validation status of his account request
                socket.write(JSON.stringify(util.validateUser(user, password)));
                break;
            }
            // client authenticating to the server with their username and password
            case "validateUser_": {
                console.log(`'Received Authentication Request'${data}`);
                const { user, password } = JSON.parse(data).message;
                //return to the caller the validation status of his account request
                socket.write(JSON.stringify(util.validateUser(user, password)));
                break;
            }
            // client requesting RPG through encrypted channel
            case "RPGEncrypted": {
                //console.log("Received RPGEncrypted request");
                const pgHash = util.hashMessage(dhParams).hashedMessage;
                const signedPGHash = util.signMessageRSA(pgHash, "../server/sign-key.pem");
                const signedPG = {
                    signedPGHash: signedPGHash,
                    dhParams: dhParams,
                };
                signedPGBuffer = Buffer.from(JSON.stringify(signedPG), "utf8").toString("hex");
                console.log(pgHash, signedPGHash, signedPGBuffer);
                socket.write(JSON.stringify(signedPGBuffer));
                break;
            }
            default:
                console.log(`Received unknown request: ${data}`);
        }
    });
    socket.on("error", (error) => {
        console.log(`connection lost from peer`);
    });
});

server.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

// Stable version of the server without the server certificate verification steps involved for client version 0.0.8 and below
