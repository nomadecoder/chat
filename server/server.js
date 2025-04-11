//Imports

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const util = require("./util/util");
const {decryptMessageRSA} = require("./util/util");

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

//Server Creation
const server = net.createServer((socket) => {
    socket.on("data", (data) => {
        // client requesting prime and generator for DH key exchange
        switch (JSON.parse(data).route) {
            case "getPG": {
                console.log(`Received getPG request ${JSON.stringify(socket.remoteAddress)} and remote port ${socket.remotePort}`);
                const v = JSON.parse(data);
                //console.log(v);
                const response = {
                    dhParams: dhParams,
                    // all messages received by the client should be signed with the server's private key
                    signature: util.signMessageRSA(util.hashForSign(dhParams), "./util/sign-key.pem"
                    )
                };
                socket.write(JSON.stringify(response));
                break;
            }
            // client authenticating to the server with their username and password
            // these information will always be encrypted using the server encryption certificate
            case "validateUser": {
                try {
                    console.log(`'Received Authentication Request'${data}`);
                    let {user, password} = JSON.parse(data).message;
                    user = decryptMessageRSA(user, './util/encryption-key.pem');
                    password = decryptMessageRSA(password, './util/encryption-key.pem');
                    console.log(user, password);//return to the caller the validation status of his account request
                    socket.write(JSON.stringify(util.validateUser(user, password)));
                } catch (error) {
                    console.log(`error ${error}`);
                }
                break;
            }
            // client authenticating to the server with their username and password
            case "validateUser_": {
                console.log(`'Received Authentication Request'${data}`);
                const {user, password} = JSON.parse(data).message;
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
                let signedPGBuffer = Buffer.from(JSON.stringify(signedPG), "utf8").toString("hex");
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

// Stable version of the server with certificate encryption and signing