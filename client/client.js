const util = require("./util/util.js");
const utilServer = require("../server/util/util.js");
const crypto = require("crypto");
const fs = require("fs");
const {request} = require("http");

/**
 * Prompts the user for a password and returns it as a Promise.
 */

// // Example usage


const main = async () => {
    const message = await util.requestPG("127.0.0.1", 3349);
    if (util.verifyRSASignedMessage(util.hashForSign(message), message.signature, "sign-cert.pem")) {
        console.log(`the signature is valid we can do stuff like print the dhparams and use it in code`);
        console.log(message);
    }
    const encryptedMessage = util.encryptMessageRSA("hello", "sign-cert.pem");
    console.log(encryptedMessage);
    const decryptedMessage = utilServer.decryptMessageRSA(encryptedMessage, '../server/util/sign-key.pem');
    console.log(decryptedMessage);

}

main()
// // Encrypt function
// function encryptMessageRSA(message, certPath) {
//     const publicKey = fs.readFileSync(certPath, "utf8"); // Read the certificate file (public key)
//     const bufferMessage = Buffer.from(message, "utf8"); // Convert message to buffer
//     const encryptedMessage = crypto.publicEncrypt(publicKey, bufferMessage);
//     // Return encrypted message as a base64 string
//     return encryptedMessage.toString("base64");
// }

// // Decrypt function
// function decryptMessageRSA(encryptedMessage, certPath) {
//     const privateKey = fs.readFileSync(certPath, "utf8"); // Read the certificate file (private key)
//     const bufferEncryptedMessage = Buffer.from(encryptedMessage, "base64"); // Convert base64 string to buffer
//     const decryptedMessage = crypto.privateDecrypt(privateKey, bufferEncryptedMessage);
//     // Return decrypted message as a UTF-8 string
//     return decryptedMessage.toString("utf8");
// }

// // Example usage:
// // Encrypt a message
// const encryptionCert = "encryption-cert.pem"; // Path to your certificate file
// const encryptionKey = "../server/encryption-key.pem";
// message = "Hello, this is a secret message!";
// const encryptedMessage = encryptMessageRSA(message, encryptionCert);
// console.log("Encrypted Message:", encryptedMessage);

// // Decrypt the message
// const decryptedMessage = decryptMessageRSA(encryptedMessage, encryptionKey);
// console.log("Decrypted Message:", decryptedMessage);
//{
//    dhParams: dhParams,
//    signature: util.signMessageRSA((hash.update(dhParams), "../server/sign-key.pem"),
// //}

// const dhSignedMessage = util.requestPG_("127.0.0.1", 3349);
// dhSignedMessage.then((data) => {
//     const bData = Buffer.from(data, "hex");
//     const bString = bData.toString("utf8");
//     console.log(JSON.parse(bString));
//     const { signedPGHash, dhParams } = JSON.parse(bString);
//     console.log(signedPGHash);
//     console.log(util.verifyRSASignedMessage(util.hashMessage(dhParams).hashedMessage, signedPGHash, "sign-cert.pem"));
//     //console.log(Buffer.from(data, "hex"));
// });



