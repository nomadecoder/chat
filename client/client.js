const util = require("./util/util.js");
const utilServer = require("../server/util/util.js");
const crypto = require("crypto");
const fs = require("fs");
const { request } = require("http");

/**
 * Prompts the user for a password and returns it as a Promise.
 */

// // Example usage
let message = "This is a test message.";

const signature = utilServer.signMessageRSA(message, "../server/sign-key.pem");
console.log("Signed Message:", signature);

message = "This is a test message..";
const isValid = util.verifyRSASignedMessage(message, signature, "sign-cert.pem");
console.log("Is the signature valid?", isValid);

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

const t = {
    dhParams: {
        prime: "b135c70a820a13c9789862a8b6df1d060cfcb5e606edc4ff108ebccc2638bad4a110643562a6554f9ddab14b761324d2951cd6999129c00a835e75a69bbdbf3f",
        generator: "02",
    },
};

//console.log("the message is", utilServer.hashMessage(JSON.stringify(t)).hashedMessage);


const t64 = Buffer.from(JSON.stringify(t)).toString("base64");
const hash = crypto.createHash("sha512");
const thash = hash.update(t64).digest("hex");
//console.log(thash)
console.log("util hashForsgin",utilServer.hashForSign(t64));
//const tsign = utilServer.signMessageRSA(utilServer.hashForSign(t64), "../server/sign-key.pem");
// console.log(JSON.stringify(t));
//console.log(thash, tsign);

 


function printRightAligned(text) {
    const consoleWidth = process.stdout.columns; // Get the console width
    const textLength = text.length;
    const padding = consoleWidth - textLength;  // Calculate the padding needed to align to the right
    
    if (padding > 0) {
      const paddedText = ' '.repeat(padding) + text;  // Add spaces before the text
      console.log(paddedText);
    } else {
      // If the text is longer than the console width, it will be printed as is
      console.log(text);
    }
  }
    

     