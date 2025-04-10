const crypto = require("crypto");
const fs = require("fs");
const database = require("./database");

// Function to hash a password using SHA-512
const hashMessage = (password, salt = "") => {
    const hash = crypto.createHash("sha512");
    hash.update(password + salt);
    const hashedMessage = hash.digest("hex");
    return {
        salt: salt,
        hashedMessage: hashedMessage,
    }; // Return both salt and hashedPassword;
};
/**
 * Create a salt of the specified length a random value for each time the function is called
 * for this purpose we are using a string of alphanumeric characters more randomized values
 * should be used in a production environment
 * @param {number} length the length of the salt
 * @return {string} salt the value of the salt
 */
const saltGenerator = (length = 16) => {
    // Ensure the length is a positive integer
    const salt = crypto.randomBytes(length).toString("hex");
    return salt;
};

const validateUser = (user, password) => {
    console.log(user, password);
    //initialize the response
    const validation = { validate: "false" };
    //find the user in the databse
    const account = database.find((account) => account.user === user);
    //log information
    console.log(account);
    if (account.password === hashMessage(password, account.salt).hashedMessage) {
        //return true if the user exist and his password is correct
        console.log("the account exist");
        validation.validate = true;
    }
    return validation;
};
/**
 * Signs a message using a private key with padding (PKCS#1 v1.5).
 * @param {string} message - The message to sign.
 * @param {string} privateKeyPath - Path to the private key file.
 * @returns {string} The signed message (base64 encoded with padding).
 */
const signMessageRSA = (message, privateKeyPath) => {
    // Read the private key from the file
    const privateKey = fs.readFileSync(privateKeyPath, "utf8");
    // Create a signer with 'RSA-SHA256' and specify PKCS1 v1.5 padding
    const signer = crypto.createSign("RSA-SHA256");
    // Update the signer with the message
    signer.update(message);
    // Sign the message using the private key and explicitly set PKCS1 v1.5 padding
    const signature = signer.sign(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding
        },
        "base64"
    );
    return signature;
};

// Encrypt the message using AES-GCM
const encryptMessageAES = (message) => {
    const iv = crypto.randomBytes(12); // AES-GCM uses a 12-byte nonce/IV
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag(); // Get the authentication tag
    return iv.toString("hex") + encrypted + authTag.toString("hex"); // Concatenate IV, ciphertext, and authTag
};

// Decrypt the message using AES-GCM
const decryptMessageAES = (encryptedMessage) => {
    const iv = Buffer.from(encryptedMessage.slice(0, 24), "hex"); // Extract the 12-byte IV (24 hex chars)
    const encryptedText = encryptedMessage.slice(24, -32); // Extract the encrypted text (everything before the authTag)
    const authTag = Buffer.from(encryptedMessage.slice(-32), "hex"); // Extract the authTag (last 32 hex chars)
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(authTag); // Set the authTag to verify integrity during decryption
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
};

// Encrypt function
function encryptMessageRSA(message, certPath) {
    const publicKey = fs.readFileSync(certPath, "utf8"); // Read the certificate file (public key)
    const bufferMessage = Buffer.from(message, "utf8"); // Convert message to buffer
    const encryptedMessage = crypto.publicEncrypt(publicKey, bufferMessage);
    // Return encrypted message as a base64 string
    return encryptedMessage.toString("base64");
}

// Decrypt function
function decryptMessageRSA(encryptedMessage, certPath) {
    const privateKey = fs.readFileSync(certPath, "utf8"); // Read the certificate file (private key)
    const bufferEncryptedMessage = Buffer.from(encryptedMessage, "base64"); // Convert base64 string to buffer
    const decryptedMessage = crypto.privateDecrypt(privateKey, bufferEncryptedMessage);
    // Return decrypted message as a UTF-8 string
    return decryptedMessage.toString("utf8");
}

const generateDH = (prime, generator) => {
    const dh = crypto.createDiffieHellman(Buffer.from(prime, "hex"), Buffer.from(generator, "hex"));
    dh.generateKeys();
    return dh;
};

const computeSharedSecret = (dh, publicKey) => {
    return dh.computeSecret(Buffer.from(publicKey, "hex"));
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
/*
/ Example usage:
const length = 16; // Specify the length of the hex string you want
const randomHex = generateRandomHex(length);
console.log(randomHex); // This will print a random hexadecimal string of length 16

// Example usage:
const password = 'mySecurePassword';
const salt = 'randomSalt';  // Ideally, generate a unique salt for each password

const hashedPassword = hashPassword(password, salt);
console.log('Hashed Password:', hashedPassword);
*/

module.exports = {
    saltGenerator,
    validateUser,
    signMessageRSA,
    encryptMessageAES,
    decryptMessageAES,
    hashMessage,
    encryptMessageRSA,
    decryptMessageRSA,
    generateDH,
    computeSharedSecret,
    hashForSign
};
