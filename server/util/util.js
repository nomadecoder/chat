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
    return crypto.randomBytes(length).toString("hex");
};

const validateUser = (user, password) => {
    console.log(user, password);
    //initialize the response
    const validation = {validate: "false"};
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
    return signer.sign(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding
        },
        "base64"
    );
};

/**
 * Encrypts a message using AES-GCM encryption.
 *
 * @param {string} message - The plaintext message to be encrypted.
 *
 * @returns {string} - The encrypted message, which includes the IV, ciphertext, and authentication tag, in hex-encoded format.
 */
const encryptMessageAES = (message) => {
    // Generate a random 12-byte nonce/IV for AES-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");

    // Get the authentication tag
    const authTag = cipher.getAuthTag();

    // Concatenate the IV, ciphertext, and authentication tag to form the final encrypted message
    // The format will be:
    // - First 24 hex characters: 12-byte IV
    // - Followed by the ciphertext
    // - Last 32 hex characters: Authentication tag (authTag)
    return iv.toString("hex") + encrypted + authTag.toString("hex");
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

/**
 * Encrypts a message using the provided public key with padding (PKCS#1 v1.5).
 * @param {string} message - The message to encrypt.
 * @param {string} certPath - Path to the certificate file (public key).
 * @returns {string} The encrypted message as a base64 string.
 */
function encryptMessageRSA(message, certPath) {
    // Read the certificate (public key) from the file
    const publicKey = fs.readFileSync(certPath, "utf8");
    // Convert message to buffer
    const bufferMessage = Buffer.from(message, "utf8");
    // Encrypt the message using the public key and specify PKCS1 v1.5 padding
    const encryptedMessage = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding
        },
        bufferMessage
    );
    // Return encrypted message as a base64 string
    return encryptedMessage.toString("base64");
}

/**
 * Decrypts a message using the private key from a certificate file with padding (PKCS#1 v1.5).
 * @param {string} encryptedMessage - The encrypted message to decrypt.
 * @param {string} certPath - Path to the certificate file (private key).
 * @returns {string} The decrypted message as a UTF-8 string.
 */
function decryptMessageRSA(encryptedMessage, certPath) {
    // Read the certificate (private key) from the file
    const privateKey = fs.readFileSync(certPath, "utf8");
    // Convert the encrypted message from a base64 string to a buffer
    const bufferEncryptedMessage = Buffer.from(encryptedMessage, "base64");
    // Decrypt the message using the private key and specify PKCS1 v1.5 padding
    const decryptedMessage = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // PKCS#1 v1.5 padding
    }, bufferEncryptedMessage);
    // Return decrypted message as a UTF-8 string
    return decryptedMessage.toString("utf8");
}

/**
 * Generates a Diffie-Hellman instance from a prime number and a generator.
 * @param {string} prime - The prime number in hexadecimal.
 * @param {string} generator - The generator in hexadecimal.
 * @returns {crypto.DiffieHellman} The Diffie-Hellman instance.
 */
const generateDH = (prime, generator) => {
    const dh = crypto.createDiffieHellman(Buffer.from(prime, "hex"), Buffer.from(generator, "hex"));
    dh.generateKeys();
    return dh;
};

/**
 * Computes the shared secret using a Diffie-Hellman instance and a public key.
 * @param {crypto.DiffieHellman} dh - The Diffie-Hellman instance.
 * @param {string} publicKey - The public key in hexadecimal.
 * @returns {Buffer} The shared secret in hexadecimal.
 */
const computeSharedSecret = (dh, publicKey) => {
    return dh.computeSecret(Buffer.from(publicKey, "hex"));
};

/**
 * Converts an object to a base64 encoded string and hashes it using SHA-512.
 * This prepares the object to be used for a signature with signMessageRSA()
 * @param {object} data - The object to hash.
 * @returns {string} The hexadecimal representation of the hash.
 */
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
