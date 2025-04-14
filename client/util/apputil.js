const net = require("net");
const crypto = require("crypto");
const fs = require("fs");
/**
 * Creates a request to the server general function to send any type of request to the server
 * @param {string} serverHost
 * @param {number} serverPort
 * @param {string} route
 * @param {{user, password}} message
 * @returns {Promise<any>}
 */
const createRequest = (serverHost, serverPort, route, message) => {
    return new Promise((resolve, rejects) => {
        const client = net.createConnection({host: serverHost, port: serverPort}, () => {
            client.write(
                JSON.stringify({
                    route: route,
                    message: message,
                })
            );
        });
        // Handle incoming data from the server or peer socket
        client.on("data", (data) => {
            try {
                resolve(JSON.parse(data.toString()));
                client.end(); // Close the connection after receiving the response
            } catch (error) {
                rejects(new Error(`Error parsing response from server: ${error}`));
            }
        });
        // Handle errors
        client.on("error", (error) => {
            console.log(`Connection error: ${error}`);
            rejects(error);
        });
    });
};

// Function to get PG (Prime and Generator)
const requestPG = (serverHost, serverPort) => {
    //console.log("requesting prime and generator from the server")
    return createRequest(serverHost, serverPort, "getPG", {});
};

// Function get peer name
const getPeerName = (peerIP, peerPort) => {
    console.log('sending request to peer')
    return createRequest(peerIP, peerPort, "getPeerName", {});
}

// Function to authenticate user
const authenticationRequest = (serverHost, serverPort, userName, password) => {
    return createRequest(serverHost, serverPort, "validateUser", {user: userName, password: password});
};

// Function to For DH Key Exchange
const diffieHellmanKeyExchange = (peerIP, peerPort, myPublicKey) => {
    console.log(`received from peer ${peerIP}`);
    return createRequest(peerIP, peerPort, "dhKeyExchange", myPublicKey);
};
/**
 * Initialize the Diffie-Hellman key exchange with provided p and g.
 * @param {string} primeHex - The prime number in hexadecimal.
 * @param {string} generatorHex - The generator in hexadecimal.
 * @returns {{ dh: crypto.DiffieHellman, publicKey: string, privateKey: string }}
 */
const initializeDH = (primeHex, generatorHex) => {
    const primeBuffer = Buffer.from(primeHex, "hex");
    const generatorBuffer = Buffer.from(generatorHex, "hex");
    const dh = crypto.createDiffieHellman(primeBuffer, generatorBuffer);
    dh.generateKeys();
    return {
        dh,
    };
};
/** compute a shared secret based on a peer's public key
 * @param {crypto.DiffieHellman} dh - Diffie-Hellman instance.
 * @param {string} remotePublicKey - The peer's public key in hexadecimal.
 * @returns {string} - The shared secret in hexadecimal.
 * */
const computeDHSharedSecret = (dh, remotePublicKey) => {
    return dh.computeSecret(remotePublicKey, "hex", "hex");
};

/**
 * Encrypts a message using AES-GCM encryption.
 *
 * @param {string} message - The plaintext message to be encrypted.
 * @param {Buffer} aesKey - The AES key (32 bytes for AES-256) used for encryption.
 *
 * @returns {string} - The encrypted message, which includes the IV, ciphertext, and authentication tag, in hex-encoded format.
 */
const encryptMessageAES = (message, aesKey) => {
    const iv = crypto.randomBytes(12); // AES-GCM uses a 12-byte nonce/IV
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag(); // Get the authentication tag
    // Concatenate the IV, ciphertext, and authentication tag to form the final encrypted message
    // The format will be:
    // - First 24 hex characters: 12-byte IV
    // - Followed by the ciphertext
    // - Last 32 hex characters: Authentication tag (authTag)
    return iv.toString("hex") + encrypted + authTag.toString("hex"); // Concatenate IV, ciphertext, and authTag
};

/**
 * Decrypts an AES-GCM encrypted message.
 * @param {string} encryptedMessage - The encrypted message that includes the IV, encrypted text, and authentication tag.
 *      The format should be a hex-encoded string with:
 *      - The first 24 hex characters being the 12-byte IV (Initialization Vector).
 *      - The next part being the encrypted ciphertext.
 *      - The last 32 hex characters being the authentication tag (authTag).
 * @param {Buffer} aesKey - The AES key (32 bytes for AES-256) used for decryption.
 *
 * @returns {string} - The decrypted message in UTF-8 format.
 */
const decryptMessageAES = (encryptedMessage, aesKey) => {
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
 * Prints text right aligned in the console.
 * If the text exceeds the console width, it is printed as is.
 *
 * @param {string} text - The text to print right aligned.
 */
function printRightAligned(text) {
    const consoleWidth = process.stdout.columns; // Get the console width of the terminal
    const textLength = text.length; // Calculate the length of the input text
    const padding = consoleWidth - textLength - 15; // Calculate the padding needed to align text to the right

    if (padding > 0) {
        const paddedText = " ".repeat(padding) + text; // Create the padded text
        console.log(paddedText); // Print the padded text
    } else {
        console.log(text); // Print the text as is if it exceeds the console width
    }
}

/**
 /**
 * Verifies a signed message using the public key from a certificate file with padding (PKCS#1 v1.5).
 * @param {string} message - The original message.
 * @param {string} signature - The signature to verify.
 * @param {string} certificatePath - Path to the certificate file (public key).
 * @returns {boolean} True if the signature is valid, false otherwise.
 */
const verifyRSASignedMessage = (message, signature, certificatePath) => {
    // Read the certificate (public key) from the file
    const certificate = fs.readFileSync(certificatePath, "utf8");
    // Create a verifier with 'RSA-SHA256' and specify PKCS1 v1.5 padding
    const verifier = crypto.createVerify("RSA-SHA256");
    // Update the verifier with the message
    verifier.update(message);
    // Verify the signature using the public key (certificate) and explicitly set PKCS1 v1.5 padding
    return verifier.verify(
        {
            key: certificate,
            padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding
        },
        signature,
        "base64"
    );
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
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // PKCS#1 v1.5 padding
        },
        bufferMessage
    );
    // Return encrypted message as a base64 string
    return encryptedMessage.toString("base64");
}

/**
 * Function to hash a password using SHA-512.
 * @param {string} password - The password to hash.
 * @param {string} [salt=""] - The salt to use when hashing the password.
 * @returns {object} - An object containing the salt and the hashed password.
 */
const hashMessage = (password, salt = "") => {
    const hash = crypto.createHash("sha512");
    hash.update(password + salt);
    const hashedMessage = hash.digest("hex");
    return {
        salt,
        hashedMessage,
    };
}
/**
 * Converts an object to a base64 encoded string and hashes it using SHA-512.
 * This prepares the object to be used for a signature with signMessageRSA()
 * @param {object} data - The object to hash.
 * @returns {string} The hexadecimal representation of the hash.
 */
const hashForSign = (data) => {
    //convert data to buffer 64 before hash
    //console.log(data)
    const t64 = Buffer.from(JSON.stringify(data)).toString("base64");
    const hash = crypto.createHash("sha512");
    return hash.update(t64).digest("hex");
};
// Export functions
module.exports = {
    requestPG,
    initializeDH,
    verifyRSASignedMessage,
    authenticationRequest,
    diffieHellmanKeyExchange,
    computeDHSharedSecret,
    encryptMessageAES,
    decryptMessageAES,
    encryptMessageRSA,
    hashMessage,
    printRightAligned,
    getPeerName,
    hashForSign
};
