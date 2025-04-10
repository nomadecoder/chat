const net = require("net");
const crypto = require("crypto");
const { error } = require("console");
const readline = require("readline");
const { rejects } = require("assert");
const fs = require("fs");
/**
 * creates a request to the server
 * @param {string} serverHost
 * @param {number} serverPort
 * @param {string} route
 * @param {string} message
 * @returns
 */
const createRequest = (serverHost, serverPort, route, message) => {
    return new Promise((resolve, rejects) => {
        const client = net.createConnection({ host: serverHost, port: serverPort }, () => {
            //console.log(`Connecting to server ${serverHost}:${serverPort}`);
            client.write(
                JSON.stringify({
                    route: route,
                    message: message,
                })
            );
        });

        client.on("data", (data) => {
            try {
                resolve(JSON.parse(data.toString()));
                client.end(); // Close the connection after receiving the response
            } catch (error) {
                rejects(new Error(`Error parsing response from server: ${error}`));
            }
        });

        client.on("error", (error) => {
            console.log(`Connection error: ${error}`);
            rejects(error);
        });
    });
};

// Function to get PG (Prime and Generator)
const requestPG = (serverHost, serverPort) => {
    return createRequest(serverHost, serverPort, "getPG", {});
};

// Function get peer name
const getPeerName = (peerIP, peerPort) => {
    return createRequest(peerIP, peerPort, "getPeerName", {});
}

//encryptedRPG
// Function to get PG (Prime and Generator)
const requestPG_ = (serverHost, serverPort) => {
    return createRequest(serverHost, serverPort, "RPGEncrypted", {});
};

// Function to authenticate user
const authenticationRequest = (serverHost, serverPort, userName, password) => {
    return createRequest(serverHost, serverPort, "validateUser", { user: userName, password: password });
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
    const sharedSecret = dh.computeSecret(remotePublicKey, "hex", "hex");
    return sharedSecret;
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

// print text right aligned
function printRightAligned(text) {
    const consoleWidth = process.stdout.columns; // Get the console width
    const textLength = text.length;
    const padding = consoleWidth - textLength - 15  // Calculate the padding needed to align to the right

    if (padding > 0) {
        const paddedText = " ".repeat(padding) + text; // Add spaces before the text
        console.log(paddedText);
    } else {
        // If the text is longer than the console width, it will be printed as is
        console.log(text);
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
    const isValid = verifier.verify(
        {
            key: certificate,
            padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding
        },
        signature,
        "base64"
    );
    return isValid;
};

// Encrypt function
function encryptMessageRSA(message, certPath) {
    const publicKey = fs.readFileSync(certPath, "utf8"); // Read the certificate file (public key)
    const bufferMessage = Buffer.from(message, "utf8"); // Convert message to buffer
    const encryptedMessage = crypto.publicEncrypt(publicKey, bufferMessage);
    // Return encrypted message as a base64 string
    return encryptedMessage.toString("base64");
}

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
    requestPG_,
    hashMessage,
    printRightAligned,
    getPeerName
};
