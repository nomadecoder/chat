const {rejects} = require("assert");
const util = require("./util/util");
const crypto = require("crypto");
const net = require("net");

let aesKey;
let sharedSecret;
let encrypt = false;
let sendSocket = null; // Global variable to hold the socket for sending messages

// Chat function - handles both server and client side logic
// @param {string} peerIP - IP address of the peer
// @param {number} peerPort - Port number of the peer
// @param {number} listeningPort - Port number to listen for incoming peer connections
// @param {crypto.DiffieHellman} dh - Diffie-Hellman instance
// @param {string} peerName - Name of the peer
const chat = async (peerIP, peerPort, listeningPort, dh, peerName) => {
    // Server to listen for incoming peer connections and handle data (receiving side)
    const server = net.createServer((socket) => {
        socket.on("data", async (data) => {
            data = JSON.parse(data);
            switch (data.route) {
                case "dhKeyExchange": {
                    peerName = data.message.myname;
                    // computing the share secret
                    sharedSecret = util.computeDHSharedSecret(dh, data.message.publicKey);
                    // After the key exchange, derive the AES key
                    aesKey = crypto.createHash("sha256").update(sharedSecret).digest();
                    // Once the key exchange is complete, prompt the user to start chatting
                    promptUser(); // Call to prompt the user for messages
                    break;
                }
                case "message": {
                    // Handle incoming messages
                    const message = data.message;
                    if (encrypt) {
                        const decryptedMessage = util.decryptMessageAES(message, aesKey);
                        util.printRightAligned(`${decryptedMessage} <${peerName}`);
                        promptUser();
                    } else {
                        util.printRightAligned(`${message} <${peerName}`);
                    }
                    break;
                }
                case "getPeerName": {
                    console.log(`Received peer name request: `);
                    break;
                }
                default:
                    console.log("Unknown route");
            }
        });

        socket.on("error", (err) => {
            console.log(`Socket error: ${err.message}`);
        });

        socket.on("close", () => {
            console.log("Connection closed");
        });
    });

    // Start listening for incoming peer connections (for receiving messages)
    server.listen(listeningPort, () => {
        console.log(`Listening for messages on port ${listeningPort}`);
    });

    // Client function to connect to peer and initiate key exchange (sending side)
    /**
     * Connects to the peer and initiates the key exchange (sending side)
     * @returns {void}
     */
    const connectToPeer = () => {
        // Create a new socket connection to the peer
        sendSocket = net.createConnection({host: peerIP, port: peerPort}, () => {
            console.log("Successfully connected to peer (sending socket)");
            // If encryption is enabled, initiate the key exchange
            if (encrypt) {
                // Send the public key to the peer for key exchange
                sendSocket.write(JSON.stringify({
                    route: "dhKeyExchange", message: {
                        publicKey: dh.getPublicKey("hex"), myname: username,
                    },
                }));
            } else {
                // If encryption is disabled, send a message to the peer to get their name
                sendSocket.write(JSON.stringify({
                    route: "getPeerName", message: {
                        myname: username,
                    },
                }));
            }
        });
        // Handle errors when connecting to the peer
        sendSocket.on("error", (err) => {
            console.log(`Error connecting to peer: ${err.message}`);
            // Retry connection after 5 seconds if error occurs
            setTimeout(connectToPeer, 5000);
        });

        // Handle connection close event
        sendSocket.on("close", () => {
            console.log("Connection to peer closed (sending socket)");
        });
    };
    // Start the connection attempt for sending messages
    return connectToPeer();
};

// Send messages to peer socket
const sendMessage = (message) => {
    if (encrypt) {
        const encryptedMessage = util.encryptMessageAES(message, aesKey);
        sendSocket.write(JSON.stringify({
            route: "message", message: encryptedMessage,
        }));
    } else {
        sendSocket.write(JSON.stringify({
            route: "message", message: message,
        }));
    }
};

// Updated promptUser function to display username and allow for dynamic user input
let promptUserCalled = false; // Flag to track if promptUser has been called

const promptUser = () => {
    if (promptUserCalled) return; // Prevent multiple invocations
    promptUserCalled = true; // Set the flag to true once it's called

    //console.log("Initializing promptUser function"); // Log when promptUser is called
    const readline = require("readline");
    const rl = readline.createInterface({
        input: process.stdin, // Use process.stdin directly
        output: process.stdout, prompt: `${username}> `,
    });
    //console.clear();
    rl.prompt(); // Show the prompt

    rl.on("line", (line) => {
        const trimmedLine = line.trim(); // Remove any spaces or tabs from the beginning and end

        if (trimmedLine) {
            sendMessage(trimmedLine); // Send message to peer
        }

        // Clear the input and directly return to the prompt
        rl.write(null, {ctrl: true, name: "u"}); // Clear the current input
        console.clear();
        rl.prompt(); // Show the prompt again immediately
    });

    rl.on("close", () => {
        // Ensure that on exit, we clean up the input stream
        console.log("Connection closed.");
    });
};

async function main(peerIP, peerPort, serverIP, serverPort, listeningPort, username, password) {
    try {
        console.log(`User ${username}, started the app`);
        // User authentication, the authentication request are sent to the server encrypted using RSA
        // the server's encryption certificate is used to encrypt the message
        const auth = await util.authenticationRequest(serverIP, serverPort, util.encryptMessageRSA(username, 'encryption-cert.pem'), util.encryptMessageRSA(password, 'encryption-cert.pem'));
        if (JSON.parse(auth.validate)) {
            console.log(`Welcome ${username}, you are now authenticated`);
            if (encrypt) {
                // message coming from the server are signed, verify the validity of the message signature from the server using the cert
                const serverResponse = await util.requestPG(serverIP, serverPort);
                let dhParams;
                if (util.verifyRSASignedMessage(util.hashForSign(serverResponse.dhParams), serverResponse.signature, "sign-cert.pem")) {
                    console.log(`Server signature verified`);
                    dhParams = serverResponse.dhParams;
                } else {
                    console.log(`Server signature not verified`);
                }
                const {dh} = util.initializeDH(dhParams.prime, dhParams.generator);
                if (dhParams) {
                    console.log(dhParams);
                    // Start chat by passing peer socket into chat function
                    await chat(peerIP, peerPort, listeningPort, dh); // Passed listeningPort

                    // Now that chat has begun, we can call promptUser and pass the socket
                    promptUser();
                } else {
                    console.log("Unable to retrieve prime and generator from the server");
                }
            } else {
                console.log("Encryption is not enabled. You can still chat without encryption.");
                //const peerName = await util.getPeerName(peerIP, peerPort);
                //console.log(peerName)
                // Start chat by passing peer socket into chat function
                await chat(peerIP, peerPort, listeningPort); // Passed listeningPort

                // Now that chat has begun, we can call promptUser and pass the socket
                promptUser();
            }
        } else {
            console.log(`Username or Password Incorrect`);
        }
    } catch (error) {
        console.error(`An unhandled error occurred see below the message: ${error}`);
    }
}

// Read command line arguments
const [peerIP, peerPort, serverIP, serverPort, listeningPort, username, password, encryptFlag] = process.argv.slice(2);

// Check if encryption is enabled
encrypt = encryptFlag === "--encrypt";

if (!peerIP || !peerPort || !serverIP || !serverPort || !listeningPort || !username || !password) {
    console.log("Usage: node app.js <remotePeerIP> <remotePeerPort> <serverIP> <serverPort> <myListeningPort> <username> <password> [encrypt]");
    process.exit(1);
}

// Run the application
main(peerIP, peerPort, serverIP, serverPort, listeningPort, username, password);

//Stable working version of the app without the server certificate verification steps involved.

//nodemon app.js localhost 5001 localhost 3349 5000 'chris' 'Password' --encrypt
//nodemon app.js localhost 5000 localhost 3349 5001 'alvin' 'Password' --encrypt
