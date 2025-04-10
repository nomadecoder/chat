const { rejects } = require("assert");
const util = require("./util/util");
const crypto = require("crypto");
const net = require("net");

let aesKey;
let sharedSecret;
let encrypt = false;
let sendSocket = null; // Global variable to hold the socket for sending messages

// Chat function - handles both server and client side logic
const chat = async (peerIP, peerPort, listeningPort, dh, peerName) => {
    // Added listeningPort parameter
    if (encrypt) {
        publicKey = dh.getPublicKey("hex");
        //console.log(`My public key: ${publicKey}`);
        privateKey = dh.getPrivateKey("hex");
    }
    // Server to listen for incoming peer connections and handle data (receiving side)
    const server = net.createServer((socket) => {
        receiveSocket = socket; // Assign the server socket to the receiveSocket

        socket.on("data", async (data) => {
            data = JSON.parse(data);
            //console.log(data)
            switch (data.route) {
                case "dhKeyExchange": {
                    peerName = data.message.myname;
                    //console.log(peerName)
                    // logs encryption information for debugging purposes only
                    //if (encrypt) console.log(`Computing the shared key${encrypt}`);
                    // computing the share secret
                    sharedSecret = util.computeDHSharedSecret(dh, data.message.publicKey);
                    // log the shared secret for debugging purposes only
                    //if (encrypt) console.log(`Shared secret: ${sharedSecret}`);
                    // After the key exchange, derive the AES key
                    aesKey = crypto.createHash("sha256").update(sharedSecret).digest();
                    // log the AES key for debugging purposes only
                    //console.log(`AES key derived: ${aesKey.toString("hex")}`);
                    // Once the key exchange is complete, prompt the user to start chatting
                    //console.log("Key exchange complete. You can start sending messages.");
                    promptUser(); // Call to prompt the user for messages
                    break;
                }
                case "message": {
                    // Handle incoming messages
                    const message = data.message;
                    if (encrypt) {
                        const decryptedMessage = util.decryptMessageAES(message, aesKey);
                        //console.log(`Received from ${peerName} (encrypted): ${decryptedMessage}`);
                        util.printRightAligned(`${decryptedMessage} <${peerName}`);
                        promptUser();
                    } else {
                        util.printRightAligned(`${message} <${peerName}`);
                        //console.log(`Received from ${peerName}: ${message}`);
                    }
                    break;
                }
                case "getPeerName": {
                    console.log(`Received peer name: `);
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
    const connectToPeer = () => {
        sendSocket = net.createConnection({ host: peerIP, port: peerPort }, () => {
            console.log("Successfully connected to peer (sending socket)");
            if (encrypt) {
                sendSocket.write(
                    JSON.stringify({
                        route: "dhKeyExchange",
                        message: {
                            publicKey: publicKey,
                            myname: username,
                        },
                    })
                );
            }
            else{
                sendSocket.write(
                    JSON.stringify({
                        route: "getPeerName",
                        message: {
                            myname: username,
                        },
                    })
                );
            }
        });

        sendSocket.on("error", (err) => {
            console.log(`Error connecting to peer: ${err.message}`);
            setTimeout(connectToPeer, 5000); // Retry connection after 5 seconds if error occurs
        });

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
        sendSocket.write(
            JSON.stringify({
                route: "message",
                message: encryptedMessage,
            })
        );
    } else {
        sendSocket.write(
            JSON.stringify({
                route: "message",
                message: message,
            })
        );
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
        output: process.stdout,
        prompt: `${username}> `,
    });
    //console.clear();
    rl.prompt(); // Show the prompt

    rl.on("line", (line) => {
        const trimmedLine = line.trim(); // Remove any spaces or tabs from the beginning and end

        if (trimmedLine) {
            sendMessage(trimmedLine); // Send message to peer
        }

        // Clear the input and directly return to the prompt
        rl.write(null, { ctrl: true, name: "u" }); // Clear the current input
        console.clear();
        rl.prompt(); // Show the prompt again immediately
    });

    rl.on("close", () => {
        // Ensure that on exit, we clean up the input stream
        console.log("Connection closed.");
    });
};

async function main(peerIP, peerPort, serverIP, serverPort, listeningPort, username, password) {
    console.log(`User ${username}, started the app`);
    const auth = await util.authenticationRequest(serverIP, serverPort, username, password);
    console.log(JSON.parse(auth.validate));
    if (JSON.parse(auth.validate)) {
        console.log(`Welcome ${username}, you are now authenticated`);

        if (encrypt) {
            const dhParams = await util.requestPG(serverIP, serverPort);
            const { dh } = util.initializeDH(dhParams.prime, dhParams.generator);
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
            //const dhParams = await util.requestPG(serverIP, serverPort);
            //console.log(dhParams);
            //const { dh } = util.initializeDH(dhParams.prime, dhParams.generator);

            // Start chat by passing peer socket into chat function
            await chat(peerIP, peerPort, listeningPort); // Passed listeningPort

            // Now that chat has begun, we can call promptUser and pass the socket
            promptUser();
        }
    } else {
        console.log(`Username or Password Incorrect`);
    }
}

// Read command line arguments
const [peerIP, peerPort, serverIP, serverPort, listeningPort, username, password, encryptFlag] = process.argv.slice(2);

// Check if encryption is enabled
encrypt = encryptFlag === "--encrypt";

if (!peerIP || !peerPort || !serverIP || !serverPort || !listeningPort || !username || !password) {
    console.log(
        "Usage: node app.js <remotePeerIP> <remotePeerPort> <serverIP> <serverPort> <myListeningPort> <username> <password> [encrypt]"
    );
    process.exit(1);
}

// Run the application
main(peerIP, peerPort, serverIP, serverPort, listeningPort, username, password);

//Stable working version of the app without the server certificate verification steps involved.

//nodemon app.js localhost 5001 localhost 3349 5000 'chris' 'Password' --encrypt
//nodemon app.js localhost 5000 localhost 3349 5001 'alvin' 'Password' --encrypt
