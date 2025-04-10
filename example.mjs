// importing the net module
import net from "node:net";

// creating the server
const server = net.createServer((socket) => {
    console.log(`The user is connected with IP:Port ${socket.remoteAddress}:${socket.remotePort} connected`);
    // 'connection' listener.
    socket.write("hello world\r\n");
    // when a disconnect is detected
    socket.on("end", () => {
        console.log("client disconnected");
    });
    socket.pipe(socket);
});
server.on("error", (err) => {
    throw err;
});
server.listen(8124, () => {
    console.log(`\nserver is listening on port bound ${server.address().port} \n`);
});
