import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

/**
 *
 * A
 * B
 * C
 *
 *
 * */
public class Dhell {

    private final int SOCKET_PORT = 9090;
    private boolean DEBUG_ENABLED = true;

    // A,B,C |
    public static void main(String[] args) {

        final BigInteger bigInteger = new BigInteger(new byte[] { 0x10 });

        Dhell program = new Dhell();
        program.validateInput(args);

        String person = args[0];

        switch (person){
            case "A": {
                Logger.info("Starting Alice");
                final Socket socket = program.startConnectionAsServer();
                new DiffieHellmanAlgorithm().playAlice(socket);
                break;
            }
            case "B": {
                Logger.info("Starting Bob");
                final Socket socket = program.startConnectionAsClient();
                new DiffieHellmanAlgorithm().playBob(socket);
                break;
            }

        }

        Logger.info("END");
    }

    private Socket startConnectionAsClient() {
        try {
            final Socket socket = new Socket("localhost", SOCKET_PORT);
            logDebugMessage(socket);
            return socket;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private Socket startConnectionAsServer() {
        try {
            ServerSocket server = new ServerSocket(SOCKET_PORT);
            Logger.info("Waiting for someone to connect on port " + SOCKET_PORT);
            final Socket socket = server.accept();

            logDebugMessage(socket);

            return socket;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void logDebugMessage(Socket socket) {
        final InetSocketAddress remoteSocketAddress = (InetSocketAddress) socket.getRemoteSocketAddress();
        Logger.debug(
                "Connected on " + SOCKET_PORT + ", remote_addr=" + remoteSocketAddress.getAddress().getHostAddress()
                        + ", remote_port=" + remoteSocketAddress.getPort());
    }

    private void validateInput(String[] args) {
        if(args == null || args.length == 0){
            Logger.err("Invalid Usage. Shoud be: 'java Dhell A|B|C'");
            System.exit(-1);
        }
    }
}

class DiffieHellmanAlgorithm {

    BigInteger modulus_p = BigInteger.valueOf(23L);
    BigInteger base_g = BigInteger.valueOf(5L);

    private int HEADER_LENGTH = 4;

    public void playAlice(Socket socket) {

        BigInteger secret = chooseSecret(6);
        Logger.info("[SECRET] Alice choose [" + secret.longValue() + "] as her secret");

        final BigInteger A = base_g.pow(secret.intValue()).mod(modulus_p);
        Logger.info("Sending [" + A.longValue() + "] as A value to Bob");

        writeValue(socket, A.toByteArray());
        final BigInteger B = readValue(socket);

        Logger.info("Alice received [" + B.longValue() + "] as Bob's B value");

        // SHARED SECRET
        Logger.debug("B(" + B.longValue() + ") ^ secret(" + secret.longValue() + ") % p("
                + modulus_p.longValue() + ")");

        final BigInteger s = B.pow(secret.intValue()).mod(modulus_p);
        Logger.info("Shared secret is [" + s.longValue() + "]");
    }

    public void playBob(Socket socket) {

        final BigInteger A = readValue(socket);
        Logger.info("Bob received [" + A.longValue() + "] as Alice's A value");

        BigInteger secret = chooseSecret(15);
        Logger.info("[SECRET] Bob choose [" + secret.longValue() + "] as his secret");

        final BigInteger B = base_g.pow(secret.intValue()).mod(modulus_p);
        Logger.info("Sending [" + B.longValue() + "] as B value to Alice");

        writeValue(socket, B.toByteArray());

        // SHARED SECRET
        Logger.debug("A(" + A.longValue() + ") ^ secret(" + secret.longValue() + ") % p("
                + modulus_p.longValue() + ")");

        final BigInteger s = A.pow(secret.intValue()).mod(modulus_p);
        Logger.info("Shared secret is [" + s.longValue() + "]");


    }

    private BigInteger readValue(Socket socket) {

        byte[] header = new byte[HEADER_LENGTH];

        try {
            final InputStream inputStream = socket.getInputStream();

            for (int i = 0; i < HEADER_LENGTH; i++) {
                header[i] = (byte) inputStream.read();
            }
            final int messageSize = ByteBuffer.wrap(header).getInt();
            Logger.debug("Received a message with [" + messageSize + "] bytes");

            final byte[] buffer = ByteBuffer.allocate(messageSize).array();
            inputStream.read(buffer);

            final BigInteger message = new BigInteger(buffer);

            Logger.debug("Message with [" + messageSize + "] bytes has value = " + message.longValue());

            return message;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeValue(Socket socket, byte[] bytes) {
        try {
            final OutputStream out = socket.getOutputStream();
            final byte[] messageLength = ByteBuffer.allocate(HEADER_LENGTH).putInt(bytes.length).array();

            out.write(messageLength);
            out.write(bytes);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private BigInteger chooseSecret(int seed) {
        // for now, let's assume the number itself
        return BigInteger.valueOf(seed);
    }
}

class Logger {

    private static boolean DEBUG_ENABLED = false;

    public static void err(String msg) {
        System.err.println(msg);
    }

    public static void info(String msg) {
        System.out.println(msg);
    }

    public static void debug(String msg) {
        if(DEBUG_ENABLED){
            info(msg);
        }
    }
}
