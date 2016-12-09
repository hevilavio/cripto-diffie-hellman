import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

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
        Dhell program = new Dhell();
        program.validateInput(args);

        String person = args[0];

        switch (person){
            case "A": {
                log("Starting Alice");
                final Socket socket = program.waitBobToConnect();

                new DiffieHellmanAlgorithm().playAlice(socket);


            }
        }

        log("OK");
    }

    private Socket waitBobToConnect() {
        try {
            ServerSocket server = new ServerSocket(SOCKET_PORT);
            log("Waiting for someone to connect on port " + SOCKET_PORT);
            final Socket socket = server.accept();

            logDebugMessage(socket);

            return socket;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void logDebugMessage(Socket socket) {
        final InetSocketAddress remoteSocketAddress = (InetSocketAddress) socket.getRemoteSocketAddress();
        debug("Someone connected on " + SOCKET_PORT
                + ", remote_addr=" + remoteSocketAddress.getAddress().getHostAddress()
                + ", remote_port=" + remoteSocketAddress.getPort());
    }

    private void validateInput(String[] args) {
        if(args == null || args.length == 0){
            err("Invalid Usage. Shoud be: 'java Dhell A|B|C'");
            System.exit(-1);
        }
    }

    private static void err(String msg) {
        System.err.println(msg);
    }

    private static void log(String msg) {
        System.out.println(msg);
    }

    private void debug(String msg) {
        if(DEBUG_ENABLED){
            log(msg);
        }
    }
}

class DiffieHellmanAlgorithm {

    BigInteger modulus_p = BigInteger.valueOf(23L);
    BigInteger base_g = BigInteger.valueOf(5L);

    byte msg_A_identifier = 0x01;

    public void playAlice(Socket socket) {
        Logger.info("Playing Alice's role");

        BigInteger secret = chooseSecret(6);
        Logger.info("[SECRET] Alice choose [" + secret.longValue() + "] as her secret");

        final BigInteger A = base_g.pow(secret.intValue()).mod(modulus_p);
        Logger.info("Sending [" + A.longValue() + "] as A value to Bob");

        sendAValue(socket, A.toByteArray());
        //waitForBValue(socket);

    }

    private void sendAValue(Socket socket, byte[] bytes) {
        try {
            final OutputStream out = socket.getOutputStream();
            out.write(msg_A_identifier);
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

    private boolean DEBUG_ENABLED = true;

    public static void err(String msg) {
        System.err.println(msg);
    }

    public static void info(String msg) {
        System.out.println(msg);
    }

    public void debug(String msg) {
        if(DEBUG_ENABLED){
            info(msg);
        }
    }
}
