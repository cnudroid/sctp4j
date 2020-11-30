package com.env.java11.dtls;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

public class SslEngineUtils {

    private static int MAXIMUM_PACKET_SIZE = 1024;
    private static int MAX_HANDSHAKE_LOOPS = 200;
    private static int MAX_APP_READ_LOOPS = 60;

    public static int BUFFER_SIZE = 1024;

    private static Exception serverException = null;
    private static Exception clientException = null;

    /*
     * =============================================================
     * The remainder is support stuff for DTLS operations.
     */
    public static SSLEngine createSSLEngine(boolean isClient) throws Exception {
        SSLContext context = getDTLSContext();
        SSLEngine engine = context.createSSLEngine();

        SSLParameters paras = engine.getSSLParameters();
        paras.setMaximumPacketSize(MAXIMUM_PACKET_SIZE);

        engine.setUseClientMode(isClient);
        engine.setSSLParameters(paras);

        return engine;
    }

    // get DTSL context
    public static SSLContext getDTLSContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = "passphrase".toCharArray();

        final String keyFilename = "rsa2048.jks";
        final String keyPasswd = "student";
        final String trustFilename = "rsa2048.jks";
        final String trustPasswd = "student";

        try (FileInputStream fis = new FileInputStream("src/test/resources/"+keyFilename)) {
            ks.load(fis, keyPasswd.toCharArray());
        }

        try (FileInputStream fis = new FileInputStream("src/test/resources/"+trustFilename)) {
            ts.load(fis, trustPasswd.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, keyPasswd.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("DTLS");

        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslCtx;
    }


    // handshake
   public static SocketAddress handshake(SSLEngine engine, DatagramSocket socket, SocketAddress serverAddr,
                    String side) throws Exception {

        boolean endLoops = false;
        SocketAddress clientAddr = null;
        int loops = MAX_HANDSHAKE_LOOPS;
        engine.beginHandshake();
        int applicationBufferSize = engine.getSession().getApplicationBufferSize();
        while (!endLoops &&
                (serverException == null) && (clientException == null)) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            log(side, "=======handshake(" + loops + ", " + hs + ")=======");
            if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                    hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {

                log(side, "Receive DTLS records, handshake status is " + hs);

                ByteBuffer iNet;
                ByteBuffer iApp;
                if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    byte[] buf = new byte[BUFFER_SIZE];
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    try {
                        socket.receive(packet);
                        log(side, "RCVD Packet: " + packet.getAddress().getHostAddress() +":" +packet.getPort());
                        clientAddr = packet.getSocketAddress();
                    } catch (SocketTimeoutException ste) {
                        log(side, "Warning: " + ste);

                        List<DatagramPacket> packets = new ArrayList<>();
                        boolean finished = onReceiveTimeout(
                                engine, clientAddr, side, packets);

                        log(side, "Reproduced " + packets.size() + " packets");
                        for (DatagramPacket p : packets) {
                            printHex("Reproduced packet",
                                    p.getData(), p.getOffset(), p.getLength());
                            socket.send(p);
                        }

                        if (finished) {
                            log(side, "Handshake status is FINISHED "
                                    + "after calling onReceiveTimeout(), "
                                    + "finish the loop");
                            endLoops = true;
                        }

                        log(side, "New handshake status is "
                                + engine.getHandshakeStatus());

                        continue;
                    }

                    iNet = ByteBuffer.wrap(buf, 0, packet.getLength());
                    iApp = ByteBuffer.allocate(BUFFER_SIZE);
                } else {
                    iNet = ByteBuffer.allocate(0);
                    iApp = ByteBuffer.allocate(BUFFER_SIZE);
                }

                SSLEngineResult r = engine.unwrap(iNet, iApp);
                SSLEngineResult.Status rs = r.getStatus();
                hs = r.getHandshakeStatus();
                if (rs == SSLEngineResult.Status.OK) {
                    // OK
                } else if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    log(side, "BUFFER_OVERFLOW, handshake status is " + hs);

                    // the client maximum fragment size config does not work?
                    throw new Exception("Buffer overflow: " +
                            "incorrect client maximum fragment size");
                } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    log(side, "BUFFER_UNDERFLOW, handshake status is " + hs);

                    // bad packet, or the client maximum fragment size
                    // config does not work?
                    if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        throw new Exception("Buffer underflow: " +
                                "incorrect client maximum fragment size");
                    } // otherwise, ignore this packet
                } else if (rs == SSLEngineResult.Status.CLOSED) {
                    throw new Exception(
                            "SSL engine closed, handshake status is " + hs);
                } else {
                    throw new Exception("Can't reach here, result is " + rs);
                }

                if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    log(side, "Handshake status is FINISHED, finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                List<DatagramPacket> packets = new ArrayList<>();
                if(serverAddr == null){
                    serverAddr = clientAddr;
                }
                boolean finished = produceHandshakePackets(
                        engine, serverAddr, side, packets);

                log(side, "Produced " + packets.size() + " packets");
                for (DatagramPacket p : packets) {
                    socket.send(p);
                }

                if (finished) {
                    log(side, "Handshake status is FINISHED "
                            + "after producing handshake packets, "
                            + "finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runDelegatedTasks(engine);
            } else if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                log(side,
                        "Handshake status is NOT_HANDSHAKING, finish the loop");
                endLoops = true;
            } else if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                throw new Exception(
                        "Unexpected status, SSLEngine.getHandshakeStatus() "
                                + "shouldn't return FINISHED");
            } else {
                throw new Exception(
                        "Can't reach here, handshake status is " + hs);
            }
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        log(side, "Handshake finished, status is " + hs);

        if (engine.getHandshakeSession() != null) {
            throw new Exception(
                    "Handshake finished, but handshake session is not null");
        }

        SSLSession session = engine.getSession();
        if (session == null) {
            throw new Exception("Handshake finished, but session is null");
        }
        log(side, "Negotiated protocol is " + session.getProtocol());
        log(side, "Negotiated cipher suite is " + session.getCipherSuite());
       int packetBufferSize = session.getPacketBufferSize();
       int applicationBufferSize1 = session.getApplicationBufferSize();
       log(side, "packetBufferSize" + packetBufferSize);
       log(side, "applicationBufferSize" + applicationBufferSize1);

       // handshake status should be NOT_HANDSHAKING
        //
        // According to the spec, SSLEngine.getHandshakeStatus() can't
        // return FINISHED.
        if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            throw new Exception("Unexpected handshake status " + hs);
        }
        return clientAddr;
    }

    static void log(String side, String message) {
        System.out.println(side + ": " + message);
    }

    final static void printHex(String prefix, ByteBuffer bb) {
        //HexDumpEncoder  dump = new HexDumpEncoder();

        synchronized (System.out) {
            System.out.println(prefix);
            try {
                //  dump.encodeBuffer(bb.slice(), System.out);
            } catch (Exception e) {
                // ignore
            }
            System.out.flush();
        }
    }

    final static void printHex(String prefix,
                               byte[] bytes, int offset, int length) {

        // HexDumpEncoder  dump = new HexDumpEncoder();

        synchronized (System.out) {
            System.out.println(prefix);
            try {
                ByteBuffer bb = ByteBuffer.wrap(bytes, offset, length);
                // dump.encodeBuffer(bb, System.out);
            } catch (Exception e) {
                // ignore
            }
            System.out.flush();
        }
    }

    // Get a datagram packet for the specified handshake type.
    static DatagramPacket getPacket(
            List<DatagramPacket> packets, byte handshakeType) {
        boolean matched = false;
        for (DatagramPacket packet : packets) {
            byte[] data = packet.getData();
            int offset = packet.getOffset();
            int length = packet.getLength();

            // Normally, this pakcet should be a handshake message
            // record.  However, even if the underlying platform
            // splits the record more, we don't really worry about
            // the improper packet loss because DTLS implementation
            // should be able to handle packet loss properly.
            //
            // See RFC 6347 for the detailed format of DTLS records.
            if (handshakeType == -1) {      // ChangeCipherSpec
                // Is it a ChangeCipherSpec message?
                matched = (length == 14) && (data[offset] == 0x14);
            } else if ((length >= 25) &&    // 25: handshake mini size
                    (data[offset] == 0x16)) {   // a handshake message

                // check epoch number for initial handshake only
                if (data[offset + 3] == 0x00) {     // 3,4: epoch
                    if (data[offset + 4] == 0x00) { // plaintext
                        matched =
                                (data[offset + 13] == handshakeType);
                    } else {                        // cipherext
                        // The 1st ciphertext is a Finished message.
                        //
                        // If it is not proposed to loss the Finished
                        // message, it is not necessary to check the
                        // following packets any mroe as a Finished
                        // message is the last handshake message.
                        matched = (handshakeType == 20);
                    }
                }
            }

            if (matched) {
                return packet;
            }
        }

        return null;
    }

    // run delegated tasks
    static void runDelegatedTasks(SSLEngine engine) throws Exception {
        Runnable runnable;
        while ((runnable = engine.getDelegatedTask()) != null) {
            runnable.run();
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            throw new Exception("handshake shouldn't need additional tasks");
        }
    }

    // retransmission if timeout
    static boolean onReceiveTimeout(SSLEngine engine, SocketAddress socketAddr,
                             String side, List<DatagramPacket> packets) throws Exception {

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return false;
        } else {
            // retransmission of handshake messages
            return produceHandshakePackets(engine, socketAddr, side, packets);
        }
    }

    // produce handshake packets
    static boolean produceHandshakePackets(SSLEngine engine, SocketAddress socketAddr,
                                    String side, List<DatagramPacket> packets) throws Exception {

        boolean endLoops = false;
        int loops = MAX_HANDSHAKE_LOOPS / 2;
        while (!endLoops &&
                (serverException == null) && (clientException == null)) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            ByteBuffer oNet = ByteBuffer.allocate(32768);
            ByteBuffer oApp = ByteBuffer.allocate(0);
            SSLEngineResult r = engine.wrap(oApp, oNet);
            oNet.flip();

            SSLEngineResult.Status rs = r.getStatus();
            SSLEngineResult.HandshakeStatus hs = r.getHandshakeStatus();
            log(side, "----produce handshake packet(" +
                    loops + ", " + rs + ", " + hs + ")----");
            if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                // the client maximum fragment size config does not work?
                throw new Exception("Buffer overflow: " +
                        "incorrect server maximum fragment size");
            } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                log(side,
                        "Produce handshake packets: BUFFER_UNDERFLOW occured");
                log(side,
                        "Produce handshake packets: Handshake status: " + hs);
                // bad packet, or the client maximum fragment size
                // config does not work?
                if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    throw new Exception("Buffer underflow: " +
                            "incorrect server maximum fragment size");
                } // otherwise, ignore this packet
            } else if (rs == SSLEngineResult.Status.CLOSED) {
                throw new Exception("SSLEngine has closed");
            } else if (rs == SSLEngineResult.Status.OK) {
                // OK
            } else {
                throw new Exception("Can't reach here, result is " + rs);
            }

            // SSLEngineResult.Status.OK:
            if (oNet.hasRemaining()) {
                byte[] ba = new byte[oNet.remaining()];
                oNet.get(ba);
                DatagramPacket packet = createHandshakePacket(ba, socketAddr);
                packets.add(packet);
            }

            if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                log(side, "Produce handshake packets: "
                        + "Handshake status is FINISHED, finish the loop");
                return true;
            }

            boolean endInnerLoop = false;
            SSLEngineResult.HandshakeStatus nhs = hs;
            while (!endInnerLoop) {
                if (nhs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    runDelegatedTasks(engine);
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                        nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN ||
                        nhs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                    endInnerLoop = true;
                    endLoops = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    endInnerLoop = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    throw new Exception(
                            "Unexpected status, SSLEngine.getHandshakeStatus() "
                                    + "shouldn't return FINISHED");
                } else {
                    throw new Exception("Can't reach here, handshake status is "
                            + nhs);
                }
                nhs = engine.getHandshakeStatus();
            }
        }

        return false;
    }

    static DatagramPacket createHandshakePacket(byte[] ba, SocketAddress socketAddr) {
        return new DatagramPacket(ba, ba.length, socketAddr);
    }

    public static void deliverAppData(SslnfoObj sslnfoObj, ByteBuffer appData) throws Exception {
        deliverAppData(sslnfoObj.getSslEngine(), sslnfoObj.getDatagramSocket(), appData, sslnfoObj.getServerSocketAddr(), "Server");
    }

      // deliver application data
      public static void deliverAppData(SSLEngine engine, DatagramSocket socket,
                                        ByteBuffer appData, SocketAddress peerAddr, String side) throws Exception {

        // Note: have not consider the packet loses
        List<DatagramPacket> packets =
                produceApplicationPackets(engine, appData, peerAddr);
        appData.flip();
        for (DatagramPacket p : packets) {
            log(side, "Sending to "+ p.getAddress().getHostAddress() +":"+p.getPort() +" and the length is " + p.getLength());
            socket.send(p);
        }
    }

    public static ByteBuffer receiveAppData(SslnfoObj sslnfoObj) throws Exception {
        return receiveAppData(sslnfoObj.getSslEngine(), sslnfoObj.getDatagramSocket(), sslnfoObj.is_isClient()?"Client":"Server");
    }

    // receive application data
//    public static byte[] receiveAppData(SSLEngine engine,
//                        DatagramSocket socket, String side) throws Exception {
//
//        int loops = MAX_APP_READ_LOOPS;
//        ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
//        while ((serverException == null) && (clientException == null)) {
//            if (--loops < 0) {
//                throw new RuntimeException(
//                        "Too much loops to receive application data");
//            }
//
//            byte[] buf = new byte[BUFFER_SIZE];
//            DatagramPacket packet = new DatagramPacket(buf, buf.length);
//            socket.receive(packet);
//            log(side, "Received packet  length is "+ packet.getLength());
//            ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());
//
//            SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);
//            recBuffer.flip();
//            if (recBuffer.remaining() != 0) {
//                log(side, "Received application data");
//                byte[] bytes = new byte[recBuffer.remaining()];
//                recBuffer.duplicate().get(bytes);
//                log(side, "Data size is" + bytes.length);
//                return bytes;
//               // break;
//            }
//        }
//        return null;
//    }

    public static ByteBuffer receiveAppData(SSLEngine engine,
                                        DatagramSocket socket, String side) throws Exception {

        int loops = MAX_APP_READ_LOOPS;
        ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        while ((serverException == null) && (clientException == null)) {
            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to receive application data");
            }

            byte[] buf = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            log(side, "Received packet  length is "+ packet.getLength());
            ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());

            SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);
            if (recBuffer.position() != 0) {
                recBuffer.flip();
//                log(side, "Received application data");
//                byte[] bytes = new byte[recBuffer.remaining()];
//                recBuffer.duplicate().get(bytes);
//                log(side, "Data size is" + bytes.length);
//                return bytes;
                 return recBuffer;
//                 break;
            }
        }
        return null;
    }

    // produce application packets
    public static List<DatagramPacket> produceApplicationPackets(
            SSLEngine engine, ByteBuffer source,
            SocketAddress socketAddr) throws Exception {

        List<DatagramPacket> packets = new ArrayList<>();
        ByteBuffer appNet = ByteBuffer.allocate(32768);
        SSLEngineResult r = engine.wrap(source, appNet);
        appNet.flip();

        SSLEngineResult.Status rs = r.getStatus();
        if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            // the client maximum fragment size config does not work?
            throw new Exception("Buffer overflow: " +
                    "incorrect server maximum fragment size");
        } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            // unlikely
            throw new Exception("Buffer underflow during wraping");
        } else if (rs == SSLEngineResult.Status.CLOSED) {
            throw new Exception("SSLEngine has closed");
        } else if (rs == SSLEngineResult.Status.OK) {
            // OK
        } else {
            throw new Exception("Can't reach here, result is " + rs);
        }

        // SSLEngineResult.Status.OK:
        if (appNet.hasRemaining()) {
            log("","sending data size is "+ appNet.remaining());
            byte[] ba = new byte[appNet.remaining()];
            appNet.get(ba);
            DatagramPacket packet =
                    new DatagramPacket(ba, ba.length, socketAddr);
            packets.add(packet);
        }

        return packets;
    }

}
