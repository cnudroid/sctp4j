package com.env.sctp4j.test.sctp.dtls;

import com.phono.srtplight.Log;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.UDPTransport;
import org.bouncycastle.tls.test.MockDTLSServer;
import pe.pi.sctp4j.sctp.SCTPByteStreamListener;
import pe.pi.sctp4j.sctp.SCTPStream;
import pe.pi.sctp4j.sctp.behave.OrderedStreamBehaviour;
import pe.pi.sctp4j.sctp.behave.UnorderedStreamBehaviour;
import pe.pi.sctp4j.sctp.small.MockAssociationListener;
import pe.pi.sctp4j.sctp.small.ThreadedAssociation;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertTrue;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS client.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS client.
 * </p>
 */
public class DTLSServerTest
{
    private static  byte[] fileBytes;
    private static ThreadedAssociation instanceRight;
    private static SCTPStream newStream;

    public static void main(String[] args)
            throws Exception
    {
        int port = 5556;

        int mtu = 1500;

        Log.setLevel(Log.INFO);

        try (FileInputStream fis = new FileInputStream("src/test/resources/1mb.txt")) {
            fileBytes = fis.readAllBytes();
        }

        SecureRandom secureRandom = new SecureRandom();

        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();


        byte[] data = new byte[mtu];
        DatagramPacket packet = new DatagramPacket(data, mtu);

        DatagramSocket socket = new DatagramSocket(port);
        socket.receive(packet);

        System.out.println("Accepting connection from " + packet.getAddress().getHostAddress() + ":" + port);
        socket.connect(packet.getAddress(), packet.getPort());

        /*
         * NOTE: For simplicity, and since we don't yet have HelloVerifyRequest support, we just
         * discard the initial packet, which the client should re-send anyway.
         */

        DatagramTransport transport = new UDPTransport(socket, mtu);

        // Uncomment to see packets
//        transport = new LoggingDatagramTransport(transport, System.out);

        MockDTLSServer server = new MockDTLSServer();
        DTLSTransport dtlsServer = serverProtocol.accept(server, transport);

        final ByteBuffer srvRcvdBuf = ByteBuffer.allocate(10000);
        final StringBuffer empty = new StringBuffer();
        final StringBuffer serverRcvdData = new StringBuffer();
//        final SCTPStreamListener rsl = new SCTPStreamListener() {
//            @Override
//            synchronized public void onMessage(SCTPStream s, String message) {
//                System.out.println("onmessage : " + message);
//                serverRcvdData.append(message);
//                this.notify();
//            }
//
//            @Override
//            public void close(SCTPStream aThis) {
//
//               System.out.println("closed");
//            }
//        };
        final SCTPByteStreamListener rsl = new SCTPByteStreamListener() {
            AtomicInteger counter = new AtomicInteger();

            @Override
            public void onMessage(SCTPStream s, String message) {
                empty.append(message);
                Log.info("String onmessage : " + message);
                synchronized (srvRcvdBuf) {
                    srvRcvdBuf.notify();
                }
            }

            @Override
            public void onMessage(SCTPStream s, byte[] message) {

                //srvRcvdBuf.put(message);
                Log.info("Counter --"+ counter.getAndIncrement() + " Byte RCVD and message is  : " + (message).length);
                try {
                    makeNewStreamAndSend(fileBytes);
                } catch (Exception e) {
                    e.printStackTrace();
                }


//                Path path = Paths.get("logs/content-server.log"+ counter.getAndIncrement());
//                try {
//                    Files.write(path, message);
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }

                synchronized (srvRcvdBuf) {
                    srvRcvdBuf.notify();
                }
            }

            @Override
            public void close(SCTPStream aThis) {
                Log.debug("closed");
            }
        };

        MockAssociationListener serverAssListener = new MockAssociationListener() {
            @Override
            public void onRawStream(SCTPStream s) {
                super.onRawStream(s);
                s.setBehave(new UnorderedStreamBehaviour());
                s.setSCTPStreamListener(rsl);
            }
        };
        System.out.println("Accepted -------------------------------");
        instanceRight = new ThreadedAssociation(dtlsServer, serverAssListener);
        synchronized (serverAssListener) {
            serverAssListener.wait(2000);
            assertTrue(serverAssListener.associated);
        }
        System.out.println("Associated -------------------------------");
        newStream = instanceRight.mkStream(new Random().nextInt());
        // instanceRight.sendHeartBeat();
        // sleep for sometime
       // Thread.sleep(2000);
        System.out.println("Let's check RCVD data --  *********************   --");
//        synchronized (srvRcvdBuf) {
//            srvRcvdBuf.wait(1000);
//            int l = srvRcvdBuf.position();
//            String res = new String(srvRcvdBuf.array(), 0, l);
//            Log.info("RCVD data ------> " +res);
//        }

//        ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
//        AtomicInteger counter = new AtomicInteger();
//
//        scheduledExecutorService.scheduleWithFixedDelay(
//                ()-> {
//                    try {
////                        SCTPStream result = instanceRight.mkStream(SecureRandom.getInstanceStrong().nextInt());
////                        String msg2 = "RES from Server msg " + counter.getAndIncrement();
////                        SCTPMessage sctpMsg = new SCTPMessage(msg2.getBytes(), result);
////                        instanceRight.sendAndBlock(sctpMsg);
//                        instanceRight.sendHeartBeat();
//                    } catch (Exception e) {
//                        e.printStackTrace();
//                    }
//                }, 10, 1, TimeUnit.SECONDS
//        );
        makeNewStreamAndSend(fileBytes);
       // rcvAndSend(socket, dtlsServer);
       // Thread.sleep(3000);
        System.out.println("Closing  -------------------------------");
       // dtlsServer.close();
    }

    private static void makeNewStreamAndSend(byte[] fileBytes) throws Exception {
//        SCTPStream newStream = instanceRight.mkStream(new Random().nextInt());
        sendMsg(newStream, fileBytes);
    }

    private static void sendMsg(SCTPStream sctpStream, byte[] fileBytes) throws Exception {
        Log.info("Sending bytes of length"+ fileBytes.length);
        sctpStream.send(fileBytes);
        Log.info("Sent bytes of length"+ fileBytes.length);
    }

    private static void rcvAndSend(DatagramSocket socket, DTLSTransport dtlsServer) throws IOException {
        byte[] buf = new byte[dtlsServer.getReceiveLimit()];
        while (!socket.isClosed())
        {
            try
            {
                int length = dtlsServer.receive(buf, 0, buf.length, 60000);
                System.out.println("Rcvd  -------------------------------");
                if (length >= 0)
                {
                    System.out.write(buf, 0, length);
                    System.out.println("Sending  -------------------------------");
                    dtlsServer.send(buf, 0, length);
                }
            }
            catch (SocketTimeoutException ste)
            {
                System.out.println("Exception  -------------------------------"+ ste);
            }
        }
    }
}