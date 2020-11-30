package com.env.sctp4j.test.sctp.dtls;

import com.env.java11.dtls.SslEngineUtils;
import com.env.java11.dtls.SslnfoObj;
import com.phono.srtplight.Log;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.test.MockDTLSClient;
import pe.pi.sctp4j.sctp.SCTPByteStreamListener;
import pe.pi.sctp4j.sctp.SCTPStream;
import pe.pi.sctp4j.sctp.behave.OrderedStreamBehaviour;
import pe.pi.sctp4j.sctp.behave.UnorderedStreamBehaviour;
import pe.pi.sctp4j.sctp.small.BlockingSCTPStream;
import pe.pi.sctp4j.sctp.small.MockAssociationListener;
import pe.pi.sctp4j.sctp.small.ThreadedAssociation;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertTrue;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS server.
 * </p>
 */
public class StartDltsClient {
    private static  String mediumSizeMsg = "***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END";


    private static int SOCKET_TIMEOUT = 10 * 1000; // in millis

    private static  byte[] fileBytes;
    private static ThreadedAssociation clientAssoc;

    public static void main(String[] args)
            throws Exception {

        Log.setLevel(Log.VERB);

        try (FileInputStream fis = new FileInputStream("src/test/resources/1mb.pdf")) {
            fileBytes = fis.readAllBytes();
        }

        AtomicInteger counte1r = new AtomicInteger();
        final SCTPByteStreamListener rsl = new SCTPByteStreamListener() {
            @Override
            public void onMessage(SCTPStream s, String message) {
                Log.info("String onmessage : " + message);
            }

            @Override
            public void onMessage(SCTPStream s, byte[] message) {
                Log.info("Counter --"+ counte1r.getAndIncrement() + "Rcvd Byte on message: " + (message).length);
                //try sending back on the same stream

                try {
                    //String addTail = new StringBuilder(("START-")).append(new String(message)).toString();
                    makeNewStreamAndSend();
                   // s.send(message);
                } catch (Exception e) {
                    Log.error("Exception while sending msg back to server");
                }
            }

            @Override
            public void close(SCTPStream aThis) {
                Log.debug("closed");
            }
        };

        MockAssociationListener clientListener = new MockAssociationListener() {
            @Override
            public void onRawStream(SCTPStream s) {
                super.onRawStream(s);
                s.setBehave(new OrderedStreamBehaviour());
                s.setSCTPStreamListener(rsl);
            }
        };

        //create SCTP instance
        MockAssociationListener associationListener = new MockAssociationListener();
        // create SSLEngine
        SSLEngine engine = SslEngineUtils.createSSLEngine(true);
        DatagramSocket clientSocket = new DatagramSocket();
        clientSocket.setSoTimeout(SOCKET_TIMEOUT);
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;
        InetSocketAddress serverSocketAddr = new InetSocketAddress(address, port);
        // handshaking
        SslEngineUtils.handshake(engine, clientSocket, serverSocketAddr, "Client");
        SSLSession session = engine.getSession();
        int packetBufferSize = session.getPacketBufferSize();
        int applicationBufferSize = session.getApplicationBufferSize();
        SslnfoObj sslnfoObj = new SslnfoObj(engine, clientSocket, packetBufferSize, applicationBufferSize, true, serverSocketAddr);
        clientAssoc = new ThreadedAssociation(sslnfoObj, clientListener);
        clientAssoc.associate();
        synchronized (clientListener) {
            clientListener.wait(5000);
            assertTrue(clientListener.associated);
        }
        clientAssoc.sendHeartBeat();
        SCTPStream sctpStream = clientAssoc.mkStream(999);
     //   scheduleMultipleMsgsAtFixedRate(clientAssoc, sctpStream);

    }

   // scheduleMultipleMsgsAtFixedRate(clientAssoc, result);
    /**
     * basically if we send two requests in parallel, this is also NOT WORKING.
     *
     */
    // scheduleMultipleMsgsConcurrently(clientAssoc, result);

    private static void scheduleMultipleMsgsConcurrently(ThreadedAssociation clientAssoc, SCTPStream result) {
        ExecutorService _ex_service = Executors.newFixedThreadPool(5);
        AtomicInteger counter = new AtomicInteger();
        for(int j=0;j<2;j++) {
            _ex_service.submit(() -> sendMsg(clientAssoc, result, counter));
        }
    }

    /**
     * this method will send 5 concurrent msgs of size 8k.
     */
    private static void scheduleMultipleMsgsAtFixedRate(ThreadedAssociation clientAssoc, SCTPStream result) {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(10);//Executors.newSingleThreadScheduledExecutor();
        AtomicInteger counter = new AtomicInteger();
       // for(int i=0;i<5;i++) {
            scheduledExecutorService.scheduleAtFixedRate(
                    () -> {
                        sendMsg(clientAssoc, result, counter);
                    }, 5, 1, TimeUnit.SECONDS
            );
      //  }
    }

    /**
     *  this method will send single msg of 8k size with fixed delay
     */
    private static void scheduleMsgs(ThreadedAssociation clientAssoc, SCTPStream result) {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(5);//Executors.newSingleThreadScheduledExecutor();
        AtomicInteger counter = new AtomicInteger();
        scheduledExecutorService.scheduleWithFixedDelay(
                ()-> {
                    sendMsg(clientAssoc, result, counter);
                }, 5, 1, TimeUnit.SECONDS
        );
    }

    private static void sendMsg(ThreadedAssociation clientAssoc, SCTPStream result, AtomicInteger counter) {
        try {
            byte[] msgBytes = (mediumSizeMsg + counter.getAndIncrement()).getBytes();
            Log.info("$$$$$$$$$$$$$$$$$$$$$$$$$$  start "+ msgBytes.length);
            //SCTPStream result1 = clientAssoc.mkStream(SecureRandom.getInstanceStrong().nextInt());
            //SCTPMessage sctpMsg1 = new SCTPMessage(msgBytes, result1);
            //clientAssoc.sendAndBlock(sctpMsg1);
            result.send(msgBytes);
            Log.info("Counter " + counter.intValue()+"  ####################  END  Client sent file content to Server");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void makeNewStreamAndSend() throws Exception {
        SCTPStream newStream = clientAssoc.mkStream(new Random().nextInt());
        sendMsg(newStream);
    }

    private static void sendMsg(SCTPStream sctpStream) throws Exception {
        Log.info("Sending bytes of length"+ fileBytes.length);
        sctpStream.send(fileBytes);
        Log.info("Sent bytes of length"+ fileBytes.length);
    }

    private static void sendDtlsMsg(DTLSTransport dtls) throws IOException {
        byte[] request = "Hello World!\n".getBytes("UTF-8");
        dtls.send(request, 0, request.length);

        byte[] response = new byte[dtls.getReceiveLimit()];
        int received = dtls.receive(response, 0, response.length, 30000);
        if (received >= 0) {
            System.out.println("########## RCVD"+new String(response, 0, received, "UTF-8"));
        }
    }

    private static TlsSession createSession(InetAddress address, int port)
            throws IOException {
        MockDTLSClient client = new MockDTLSClient(null);
        DTLSTransport dtls = openDTLSConnection(address, port, client);
        TlsSession session = client.getSessionToResume();
        dtls.close();
        return session;
    }

    private static DTLSTransport openDTLSConnection(InetAddress address, int port, TlsClient client)
            throws IOException {
        DatagramSocket socket = new DatagramSocket();
        socket.connect(address, port);

        int mtu = 1500;
        DatagramTransport transport = new UDPTransport(socket, mtu);
     //   transport = new UnreliableDatagramTransport(transport, secureRandom, 0, 0);
      //  transport = new LoggingDatagramTransport(transport, System.out);

        DTLSClientProtocol protocol = new DTLSClientProtocol();

        return protocol.connect(client, transport);
    }
}
