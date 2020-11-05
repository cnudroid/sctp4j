package com.env.sctp4j.test.sctp.dtls;

import com.phono.srtplight.Log;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.test.MockDTLSClient;
import pe.pi.sctp4j.sctp.SCTPByteStreamListener;
import pe.pi.sctp4j.sctp.SCTPMessage;
import pe.pi.sctp4j.sctp.SCTPStream;
import pe.pi.sctp4j.sctp.behave.OrderedStreamBehaviour;
import pe.pi.sctp4j.sctp.small.BlockingSCTPStream;
import pe.pi.sctp4j.sctp.small.MockAssociationListener;
import pe.pi.sctp4j.sctp.small.ThreadedAssociation;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS server.
 * </p>
 */
public class StartDltsClient {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String mediumSizeMsg = "***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END";

    public static void main(String[] args)
            throws Exception {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;
        Log.setLevel(Log.INFO);

//        File file = new File(StartDltsClient.class.getResource("proxy-test.log").toURI());
//        byte[] fileContent = Files.readAllBytes(file.toPath());

        byte[] mediumMsgBytes = mediumSizeMsg.getBytes();

        MockDTLSClient client = new MockDTLSClient(null);

        DTLSTransport dtls = openDTLSConnection(address, port, client);
        AtomicInteger counte1r = new AtomicInteger();
        final SCTPByteStreamListener rsl = new SCTPByteStreamListener() {
            @Override
            public void onMessage(SCTPStream s, String message) {
                Log.info("String onmessage : " + message);
            }

            @Override
            public void onMessage(SCTPStream s, byte[] message) {
                Log.info("Counter --"+ counte1r.getAndIncrement() + "Rcvd Byte on message length: " + message.length);
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
        ThreadedAssociation clientAssoc = new ThreadedAssociation(dtls, clientListener);
        clientAssoc.associate();
        synchronized (clientListener) {
            clientListener.wait(1000);
            //assertTrue(clientListener.associated);
        }

        System.out.println("Receive limit: " + dtls.getReceiveLimit());
        System.out.println("Send limit: " + dtls.getSendLimit());

       // Thread.sleep(1000);
        // Send and hopefully receive a packet back

        int id = 10;
        SCTPStream result = clientAssoc.mkStream(id);
        assert (result instanceof BlockingSCTPStream);
        clientAssoc.sendHeartBeat();
        //Thread.sleep(3000);
        Log.info("%%%%%%%%%%%%%%%%% let's start client sending msgs %%%%%%%%%%%%%%%%%%%%%");
        /**
         * uncommented this method will send single msg of 8k size with fixed delay
         * this is WORKING
         */
        //scheduleMsgs(clientAssoc);
        /**
         * this method will send 5 concurrent msgs of size 8k.
         * this is NOT WORKING
         */
        scheduleMultipleMsgsAtFixedRate(clientAssoc);
        /**
         * basically if we send two requests in parallel, this is also NOT WORKING.
         *
         */
        scheduleMultipleMsgsConcurrently(clientAssoc);
    }

    private static void scheduleMultipleMsgsConcurrently(ThreadedAssociation clientAssoc) {
        ExecutorService _ex_service = Executors.newFixedThreadPool(5);
        AtomicInteger counter = new AtomicInteger();
        for(int j=0;j<2;j++) {
            _ex_service.submit(() -> sendMsg(clientAssoc, counter));
        }
    }

    /**
     * this method will send 5 concurrent msgs of size 8k.
     */
    private static void scheduleMultipleMsgsAtFixedRate(ThreadedAssociation clientAssoc) {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(10);//Executors.newSingleThreadScheduledExecutor();
        AtomicInteger counter = new AtomicInteger();
        for(int i=0;i<5;i++) {
            scheduledExecutorService.scheduleAtFixedRate(
                    () -> {
                        sendMsg(clientAssoc, counter);
                    }, 5, 1, TimeUnit.SECONDS
            );
        }
    }

    /**
     *  this method will send single msg of 8k size with fixed delay
     */
    private static void scheduleMsgs(ThreadedAssociation clientAssoc) {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(5);//Executors.newSingleThreadScheduledExecutor();
        AtomicInteger counter = new AtomicInteger();
        scheduledExecutorService.scheduleWithFixedDelay(
                ()-> {
                    sendMsg(clientAssoc, counter);
                }, 5, 1, TimeUnit.SECONDS
        );
    }

    private static void sendMsg(ThreadedAssociation clientAssoc, AtomicInteger counter) {
        try {
            byte[] msgBytes = (mediumSizeMsg + counter.getAndIncrement()).getBytes();
            Log.info("$$$$$$$$$$$$$$$$$$$$$$$$$$  start "+ msgBytes.length);
            SCTPStream result1 = clientAssoc.mkStream(SecureRandom.getInstanceStrong().nextInt());
            SCTPMessage sctpMsg1 = new SCTPMessage(msgBytes, result1);
            clientAssoc.sendAndBlock(sctpMsg1);
            Log.info("Counter " + counter.intValue()+"  ####################  END  Client sent file content to Server");
        } catch (Exception e) {
            e.printStackTrace();
        }
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
