package com.env.sctp4j.test.sctp.dtls;

import com.env.java11.dtls.SslEngineUtils;
import com.env.java11.dtls.SslnfoObj;
import com.phono.srtplight.Log;
import org.bouncycastle.tls.DTLSTransport;
import pe.pi.sctp4j.sctp.SCTPByteStreamListener;
import pe.pi.sctp4j.sctp.SCTPStream;
import pe.pi.sctp4j.sctp.behave.OrderedStreamBehaviour;
import pe.pi.sctp4j.sctp.behave.UnorderedStreamBehaviour;
import pe.pi.sctp4j.sctp.small.MockAssociationListener;
import pe.pi.sctp4j.sctp.small.ThreadedAssociation;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS client.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS client.
 * </p>
 */
public class DTLSServer11Test
{
    private static  String mediumSizeMsg = "***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***this is really asomrhings fsdpfsdf sdfsdfsd ***------------------------------------------------------END";

    private static SCTPStream sctpStream = null;
    private static  byte[] fileBytes;
    private static ThreadedAssociation instanceRight;

    public static void main(String[] args)
            throws Exception
    {
        int port = 5556;

        int mtu = 1500;
       // byte[] fileBytes;
      //  FileUtils.readFileToByteArray(File input).
        try (FileInputStream fis = new FileInputStream("src/test/resources/1mb.pdf")) {
           fileBytes = fis.readAllBytes();
        }

        Log.setLevel(Log.VERB);
        DatagramSocket socket = new DatagramSocket(port);
        // create SSLEngine
        SSLEngine engine = SslEngineUtils.createSSLEngine(false);
        // handshaking
        SocketAddress clientAddr = SslEngineUtils.handshake(engine, socket, null,"Server");
        SSLSession session = engine.getSession();
        int packetBufferSize = session.getPacketBufferSize();
        int applicationBufferSize = session.getApplicationBufferSize();
        SslnfoObj serverSslInfo = new SslnfoObj(engine, socket, packetBufferSize, applicationBufferSize, false, clientAddr);
        final ByteBuffer srvRcvdBuf = ByteBuffer.allocate(10000);
        final StringBuffer empty = new StringBuffer();
        final StringBuffer serverRcvdData = new StringBuffer();
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
                Log.info("Counter --"+ counter.getAndIncrement() + " Byte RCVD and message is  : " +  (message).length);
                try {
                 //   String addTail = new StringBuilder(new String(message)).append("TAIL-").toString();
                    makeNewStreamAndSend();
                    s.send(message);
                } catch (Exception e) {
                    Log.error("Exception while sending msg back to server");
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
                s.setBehave(new OrderedStreamBehaviour());
                s.setSCTPStreamListener(rsl);
            }
        };
        System.out.println("Accepted -------------------------------");
        instanceRight = new ThreadedAssociation(serverSslInfo, serverAssListener);
        synchronized (serverAssListener) {
            serverAssListener.wait(2000);
        }
        System.out.println("Associated -------------------------------"+ serverAssListener.associated);
        instanceRight.sendHeartBeat();
        Thread.sleep(3000);
        int id = 10;
        sctpStream = instanceRight.mkStream(id);
        sendMsg(sctpStream);
        System.out.println("Let's check RCVD data --  *********************   --");
    }

    private static void makeNewStreamAndSend() throws Exception {
        SCTPStream newStream = instanceRight.mkStream(new Random().nextInt());
        sendMsg(newStream);
    }

    private static void sendMsg(SCTPStream sctpStream) throws Exception {
        Log.info("Sending bytes of length"+ fileBytes.length);
        sctpStream.send(fileBytes);
        Log.info("Sent bytes of length"+ fileBytes.length);
    }
}