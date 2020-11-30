/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

// SunJSSE does not support dynamic system properties, no way to re-use
// system properties in samevm/agentvm mode.

/*
 * @test
 * @bug 8043758
 * @summary Datagram Transport Layer Security (DTLS)
 * @modules java.base/sun.security.util
 * @run main/othervm DTLSOverDatagram
 */

package com.env.java11.dtls;

import javax.net.ssl.*;
import java.io.InputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * An example to show the way to use SSLEngine in datagram connections.
 */
public class DTLSOverDatagram {

    private static int MAX_HANDSHAKE_LOOPS = 200;
    private static int MAX_APP_READ_LOOPS = 60;
    private static int SOCKET_TIMEOUT = 10 * 1000; // in millis
    private static int BUFFER_SIZE = 1024;


    /*
     * The following is to set up the keystores.
     */
    private static String pathToStores = "../etc";
    private static String keyStoreFile = "keystore";
    private static String trustStoreFile = "truststore";
    private static String passwd = "passphrase";

    private static String keyFilename =
            System.getProperty("test.src", ".") + "/" + pathToStores +
                    "/" + keyStoreFile;
    private static String trustFilename =
            System.getProperty("test.src", ".") + "/" + pathToStores +
                    "/" + trustStoreFile;
    private static Exception clientException = null;
    private static Exception serverException = null;

    private static ByteBuffer serverApp =
            ByteBuffer.wrap("Hi Client, I'm Server".getBytes());
    private static ByteBuffer clientApp =
            ByteBuffer.wrap("Hi Server, I'm Client".getBytes());

    static ByteBuffer sampleData ;

    /*
     * =============================================================
     * The test case
     */
    public static void main(String[] args) throws Exception {

        addSampleData("httpreq.txt");
        DTLSOverDatagram testCase = new DTLSOverDatagram();
        testCase.runTest(testCase);
    }

    private static void addSampleData(String fileName) {
        final InputStream input;
        try {
//            input = new FileInputStream("src/main/resources/"+fileName);
//            byte[] bytes = IOUtils.toByteArray(input);
            sampleData =  ByteBuffer.wrap("this is sample msg".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /*
     * Define the server side of the test.
     */
    void doServerSide(DatagramSocket socket, InetSocketAddress clientSocketAddr)
            throws Exception {

        // create SSLEngine
        SSLEngine engine = SslEngineUtils.createSSLEngine(false);

        // handshaking
        SocketAddress clientAddr = SslEngineUtils.handshake(engine, socket, null, "Server");

        // read client application data
        receiveAppData(engine, socket, "Server");

        // write server application data
        deliverAppData(engine, socket,  ByteBuffer.wrap("Hi Client,This is Server".getBytes()), clientAddr, "Server");
    }

    /*
     * Define the client side of the test.
     */
    void doClientSide(DatagramSocket socket, InetSocketAddress serverSocketAddr)
            throws Exception {

        // create SSLEngine
        SSLEngine engine = SslEngineUtils.createSSLEngine(true);

        // handshaking
        SslEngineUtils.handshake(engine, socket, serverSocketAddr, "Client");

        // write client application data
        SslEngineUtils.deliverAppData(engine, socket, ByteBuffer.wrap("Hi Server,This is Client".getBytes()), serverSocketAddr, "Client");

        // read server application data
        receiveAppData(engine, socket, "Client");
    }


    /*
     * =============================================================
     * The remainder is support stuff to kickstart the testing.
     */

    // Will the handshaking and application data exchange succeed?
    public boolean isGoodJob() {
        return true;
    }

    public final void runTest(DTLSOverDatagram testCase) throws Exception {
        try (DatagramSocket serverSocket = new DatagramSocket(5556);
             DatagramSocket clientSocket = new DatagramSocket(8887)) {

            serverSocket.setSoTimeout(SOCKET_TIMEOUT);
            clientSocket.setSoTimeout(SOCKET_TIMEOUT);

            InetSocketAddress serverSocketAddr = new InetSocketAddress(
                    InetAddress.getLocalHost(), serverSocket.getLocalPort());

            InetSocketAddress clientSocketAddr = new InetSocketAddress(
                    InetAddress.getLocalHost(), clientSocket.getLocalPort());

            ExecutorService pool = Executors.newFixedThreadPool(2);
            Future<String> server, client;
            SslEngineUtils.log("*******","Starting the test");
            try {
                server = pool.submit(new ServerCallable(
                        testCase, serverSocket, clientSocketAddr));
                client = pool.submit(new ClientCallable(
                        testCase, clientSocket, serverSocketAddr));
            } finally {
                pool.shutdown();
            }

            boolean failed = false;

            // wait for client to finish
            try {
                System.out.println("Client finished: " + client.get());
            } catch (CancellationException | InterruptedException
                    | ExecutionException e) {
                System.out.println("Exception on client side: ");
                e.printStackTrace(System.out);
                failed = true;
            }

            // wait for server to finish
            try {
                System.out.println("Client finished: " + server.get());
            } catch (CancellationException | InterruptedException
                    | ExecutionException e) {
                System.out.println("Exception on server side: ");
                e.printStackTrace(System.out);
                failed = true;
            }

            if (failed) {
                throw new RuntimeException("Test failed");
            }
        }
    }


    ByteBuffer receiveAppData(SSLEngine engine,
                        DatagramSocket socket, String side) throws Exception {

        int loops = MAX_APP_READ_LOOPS;
        ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
        while ((serverException == null) && (clientException == null)) {
            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to receive application data");
            }
            SslEngineUtils.log(side, "loop "+ loops);
            byte[] buf = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            SslEngineUtils.log(side, "packet length "+ packet.getLength());
            ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());

            SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);

            if (recBuffer.position() != 0) {
                recBuffer.flip();
                SslEngineUtils.log(side, "Received application data");
//                if (!recBuffer.equals(expectedApp)) {
//                    System.out.println("Engine status is " + rs);
//                    throw new Exception("Not the right application data");
//                }
                return recBuffer;
               // break;
            }
        }
        return null;
    }

    // deliver application data
    void deliverAppData(SSLEngine engine, DatagramSocket socket,
                        ByteBuffer appData, SocketAddress peerAddr, String side) throws Exception {

        // Note: have not consider the packet loses
        List<DatagramPacket> packets =
                produceApplicationPackets(engine, appData, peerAddr);
        appData.flip();
        SslEngineUtils.log(side, "sendign data");
        for (DatagramPacket p : packets) {
            socket.send(p);
        }
    }

    // produce application packets
    List<DatagramPacket> produceApplicationPackets(
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
            byte[] ba = new byte[appNet.remaining()];
            appNet.get(ba);
            DatagramPacket packet =
                    new DatagramPacket(ba, ba.length, socketAddr);
            packets.add(packet);
        }

        return packets;
    }


    final static class ServerCallable implements Callable<String> {

        private final DTLSOverDatagram testCase;
        private final DatagramSocket socket;
        private final InetSocketAddress clientSocketAddr;

        ServerCallable(DTLSOverDatagram testCase, DatagramSocket socket,
                       InetSocketAddress clientSocketAddr) {

            this.testCase = testCase;
            this.socket = socket;
            this.clientSocketAddr = clientSocketAddr;
        }

        @Override
        public String call() throws Exception {
            try {
                testCase.doServerSide(socket, clientSocketAddr);
            } catch (Exception e) {
                System.out.println("Exception in  ServerCallable.call():");
                e.printStackTrace(System.out);
                serverException = e;

                if (testCase.isGoodJob()) {
                    throw e;
                } else {
                    return "Well done, server!";
                }
            }

            if (testCase.isGoodJob()) {
                return "Well done, server!";
            } else {
                throw new Exception("No expected exception");
            }
        }
    }

    final static class ClientCallable implements Callable<String> {

        private final DTLSOverDatagram testCase;
        private final DatagramSocket socket;
        private final InetSocketAddress serverSocketAddr;

        ClientCallable(DTLSOverDatagram testCase, DatagramSocket socket,
                       InetSocketAddress serverSocketAddr) {

            this.testCase = testCase;
            this.socket = socket;
            this.serverSocketAddr = serverSocketAddr;
        }

        @Override
        public String call() throws Exception {
            try {
                testCase.doClientSide(socket, serverSocketAddr);
            } catch (Exception e) {
                System.out.println("Exception in ClientCallable.call():");
                e.printStackTrace(System.out);
                clientException = e;

                if (testCase.isGoodJob()) {
                    throw e;
                } else {
                    return "Well done, client!";
                }
            }

            if (testCase.isGoodJob()) {
                return "Well done, client!";
            } else {
                throw new Exception("No expected exception");
            }
        }
    }
}
