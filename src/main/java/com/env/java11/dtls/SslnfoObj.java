package com.env.java11.dtls;

import javax.net.ssl.SSLEngine;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public class SslnfoObj {

    private final SSLEngine sslEngine;
    private final DatagramSocket datagramSocket;
    private boolean _isClient;
    private final int packetBufferSize;
    private final int applicationBufferSize;
    private SocketAddress serverSocketAddr;

    public SslnfoObj(SSLEngine engine, DatagramSocket socket, int packetBufferSize, int applicationBufferSize, boolean isClient){
        sslEngine = engine;
        datagramSocket = socket;
        this.packetBufferSize = packetBufferSize;
        this.applicationBufferSize = applicationBufferSize;
        _isClient = isClient;
    }

    public SslnfoObj(SSLEngine engine, DatagramSocket socket, int packetBufferSize, int applicationBufferSize, boolean isClient, SocketAddress serverSocketAddr){
        this(engine,socket,packetBufferSize, applicationBufferSize, isClient);
        this.serverSocketAddr = serverSocketAddr;
    }

    public SocketAddress getServerSocketAddr() {
        return serverSocketAddr;
    }

    public DatagramSocket getDatagramSocket() {
        return datagramSocket;
    }

    public SSLEngine getSslEngine(){
        return sslEngine;
    }

    public boolean is_isClient() {
        return _isClient;
    }

    public int getPacketBufferSize() {
        return packetBufferSize;
    }

    public int getApplicationBufferSize() {
        return applicationBufferSize;
    }
}
