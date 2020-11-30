/*
 * Copyright 2017 pi.pe gmbh .
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package pe.pi.sctp4j.sctp.small;

import pe.pi.sctp4j.sctp.SCTPMessage;
import pe.pi.sctp4j.sctp.Association;
import pe.pi.sctp4j.sctp.SCTPStream;
import pe.pi.sctp4j.sctp.messages.DataChunk;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 * @author Westhawk Ltd<thp@westhawk.co.uk>
 */
public class BlockingSCTPStream extends SCTPStream {

    private static final ExecutorService _ex_service = Executors.newFixedThreadPool(100);

    private HashMap<Integer,SCTPMessage> undeliveredOutboundMessages = new HashMap();
    
    BlockingSCTPStream(Association a, Integer id) {
        super(a, id);
//        _ex_service = Executors.newSingleThreadExecutor();
    }

    @Override
    synchronized public void send(String message) throws Exception {
        Association a = super.getAssociation();
        SCTPMessage m = a.makeMessage(message, this);
        if (m != null){
            a.sendAndBlock(m);
        }
    }
    @Override
    synchronized public void send(byte[] message) throws Exception {
        Association a = super.getAssociation();
        SCTPMessage m = a.makeMessage(message, this);
        if(m != null) {
            undeliveredOutboundMessages.put(m.getSeq(), m);
            a.sendAndBlock(m);
        }
    }

    @Override
    public void deliverMessage(SCTPMessage message) {
        _ex_service.execute(message); // switch to callable ?
    }

    @Override
    public void delivered(DataChunk d) {
        int f = d.getFlags();
        if ((f & DataChunk.ENDFLAG) > 0){
            int ssn = d.getSSeqNo();
            SCTPMessage st = undeliveredOutboundMessages.remove(ssn);
            if (st != null) {st.acked();}
        }
    }

    @Override
    public boolean idle(){
        return undeliveredOutboundMessages.isEmpty();
    }
    
}
