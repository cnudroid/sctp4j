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
package pe.pi.sctp4j.sctp.messages;

import pe.pi.sctp4j.sctp.dataChannel.DECP.DCOpen;
import pe.pi.sctp4j.sctp.messages.exceptions.InvalidDataChunkException;
import com.phono.srtplight.Log;
import java.nio.ByteBuffer;
import java.util.Comparator;

/**
 *
 * @author Westhawk Ltd<thp@westhawk.co.uk>
 */
public class DataChunk extends Chunk implements Comparable, Comparator {

    /*
   +-------------------------------+----------+-----------+------------+
   | Value                         | SCTP     | Reference | Date       |
   |                               | PPID     |           |            |
   +-------------------------------+----------+-----------+------------+
   | WebRTC String                 | 51       | [RFCXXXX] | 2013-09-20 |
   | WebRTC Binary Partial         | 52       | [RFCXXXX] | 2013-09-20 |
   | (Deprecated)                  |          |           |            |
   | WebRTC Binary                 | 53       | [RFCXXXX] | 2013-09-20 |
   | WebRTC String Partial         | 54       | [RFCXXXX] | 2013-09-20 |
   | (Deprecated)                  |          |           |            |
   | WebRTC String Empty           | 56       | [RFCXXXX] | 2014-08-22 |
   | WebRTC Binary Empty           | 57       | [RFCXXXX] | 2014-08-22 |
   +-------------------------------+----------+-----------+------------+

     */

    public final static int WEBRTCCONTROL = 50;
    public final static int WEBRTCSTRING = 51;
    public final static int WEBRTCBINARY = 53;
    public final static int WEBRTCSTRINGEMPTY = 56;
    public final static int WEBRTCBINARYEMPTY = 57;

    public final static int BEGINFLAG = 2;
    public final static int ENDFLAG = 1;
    public final static int SINGLEFLAG = 3;
    public final static int UNORDERED = 4;

    private long _tsn;
    private int _streamId;
    private int _sSeqNo;
    private int _ppid;
    private byte[] _data;
    private int _dataOffset;
    private int _dataLength;

    private DCOpen _open;
    private InvalidDataChunkException _invalid;
    private boolean _gapAck;
    private long _retryTime;
    private int _retryCount;
    private long _sentTime;

    private int _defaultCapacity = 512;

    public DataChunk(byte type, byte flags, int length, ByteBuffer pkt) {
        super(type, flags, length, pkt);
        Log.debug("read in chunk header " + length);
        Log.debug("body remaining " + _body.remaining());

        if (_body.remaining() >= 12) {
            _tsn = getUnsignedInt(_body);
            _streamId = _body.getChar();
            _sSeqNo = _body.getChar();
            _ppid = _body.getInt();

            Log.debug(" _tsn : " + _tsn
                    + " _streamId : " + _streamId
                    + " _sSeqNo : " + _sSeqNo
                    + " _ppid : " + _ppid);
            Log.debug("data size remaining " + _body.remaining());

            switch (_ppid) {
                case WEBRTCCONTROL:
                    ByteBuffer bb = _body.slice();
                    try {
                        _open = new DCOpen(bb);
                    } catch (InvalidDataChunkException ex) {
                        _invalid = ex;
                    }
                    Log.verb("Got an DCEP " + _open);
                    break;
                case WEBRTCSTRING:
                    // what format is a string ?
                    _data = new byte[_body.remaining()];
                    _body.get(_data);
                    _dataOffset = 0;
                    _dataLength = _data.length;
                    Log.verb("String data is " + new String(_data));
                    break;
                case WEBRTCBINARY:
                    _data = new byte[_body.remaining()];
                    _body.get(_data);
                    _dataOffset = 0;
                    _dataLength = _data.length;
                    Log.verb("data is " + Packet.getHex(_data));
                    break;

                default:
                    _invalid = new InvalidDataChunkException("Invalid Protocol Id in data Chunk " + _ppid);
                    break;
            }
        }
    }

    public String getDataAsString() {
        String ret;
        switch (_ppid) {
            case WEBRTCCONTROL:
                ret = "Got an DCEP " + _open;
                break;
            case WEBRTCSTRING:
                ret = new String(_data, _dataOffset, _dataLength);
                break;
            case WEBRTCSTRINGEMPTY:
                ret = "Empty String message";
                break;
            case WEBRTCBINARY:
                byte[] p = new byte[_dataLength];
                System.arraycopy(_data, _dataOffset, p, 0, _dataLength);
                ret = Packet.getHex(_data);
                break;
            case WEBRTCBINARYEMPTY:
                ret = "Empty binay message";
                break;
            default:
                ret = "Invalid Protocol Id in data Chunk " + _ppid;
                break;
        }
        return ret;
    }

    @Override
    public void validate() throws InvalidDataChunkException {
        if (_invalid != null) {
            throw _invalid;
        }
    }

    public DataChunk() {
        super((byte) Chunk.DATA);
        setFlags(0); // default assumption.
    }

    public DataChunk(int capacity) {
        this();
        _defaultCapacity = capacity;
    }


    /*
   
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Type = 0    | Reserved|U|B|E|    Length                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                              TSN                              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Stream Identifier S      |   Stream Sequence Number n    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Payload Protocol Identifier                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     \                                                               \
     /                 User Data (seq n of Stream S)                 /
     \                                                               \
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     */

    public long getTsn() {
        return _tsn;
    }

    public int getStreamId() {
        return this._streamId;
    }

    public int getSSeqNo() {
        return this._sSeqNo;
    }

    public int getPpid() {
        return this._ppid;
    }

    public byte[] getData() {
        return this._data;
    }

    public DCOpen getDCEP() {
        return this._open;
    }

    public void setPpid(int pp) {
        _ppid = pp;
    }

    public int getDataSize() {
        return _dataLength;
    }

    public int getChunkLength() {
        int len = super.getLength();
        if (len == 0) {
            // ie outbound chunk.
            len = _dataLength + 12 + 4;
        }
        return len;
    }

    @Override
    void putFixedParams(ByteBuffer ret) {
        putUnsignedInt(ret, _tsn);// = _body.getInt();
        ret.putChar((char) _streamId);// = _body.getChar();
        ret.putChar((char) _sSeqNo);// = _body.getChar();
        ret.putInt(_ppid);// = _body.getInt();
        ret.put(_data, _dataOffset, _dataLength);
    }

    /**
     * @param tsn the _tsn to set
     */
    public void setTsn(long tsn) {
        _tsn = tsn;
    }

    /**
     * @param streamId the _streamId to set
     */
    public void setStreamId(int streamId) {
        _streamId = streamId;
    }

    /**
     * @param sSeqNo the _sSeqNo to set
     */
    public void setsSeqNo(int sSeqNo) {
        _sSeqNo = sSeqNo;
    }

    public DataChunk mkAck(DCOpen dcep) {
        DataChunk ack = new DataChunk();
        ack.setData(dcep.mkAck());
        ack._ppid = WEBRTCCONTROL;
        ack.setFlags(DataChunk.SINGLEFLAG);

        return ack;
    }

    public static DataChunk mkDCOpen(String label) {
        DataChunk open = new DataChunk();
        DCOpen dope = new DCOpen(label);
        open.setData(dope.getBytes());
        open._ppid = WEBRTCCONTROL;
        open.setFlags(DataChunk.SINGLEFLAG);
        return open;
    }

    /*
    public DataChunk(String s) {
        this();
        _data = s.getBytes();
        _ppid = WEBRTCSTRING;
    }
     */
    public String toString() {
        String ret = super.toString();
        ret += " ppid = " + _ppid + "seqn " + _sSeqNo + " streamId " + _streamId + " tsn " + _tsn
                + " retry " + _retryTime + " gap acked " + _gapAck;
        return ret;
    }

    public void setFlags(int flag) {
        _flags = (byte) flag;
    }

    public int getFlags() {
        return _flags;
    }

    public int getCapacity() {
        return _defaultCapacity-50; // shrug - needs to be less than the theoretical MTU or slow start fails.
    }

    public void setData(byte[] data) {
        _data = data;
        _dataLength = data.length;
        _dataOffset = 0;
    }

    /**
     * Only use this method if you are certain that data won't be reused until
     * this chunk is sent and ack'd ie after MessageCompleteHandler has been
     * called for the surrounding message
     */
    public void setData(byte[] data, int offs, int len) {
        _data = data;
        _dataLength = len;
        _dataOffset = offs;
    }

    public void setGapAck(boolean b) {
        _gapAck = b;
    }

    public boolean getGapAck() {
        return _gapAck;
    }

    public void setRetryTime(long l) {
        _retryTime = l;
        _retryCount++;
    }

    public long getRetryTime() {
        return _retryTime;
    }

    @Override
    public int compareTo(Object o) {
        return compare(this, o);
    }

    @Override
    public int compare(Object o1, Object o2) {
        return (int) (((DataChunk) o1)._tsn - ((DataChunk) o2)._tsn);
    }

    public long getSentTime() {
        return _sentTime;
    }

    public void setSentTime(long now) {
        _sentTime = now;
    }

}
