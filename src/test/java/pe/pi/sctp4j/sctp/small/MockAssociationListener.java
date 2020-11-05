package pe.pi.sctp4j.sctp.small;

import com.phono.srtplight.Log;
import pe.pi.sctp4j.sctp.Association;
import pe.pi.sctp4j.sctp.AssociationListener;
import pe.pi.sctp4j.sctp.SCTPStream;

public class MockAssociationListener implements AssociationListener {

    public Boolean associated = false;
    SCTPStream stream = null;

    @Override
    synchronized public void onAssociated(Association a) {
        Log.debug("associated");
        associated = true;
        this.notifyAll();
    }

    @Override
    synchronized public void onDisAssociated(Association a) {
        Log.debug("dis associated");
        associated = false;
        this.notifyAll();
    }

    @Override
    public void onDCEPStream(SCTPStream s, String label, int type) {
        Log.debug("dcep stream");
    }

    @Override
    public void onRawStream(SCTPStream s) {
        stream = s;
    }
}
