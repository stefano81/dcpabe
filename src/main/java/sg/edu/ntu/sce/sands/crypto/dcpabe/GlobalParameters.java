package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.Serializable;


public class GlobalParameters implements Serializable {
    private static final long serialVersionUID = 1L;
    private final CurveParameters curveParams;
    private Element g1;

    public CurveParameters getCurveParams() {
        return curveParams;
    }

    public void setCurveParams(CurveParameters curveParams) {
        this.curveParams = curveParams;
    }

    public Element getG1() {
        return g1;
    }

    public void setG1(Element g1) {
        this.g1 = g1;
    }

    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        out.writeObject(curveParams);
        out.writeObject(g1.toBytes());
    }

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        curveParams = (CurveParameters) in.readObject();
        Pairing pairing = PairingFactory.getPairing(curveParams);
        g1 = pairing.getG1().newElement();
        g1.setFromBytes((byte[]) in.readObject());
        g1 = g1.getImmutable();
    }

    @Override
    public boolean equals(Object obj) {
        if (null != obj)
            if (obj instanceof GlobalParameters) {
                GlobalParameters other = (GlobalParameters) obj;
                if (curveParams.equals(other.curveParams))
                    return g1.isEqual(other.g1);
            }
        return false;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(curveParams.toString());
        sb.append(g1.toString());

        return sb.toString();
    }
}
