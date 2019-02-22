package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.Serializable;
import java.util.Objects;


public class GlobalParameters implements Serializable {
    private static final long serialVersionUID = 1L;
    private PairingParameters pairingParameters;
    private Element g1;

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public void setPairingParameters(PairingParameters pairingParameters) {
        this.pairingParameters = pairingParameters;
    }

    public Element getG1() {
        return g1;
    }

    public void setG1(Element g1) {
        this.g1 = g1;
    }

    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        out.writeObject(pairingParameters);
        out.writeObject(g1.toBytes());
    }

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        pairingParameters = (PairingParameters) in.readObject();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        g1 = pairing.getG1().newElement();
        g1.setFromBytes((byte[]) in.readObject());
        g1 = g1.getImmutable();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GlobalParameters that = (GlobalParameters) o;
        return Objects.equals(pairingParameters, that.pairingParameters) &&
                Objects.equals(g1, that.g1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pairingParameters, g1);
    }

    @Override
    public String toString() {
        return pairingParameters.toString() + g1.toString();
    }
}
