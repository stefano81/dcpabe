package sg.edu.ntu.sce.sands.crypto.dcpabe;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


public class Ciphertext implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] c0;
    private List<byte[]> c1;
    private List<byte[]> c2;
    private List<byte[]> c3;
    private AccessStructure accessStructure;

    public Ciphertext() {
        c1 = new ArrayList<byte[]>();
        c2 = new ArrayList<byte[]>();
        c3 = new ArrayList<byte[]>();
    }

    public byte[] getC0() {
        return c0;
    }

    public void setC0(byte[] c0) {
        this.c0 = c0;
    }

    public byte[] getC1(int x) {
        return c1.get(x);
    }

    public void setC1(byte[] c1x) {
        c1.add(c1x);
    }

    public byte[] getC2(int x) {
        return c2.get(x);
    }

    public void setC2(byte[] c2x) {
        c2.add(c2x);
    }

    public byte[] getC3(int x) {
        return c3.get(x);
    }

    public void setC3(byte[] c3x) {
        c3.add(c3x);
    }

    public AccessStructure getAccessStructure() {
        return accessStructure;
    }

    public void setAccessStructure(AccessStructure accessStructure) {
        this.accessStructure = accessStructure;
    }
}
