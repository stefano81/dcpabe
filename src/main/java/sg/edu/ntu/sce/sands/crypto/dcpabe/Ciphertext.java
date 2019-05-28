package sg.edu.ntu.sce.sands.crypto.dcpabe;

import com.fasterxml.jackson.annotation.JsonProperty;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

import java.io.Serializable;
import java.util.*;


public class Ciphertext implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] c0;

    @JsonProperty("c1")
    private List<byte[]> c1;
    @JsonProperty("c2")
    private List<byte[]> c2;
    @JsonProperty("c3")
    private List<byte[]> c3;
    private AccessStructure accessStructure;

    public Ciphertext() {
        c1 = new ArrayList<>();
        c2 = new ArrayList<>();
        c3 = new ArrayList<>();
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

    public void addC1(byte[] c1x) {
        c1.add(c1x);
    }

    public byte[] getC2(int x) {
        return c2.get(x);
    }

    public void addC2(byte[] c2x) {
        c2.add(c2x);
    }

    public byte[] getC3(int x) {
        return c3.get(x);
    }

    public void addC3(byte[] c3x) {
        c3.add(c3x);
    }

    public AccessStructure getAccessStructure() {
        return accessStructure;
    }

    public void setAccessStructure(AccessStructure accessStructure) {
        this.accessStructure = accessStructure;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Ciphertext that = (Ciphertext) o;
        return Arrays.equals(getC0(), that.getC0()) &&
                areEqual(c1, that.c1) &&
                areEqual(c2, that.c2) &&
                areEqual(c3, that.c3) &&
                Objects.equals(getAccessStructure(), that.getAccessStructure());
    }

    private boolean areEqual(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) return false;

        Iterator<byte[]> aIterator = a.iterator();
        Iterator<byte[]> bIterator = b.iterator();

        while (aIterator.hasNext() && bIterator.hasNext()) {
            byte[] aElement = aIterator.next();
            byte[] bElement = bIterator.next();

            if (!Arrays.equals(aElement, bElement)) return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(c1, c2, c3, getAccessStructure());
        result = 31 * result + Arrays.hashCode(getC0());
        return result;
    }

    @Override
    public String toString() {
        return "Ciphertext{" +
                "c0=" + Arrays.toString(c0) +
                ", c1=" + c1 +
                ", c2=" + c2 +
                ", c3=" + c3 +
                ", accessStructure=" + accessStructure +
                '}';
    }
}
