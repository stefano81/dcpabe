package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Vector;

public class AbstractElementPowPreProcessing_Fast {
    public static final int DEFAULT_K = 5;

    protected Field field;

    protected int k;
    protected int bits;
    protected int numLookups;
    protected Element table[][];
    
    protected byte[] data;
    protected Integer[] offsets;


    public AbstractElementPowPreProcessing_Fast(Element g, int k) {
        this.field = g.getField();
        this.bits = field.getOrder().bitLength();
        this.k = k;

        initTable(g);
    }

    public AbstractElementPowPreProcessing_Fast(Field field, int k, byte[] data, Integer[] offsets) {
        this.field = field;
        this.bits = field.getOrder().bitLength();
        this.k = k;
        this.data = data;
        this.offsets = offsets;
        
        //initTableFromBytes(source, offset);
    }

    public Field getField() {
        return field;
    }

    public Element pow(BigInteger n) {
        return powBaseTable(n);
    }

    public Element powZn(Element n) {
        return pow(n.toBigInteger());
    }

    public Tuple<byte[], Integer[]> toBytes() {
        try {
        	int cnt=0;
        	Vector<Integer> offsets = new Vector<Integer>();
            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    field.getLengthInBytes() * table.length * table[0].length
            );
            for (Element[] row : table) {
                for (Element element : row) {
                	offsets.add(cnt);
                    out.write(element.toBytes());
                    cnt+=element.getLengthInBytes();
                }
            }
            return new Tuple<byte[], Integer[]>(out.toByteArray(), offsets.toArray(new Integer[]{0}));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    protected void initTableFromBytes(byte[] source, int offset) {
        int lookupSize = 1 << k;
        numLookups = bits / k + 1;
        table = new Element[numLookups][lookupSize];

        for (int i = 0; i < numLookups; i++) {
            for (int j = 0; j < lookupSize; j++) {
                table[i][j] = field.newElement();
                offset += table[i][j].setFromBytes(source, offset);
            }
        }
    }

    /**
     * build k-bit base table for n-bit exponentiation w/ base a
     *
     * @param g an element
     */
    protected void initTable(Element g) {
        int lookupSize = 1 << k;

        numLookups = bits / k + 1;
        table = new Element[numLookups][lookupSize];

        Element multiplier = g.duplicate();

        for (int i = 0; i < numLookups; i++) {
            table[i][0] = field.newOneElement();

            for (int j = 1; j < lookupSize; j++) {
                table[i][j] = multiplier.duplicate().mul(table[i][j - 1]);
            }
            multiplier.mul(table[i][lookupSize - 1]);
        }
    }

    protected Element powBaseTable(BigInteger n) {
        /* early abort if raising to power 0 */
        if (n.signum() == 0) {
            return field.newOneElement();
        }

        if (n.compareTo(field.getOrder()) > 0)
            n = n.mod(field.getOrder());

        Element result = field.newOneElement();
        
        int numLookups = n.bitLength() / k + 1;
        
        int lookupSize = 1 << k;

        for (int row = 0; row < numLookups; row++) {
            int word = 0;
            for (int s = 0; s < k; s++) {
                word |= (n.testBit(k * row + s) ? 1 : 0) << s;
            }

            if (word > 0) {
            	field.newElement().setFromBytes(data,offsets[0]);
            	field.newElement().setFromBytes(data,offsets[1]);
            	
            	int offset=offsets[row*lookupSize+word];
            	Element element = field.newElement();
            	element.setFromBytes(data, offset);
                result.mul(element);
            }
        }

        return result;
    }

}
