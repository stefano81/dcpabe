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
    protected int offsets;

    private Element table_flat[];

    public AbstractElementPowPreProcessing_Fast(Element g) {
        this.field = g.getField();
        this.bits = field.getOrder().bitLength();
        this.k = DEFAULT_K;

        initTable(g);
    }

    public AbstractElementPowPreProcessing_Fast(Field field, byte[] data) {
        this.field = field;
        this.bits = field.getOrder().bitLength();
        this.k = DEFAULT_K;
        this.data = data;
        this.offsets = field.getLengthInBytes();
        
        table_flat = new Element[data.length/offsets];
        
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

    public byte[] toBytes() {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(
                    field.getLengthInBytes() * table.length * table[0].length
            );
            for (Element[] row : table) {
                for (Element element : row) {
                    out.write(element.toBytes());
                }
            }
            return out.toByteArray();
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
            	int position = row*lookupSize+word;
            	if (table_flat[position]==null){
            		int offset=offsets*position;
            		Element element = field.newElement();
            		element.setFromBytes(data, offset);
            		table_flat[position]=element;
            	}
                result.mul(table_flat[position]);
            }
        }

        return result;
    }

}
