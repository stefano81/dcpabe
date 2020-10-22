package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import org.junit.Before;
import org.junit.Test;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure.MatrixElement;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

public class AccessStructureTest {
    private AccessStructure arho;
    private String policy;

    @Before
    public void setUp() {
        policy = "and or D and C B A";
        arho = AccessStructure.buildFromPolicy(policy);
    }

    @Test
    public void testPolicyToStringConversion() throws Exception {
        String recoveredPolicy = arho.toString();
        assertEquals(policy, recoveredPolicy);
    }

    @Test
    public void testInfixToPolishNotationWithSingleElement() {
        String infixNotation = "a";
        String infixNotation2 = "(a)";

        AccessStructure arhoInfix = AccessStructure.buildFromPolicy(infixNotation);
        AccessStructure arhoInfix2 = AccessStructure.buildFromPolicy(infixNotation2);

        assertEquals(infixNotation, arhoInfix.toString());
        assertEquals(infixNotation, arhoInfix2.toString());
    }

    @Test
    public void testInfixToPolishNotationConversionWithParentheses() {
        String infixNotation = "A and (B and C or D)";
        AccessStructure arhoInfix = AccessStructure.buildFromPolicy(infixNotation);
        assertEquals(policy, arhoInfix.toString());
    }

    @Test
    public void testAccessStructureIsEquivalentToPolicy() {
        MatrixElement __1 = MatrixElement.ONE;
        MatrixElement __0 = MatrixElement.ZERO;
        MatrixElement _m1 = MatrixElement.MINUS_ONE;
        MatrixElement[][] as1_expected = {{__1, __1, __0}, {__0, _m1, __0}, {__0, _m1, __1}, {__0, __0, _m1}};
        MatrixElement[][] as2_expected = {{__0, _m1, __0}, {__1, __1, __0}, {__1, __1, __1}, {__0, __0, _m1}};
        MatrixElement[][] as3_expected = {{__1, __1, __0}, {__1, __1, __0}, {__0, _m1, __1}, {__0, __0, _m1}};

        AccessStructure as1 = AccessStructure.buildFromPolicy("and a or d and b c");
        AccessStructure as2 = AccessStructure.buildFromPolicy("and or d and b c a");
        AccessStructure as3 = AccessStructure.buildFromPolicy("and or a b and c d");

        for (int i = 0; i < as1.getL(); i++) {
            assertEquals(Arrays.asList(as1_expected[i]), as1.getRow(i));
        }
        for (int i = 0; i < as2.getL(); i++) {
            assertEquals(Arrays.asList(as2_expected[i]), as2.getRow(i));
        }
        for (int i = 0; i < as3.getL(); i++) {
            assertEquals(Arrays.asList(as3_expected[i]), as3.getRow(i));
        }
    }

    @Test
    public void testPrintMatrixWorks() {
        String as1_str = "a: [  1  1  0]\n" + "d: [  0 -1  0]\n" + "b: [  0 -1  1]\n" + "c: [  0  0 -1]";
        String as2_str = "a: [  0 -1  0]\n" + "d: [  1  1  0]\n" + "b: [  1  1  1]\n" + "c: [  0  0 -1]";
        String as3_str = "a: [  1  1  0]\n" + "b: [  1  1  0]\n" + "c: [  0 -1  1]\n" + "d: [  0  0 -1]";

        AccessStructure as1 = AccessStructure.buildFromPolicy("and a or d and b c");
        AccessStructure as2 = AccessStructure.buildFromPolicy("and or d and b c a");
        AccessStructure as3 = AccessStructure.buildFromPolicy("and or a b and c d");

        assertEquals(as1_str, as1.getMatrixAsString());
        assertEquals(as2_str, as2.getMatrixAsString());
        assertEquals(as3_str, as3.getMatrixAsString());
    }
}
