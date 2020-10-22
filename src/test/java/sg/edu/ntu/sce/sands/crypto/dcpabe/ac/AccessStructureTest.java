package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import org.junit.Before;
import org.junit.Test;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure.MatrixElement;

import static org.junit.Assert.assertEquals;

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
    public void testASMatrixEquivalentToPolicy() {
        MatrixElement ONE = MatrixElement.ONE;
        MatrixElement ZERO = MatrixElement.ZERO;
        MatrixElement MINUS_ONE = MatrixElement.MINUS_ONE;

        MatrixElement[][] as1_expected = {
            {ONE, ONE, ZERO},
            {ZERO, MINUS_ONE, ZERO},
            {ZERO, MINUS_ONE, ZERO},
            {ZERO, MINUS_ONE, ONE},
            {ZERO, ZERO, MINUS_ONE}};

        AccessStructure as1 = AccessStructure.buildFromPolicy("and a or d and b c");

        System.out.println(as1.toString());
        as1.printMatrix();

        AccessStructure as2 = AccessStructure.buildFromPolicy("and or d and b c a");
        System.out.println(as2.toString());
        as2.printMatrix();

        AccessStructure as3 = AccessStructure.buildFromPolicy("and or a b and c d");
        System.out.println(as3.toString());
        as3.printMatrix();
    }

    @Test
    public void testPrintMatrixWorks() {

        String matrix_str1 = "a: [  1  1  0]\n" + "d: [  0 -1  0]\n" + "b: [  0 -1  1]\n" + "c: [  0  0 -1]";
        String matrix_str2 = "a: [  0 -1  0]\n" + "d: [  1  1  0]\n" + "b: [  1  1  1]\n" + "c: [  0  0 -1]";
        String matrix_str3 = "a: [  1  1  0]\n" + "b: [  1  1  0]\n" + "c: [  0 -1  1]\n" + "d: [  0  0 -1]";

    }
}
