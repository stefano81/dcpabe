package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import org.junit.Before;
import org.junit.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

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
    public void testInfixToPolishNotationSimpleConversion() {
        String infixNotation = "a";
        AccessStructure arhoInfix = AccessStructure.buildFromPolicy(infixNotation);
        assertEquals(infixNotation, arhoInfix.toString());
    }

    @Test
    public void testInfixToPolishNotationConversionWithParentheses() {
        String infixNotation = "A and (B and C or D)";
        AccessStructure arhoInfix = AccessStructure.buildFromPolicy(infixNotation);
        assertEquals(policy, arhoInfix.toString());
    }
}
