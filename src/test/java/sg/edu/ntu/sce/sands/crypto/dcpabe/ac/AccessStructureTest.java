package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

import static org.junit.Assert.assertEquals;

public class AccessStructureTest {
    private AccessStructure arho;
    private String policy;

    @Before
    public void setUp() {
        policy = "and A or D and C B";
        arho = AccessStructure.buildFromPolicy(policy);
    }

    @Test
    public void testPolicyToStringConversion() throws Exception{
        String recoveredPolicy = arho.toString();
        assertEquals(policy, recoveredPolicy);
    }
}
