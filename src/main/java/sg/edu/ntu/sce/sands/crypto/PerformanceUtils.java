package sg.edu.ntu.sce.sands.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.DecimalFormat;

import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;

public class PerformanceUtils {
	
	public final static int TEST_PERIOD_MILLIS = 23000;
	
	//default performance index on a computer, used to normalize test results
	public final static double DEFAULT_PERFORMANCE = 40.52174;
	
	//reject, instead of using mod p, to give even distribution of results
	public static BigInteger random(BigInteger p) {
	    SecureRandom rnd = new SecureRandom();
	    
	    //however, if the random number is unfortunately consistently larger than p, 
	    //will fallback to mod solution for to avoid performance loss
	    for (int cnt=0; cnt<3; cnt++) {
	        BigInteger num = new BigInteger(p.bitLength(), rnd);
	        if (num.compareTo(p) <= 0)
	            return num;
	    }
	    
	    return new BigInteger(p.bitLength(), rnd).mod(p.add(BigInteger.ONE));
	}
	
	//precision: how many decimal after the dot
	public static String formatNumber(double num, int precision)
	{
		String format = "###,###,###,###,##0";
		
		if (precision == 0)
		{
			DecimalFormat df = new DecimalFormat(format);
			return df.format(num);
		}
		
		format = "###,###,###,###,##0.";
		for(int x = 0; x < precision; x++)
			format = format + "0";
		DecimalFormat df = new DecimalFormat(format);
		
		return df.format(num);
	}
	
	//determine CPU integer performance
	public static double getPerformanceIndex(GlobalParameters gp){
		long count = 0;
		
		Pairing pairing = PairingFactory.getPairing(gp.getCurveParams());
		
		long start = System.currentTimeMillis();

		while (System.currentTimeMillis() - start < TEST_PERIOD_MILLIS) {
			BigInteger bgint = BigInteger.valueOf(2).pow(37).subtract(
								random(BigInteger.valueOf(2).pow(5)));
			Element e = pairing.getG1().newRandomElement().getImmutable();
			e.pow(bgint);
			count++;
		}
		
		return count*1000.0/(double)TEST_PERIOD_MILLIS;
	}
	
}
