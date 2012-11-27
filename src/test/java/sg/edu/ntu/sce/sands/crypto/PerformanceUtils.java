package sg.edu.ntu.sce.sands.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.DecimalFormat;

public class PerformanceUtils {
	
	//reject, instead of using mod p, to give even distribution of results
	public static BigInteger random(BigInteger p) {
	    SecureRandom rnd = new SecureRandom();
	    
	    //however, if the random number is unfortunately consistently larger than p, 
	    //will fallback to mod solution for to avoid performance loss
	    for (int cnt=0; cnt<4; cnt++) {
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
	
}
