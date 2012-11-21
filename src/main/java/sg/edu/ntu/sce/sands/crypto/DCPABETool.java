package sg.edu.ntu.sce.sands.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.PaddedBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sg.edu.ntu.sce.sands.crypto.dcpabe.AuthorityKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.Ciphertext;
import sg.edu.ntu.sce.sands.crypto.dcpabe.DCPABE;
import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;
import sg.edu.ntu.sce.sands.crypto.dcpabe.Message;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PersonalKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PublicKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.SecretKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

public class DCPABETool {
	private static int BLOCKSIZE = 16;

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		
		
		if (encrypt(args) ||
				decrypt(args) ||
				globalsetup(args) ||
				keygen(args) ||
				authhoritysetup(args))
			return;
		else
			help();
	}

	// asetup <authority name> <gpfile> <authorityfileS> <authorityfileP> <attribute 1 > ... <attribute n>
	private static boolean authhoritysetup(String[] args) {
		if (!args[0].equals("asetup") || args.length <= 5) return false;

		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[2]));

			GlobalParameters gp = (GlobalParameters) ois.readObject();
			ois.close();

			String[] subArgs = Arrays.copyOfRange(args, 5, args.length);

			AuthorityKeys ak = DCPABE.authoritySetup(args[1], gp, subArgs);

			ObjectOutputStream oos =  new ObjectOutputStream(new FileOutputStream(args[3]));
			//oos.writeObject(ak.getAuthorityID());
			oos.writeObject(ak.getSecretKeys());
			oos.flush();
			oos.close();

			oos = new ObjectOutputStream(new FileOutputStream(args[4]));
			//oos.writeObject(ak.getAuthorityID());
			oos.writeObject(ak.getPublicKeys());
			oos.flush();
			oos.close();

			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
		}

		return false;
	}

	// keygen <username> <attribute name> <gpfile> <authorityfileS> <keyfile>
	private static boolean keygen(String[] args) {
		if (!args[0].equals("keygen") || args.length != 6) return false;

		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[3]));
			GlobalParameters gp = (GlobalParameters) ois.readObject();
			ois.close();

			ois = new ObjectInputStream(new FileInputStream(args[4]));
			//ois.readObject(); // flush the ID
			@SuppressWarnings("unchecked")
			Map<String, SecretKey> skeys = (Map<String, SecretKey>) ois.readObject();
			ois.close();

			SecretKey sk = skeys.get(args[2]);

			if (null == sk) {
				System.err.println("Attribute not handled");
				return false;
			}

			PersonalKey pk = DCPABE.keyGen(args[1], args[2], sk, gp);

			ObjectOutputStream oos =  new ObjectOutputStream(new FileOutputStream(args[5]));
			oos.writeObject(pk);
			oos.flush();
			oos.close();

			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
		}

		return false;
	}

	private static boolean globalsetup(String[] args) {
		if (!args[0].equals("gsetup") || args.length != 2) return false;

		try {
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(args[1]));

			GlobalParameters gp = DCPABE.globalSetup(160);

			oos.writeObject(gp);
			oos.flush();
			oos.close();

			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println("Error operating on the file");
		}

		return false;
	}

	// dec <username> <ciphertext> <resource file> <gpfile> <keyfile 1> <keyfile 2>
	private static boolean decrypt(String[] args) {
		System.out.println(Arrays.toString(args));
		System.out.println(args.length);
		if (!args[0].equals("dec") || args.length < 6) {System.err.println("false");return false;}
		//Security.addProvider(new BouncyCastleProvider());

		try {
			ObjectInputStream oIn = new ObjectInputStream(new FileInputStream(args[2]));
			Ciphertext ct = (Ciphertext) oIn.readObject();
			
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[4]));
			GlobalParameters gp = (GlobalParameters) ois.readObject();
			ois.close();

			PersonalKeys pks = new PersonalKeys(args[1]);
			
			for (int i = 5; i < args.length; i++) {
				ois = new ObjectInputStream(new FileInputStream(args[i]));
				PersonalKey pk = (PersonalKey) ois.readObject();
				ois.close();
				pks.addKey(pk);
			}
			
			Message m = DCPABE.decrypt(ct, pks, gp);

			PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
		    CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(Arrays.copyOfRange(m.m, 0, 192/8)), new byte[BLOCKSIZE]);
		    aes.init(true, ivAndKey);
		    
		    cipherData(aes, oIn, new BufferedOutputStream(new FileOutputStream(args[3])));
			
			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}
	
	private static void cipherData(PaddedBufferedBlockCipher cipher, InputStream is, OutputStream os) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException  {
		byte[] inBuff = new byte[cipher.getBlockSize()];
	    byte[] outBuff = new byte[cipher.getOutputSize(inBuff.length)];
	    int nbytes;
	    while (-1 != (nbytes = is.read(inBuff, 0, inBuff.length))) {
	    	int length1 = cipher.processBytes(inBuff, 0, nbytes, outBuff, 0);
	    	os.write(outBuff, 0, length1);
	    }
	    nbytes = cipher.doFinal(outBuff, 0);
	    os.write(outBuff, 0, nbytes);
	}

	// enc <resource file> <policy> <ciphertext> <gpfile> <authorityfileP 1> ... <authorityfileP n>
	@SuppressWarnings("unchecked")
	private static boolean encrypt(String[] args) {
		if (!args[0].equals("enc") || args.length < 6) return false;

		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[4]));

			GlobalParameters gp = (GlobalParameters) ois.readObject();
			ois.close();

			PublicKeys pks = new PublicKeys();

			for (int i = 5; i < args.length; i++) {
				ois = new ObjectInputStream(new FileInputStream(args[i]));
				pks.subscribeAuthority((Map<String, PublicKey>) ois.readObject());
			}

			AccessStructure arho = AccessStructure.buildFromPolicy(args[2]);
			Message m = new Message();
			Ciphertext ct = DCPABE.encrypt(m, arho, gp, pks);

			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(args[3]));
			oos.writeObject(ct);
			
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(args[1]));

			PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
		    CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(Arrays.copyOfRange(m.m, 0, 192/8)), new byte[BLOCKSIZE]);
		    aes.init(true, ivAndKey);
		    
		    cipherData(aes, bis, oos);

		    oos.flush();
		    oos.close();
		   
			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private static void help() {
		System.out.println("Syntax:");
		System.out.println("gsetup <gpfile>");
		System.out.println("asetup <authority name> <gpfile> <authorityfileS> <authorityfileP> <attribute 1 > ... <attribute n>");
		System.out.println("keygen <username> <attribute name> <gpfile> <authorityfileS> <keyfile>");
		System.out.println("enc <resource file> <policy> <ciphertext> <gpfile> <authorityfileP 1> ... <authorityfileP n>");
		System.out.println("dec <ciphertext> <resource file> <gpfile> <keyfile 1> <keyfile 2>");
	}
}
