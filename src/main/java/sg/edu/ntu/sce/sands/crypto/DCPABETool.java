package sg.edu.ntu.sce.sands.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sg.edu.ntu.sce.sands.crypto.dcpabe.*;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;
import sg.edu.ntu.sce.sands.crypto.utility.Utility;

import java.io.*;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

public class DCPABETool {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		if (encrypt(args) ||
				decrypt(args) ||
				globalsetup(args) ||
				keygen(args) ||
				authhoritySetup(args) ||
				check(args)) {
        } else {
            help();
        }
	}

    // asetup <authority name> <gpfile> <authorityfileS> <authorityfileP> <attribute 1 > ... <attribute n>
    private static boolean authhoritySetup(String[] args) {
        if (!args[0].equals("asetup") || args.length <= 5) return false;

		try {
			GlobalParameters gp = Utility.readGlobalParameters(args[2]);

			String[] subArgs = Arrays.copyOfRange(args, 5, args.length);

			AuthorityKeys ak = DCPABE.authoritySetup(args[1], gp, subArgs);

			Utility.writeSecretKeys(args[3], ak.getSecretKeys());
			Utility.writePublicKeys(args[4], ak.getPublicKeys());

            return true;
        } catch (ClassNotFoundException | IOException e) {
            System.err.println(e.getMessage());
        }

        return false;
    }

	// keygen <username> <attribute name> <gpfile> <authorityfileS> <keyfile>
	private static boolean keygen(String[] args) {
		if (!args[0].equals("keyGen") || args.length != 6) return false;

		try {
			GlobalParameters gp = Utility.readGlobalParameters(args[3]);

			Map<String, SecretKey> skeys = Utility.readSecretKeys(args[4]);

			SecretKey sk = skeys.get(args[2]);

			if (null == sk) {
				System.err.println("Attribute not handled");
				return false;
			}

			PersonalKey pk = DCPABE.keyGen(args[1], args[2], sk, gp);
            Utility.writePersonalKey(args[5], pk);

			return true;
		} catch (ClassNotFoundException | IOException e) {
			System.err.println(e.getMessage());
            e.printStackTrace();
		}

        return false;
	}

	private static boolean globalsetup(String[] args) {
		if (!args[0].equals("gsetup") || args.length != 2) return false;

		try {
			GlobalParameters gp = DCPABE.globalSetup(160);

			Utility.writeGlobalParameters(args[1], gp);

			return true;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println("Error operating on the file");
		}

		return false;
	}
	
	// check <username> <policy> <gpfile> m <authorityP 1>...<authorityP m> n <keyfile 1> ... <keyfile n>
	@SuppressWarnings("unchecked")
	private static boolean check(String[] args) {
		if (!args[0].equals("check") || args.length < 8) return false;

		try {
            GlobalParameters gp = Utility.readGlobalParameters(args[3]);

            PublicKeys pubKeys = new PublicKeys();

            int m = Integer.parseInt(args[4]);
            for (int i = 0; i < m; i++) {
                pubKeys.subscribeAuthority(Utility.readPublicKeys(args[4 + i + 1]));
            }

            Message om = DCPABE.generateRandomMessage(gp);
            AccessStructure arho = AccessStructure.buildFromPolicy(args[2]);
            Ciphertext oct = DCPABE.encrypt(om, arho, gp, pubKeys);

            byte[] cipherAsBytes = Utility.toBytes(oct);
            try (
            		ByteArrayInputStream input = new ByteArrayInputStream(cipherAsBytes);
            		ObjectInputStream ois = new ObjectInputStream(input)
			) {
                Ciphertext nct = (Ciphertext) ois.readObject();

                arho.printPolicy();

                PersonalKeys pks = new PersonalKeys(args[1]);

                int n = Integer.parseInt(args[4 + m + 1]);
                for (int i = 0; i < n; i++) {
                    pks.addKey(Utility.readPersonalKey(args[4 + i + m + 2]));
                }

                Message dm = DCPABE.decrypt(nct, pks, gp);

                System.err.println(om.m.length);
                System.err.println(dm.m.length);
                System.err.println(Arrays.toString(om.m));
                System.err.println(Arrays.toString(dm.m));

                return true;
            }
        } catch (IllegalStateException | IOException | DataLengthException | ClassNotFoundException e) {
			System.err.println(e.getMessage());
		}

        return false;
	}

	// dec <username> <ciphertext> <resource file> <gpfile> <keyfile 1> <keyfile 2>
    private static boolean decrypt(String[] args) {
        if (!args[0].equals("dec") || args.length < 6) return false;

        try (
        		FileInputStream input = new FileInputStream(args[2]);
        		ObjectInputStream oIn = new ObjectInputStream(input)
		) {
            GlobalParameters gp = Utility.readGlobalParameters(args[4]);

            PersonalKeys pks = new PersonalKeys(args[1]);

            for (int i = 5; i < args.length; i++) {
//				System.err.println(pk.getAttribute());
                pks.addKey(Utility.readPersonalKey(args[i]));
            }

            Ciphertext ct = Utility.readCiphertext(oIn);
            Message m = DCPABE.decrypt(ct, pks, gp);

            PaddedBufferedBlockCipher aes = Utility.initializeAES(m.m, false);

            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(args[3]))) {
                encryptOrDecryptPayload(aes, oIn, bos);
                bos.flush();
            }

            return true;
        } catch (IOException | ClassNotFoundException | DataLengthException | IllegalStateException | InvalidCipherTextException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }

        return false;
    }

    private static void encryptOrDecryptPayload(PaddedBufferedBlockCipher cipher, InputStream is, OutputStream os) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
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
			GlobalParameters gp = Utility.readGlobalParameters(args[4]);

			PublicKeys pks = new PublicKeys();

			for (int i = 5; i < args.length; i++) {
				pks.subscribeAuthority(Utility.readPublicKeys(args[i]));
			}

			AccessStructure arho = AccessStructure.buildFromPolicy(args[2]);
			Message m = DCPABE.generateRandomMessage(gp);
			Ciphertext ct = DCPABE.encrypt(m, arho, gp, pks);
			
			try (
					FileOutputStream fos = new FileOutputStream(args[3]);
					ObjectOutputStream oos = new ObjectOutputStream(fos);

					FileInputStream fis = new FileInputStream(args[1]);
					BufferedInputStream bis = new BufferedInputStream(fis);
			) {
				oos.writeObject(ct);

				PaddedBufferedBlockCipher aes = Utility.initializeAES(m.m, true);

				encryptOrDecryptPayload(aes, bis, oos);

				return true;

			}
		} catch (IOException | DataLengthException | ClassNotFoundException | InvalidCipherTextException | IllegalStateException e) {
			e.printStackTrace();
		}
        return false;
	}

	private static void help() {
		System.out.println("Syntax:");
		System.out.println("gsetup <gpfile>");
		System.out.println("asetup <authority name> <gpfile> <authorityfileS> <authorityfileP> <attribute 1 > ... <attribute n>");
		System.out.println("keyGen <username> <attribute name> <gpfile> <authorityfileS> <keyfile>");
		System.out.println("enc <resource file> <policy> <ciphertext> <gpfile> <authorityfileP 1> ... <authorityfileP n>");
		System.out.println("dec <ciphertext> <resource file> <gpfile> <keyfile 1> <keyfile 2>");
	}
}
