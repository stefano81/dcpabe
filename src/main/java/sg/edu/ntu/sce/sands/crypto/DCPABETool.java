package sg.edu.ntu.sce.sands.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;
import sg.edu.ntu.sce.sands.crypto.BasicCommand.ForcibleCommand;
import sg.edu.ntu.sce.sands.crypto.dcpabe.*;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;
import sg.edu.ntu.sce.sands.crypto.utility.Utility;

import java.io.*;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Command(
	name = "",
	versionProvider = sg.edu.ntu.sce.sands.crypto.utility.VersionProvider.class,
	headerHeading = "Usage:%n%n",
	synopsisHeading = "",
	descriptionHeading = "%nDescription:%n%n",
	parameterListHeading = "%nParameters:%n",
	optionListHeading = "%nOptions:%n",
	synopsisSubcommandLabel = "COMMAND [arg...]",
	description = "Toolset of commands to run a DCPABE scheme.",
	subcommands = {
		DCPABETool.AuthoritySetup.class,
		DCPABETool.Check.class,
		DCPABETool.Decrypt.class,
		DCPABETool.Encrypt.class,
		DCPABETool.GlobalSetup.class,
		DCPABETool.KeyGeneration.class,
		DCPABETool.Help.class,
	},
	footer = {"","Run COMMAND --help for more information on a command."})
public class DCPABETool implements Runnable {

	@Spec CommandSpec commandSpec;

	@Option(names = {"--version", "-V"}, versionHelp = true, description = "print version information and exit")
	boolean versionRequested;

	private static final CommandLine cmd = new picocli.CommandLine(new DCPABETool());
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		cmd.setUsageHelpAutoWidth(true);
		cmd.setUsageHelpLongOptionsMaxWidth(35);
		int exitCode = cmd.execute(args);
		System.exit(exitCode);
	}

	@Override
	public void run() {
		cmd.usage(System.out);
	}

	@Command(name = "asetup", description = "Generates public and secret keys of attributes to an authority.")
	static class AuthoritySetup extends ForcibleCommand {

		@Parameters(index = "1", paramLabel = "<authName>", description = "Authority name")
		String name;

		@Parameters(index = "2", paramLabel = "<secKeyFile>", description = "Path of file to store attribute secret keys")
		String secKeyPath;

		@Parameters(index = "3", paramLabel = "<pubKeyFile>", description = "Path of file to store attribute public keys")
		String pubKeyPath;

		@Parameters(index = "4", arity = "1..*", description = "List of attributes")
		String[] attributes;

		@Override
		public void setFilesForValidation() {
			inputFilePaths.add(gpPath);
			outputFilePaths = Arrays.asList(secKeyPath, pubKeyPath);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			GlobalParameters gp = Utility.readGlobalParameters(gpPath);

			AuthorityKeys ak = DCPABE.authoritySetup(name, gp, attributes);

			Utility.writeSecretKeys(secKeyPath, ak.getSecretKeys());
			Utility.writePublicKeys(pubKeyPath, ak.getPublicKeys());
		}
	}

	@Command(name = "keygen", description = "Generates personal key of an attribute to an user.")
	static class KeyGeneration extends ForcibleCommand {

		@Parameters(index = "1", description = "User name")
		String username;

		@Parameters(index = "2", description = "An attribute")
		String attribute;

		@Parameters(index = "3", paramLabel = "<secKeyFile>", description = "Path to file containing secret key of the attribute")
		String authoritySecKeyPath;

		@Parameters(index = "4", paramLabel = "<userKeyFile>", description = "Path of file to write user personal key")
		String userKeyPath;

		@Override
		public void setFilesForValidation() {
			inputFilePaths = Arrays.asList(gpPath, authoritySecKeyPath);
			outputFilePaths = Arrays.asList(userKeyPath);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			GlobalParameters gp = Utility.readGlobalParameters(gpPath);

			Map<String, SecretKey> skeys = Utility.readSecretKeys(authoritySecKeyPath);

			SecretKey sk = skeys.get(attribute);

			if (null == sk) {
				throw new RuntimeException("Attribute not handled");
			}

			PersonalKey pk = DCPABE.keyGen(username, attribute, sk, gp);
            Utility.writePersonalKey(userKeyPath, pk);
		}
	}

	@Command(name = "gsetup", description = "Setup DCPABE common parameters, used by users and authorities.")
	static class GlobalSetup extends ForcibleCommand {

		@Override
		public void setFilesForValidation() {
			outputFilePaths = Arrays.asList(gpPath);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			GlobalParameters gp = DCPABE.globalSetup(160);

			Utility.writeGlobalParameters(gpPath, gp);
		}
	}

	@Command(
		name = "check",
		description = "Checks wether encryption and decryption could work with provided arguments."
	)
	static class Check extends BasicCommand
	 {
		@Parameters(index = "1", description = "User name")
		String username;

		@Parameters(index = "2", description = "access policy to test")
		String policy;

		@Parameters(index = "3", split = ",", splitSynopsisLabel = ",", paramLabel = "<pubKey> ", description = "files containing public keys of the attributes used in policy")
		List<String> authPubKeys;

		@Parameters(index = "4", split = ",", splitSynopsisLabel = ",", description = "files containing personal keys of the attributes used in policy")
		List<String> userKey;

		@Option(names = {"-d", "--debug"}, description = "Prints extra information to console. Disabled by default")
		boolean debug;

		@Override
		public void setFilesForValidation() {
			inputFilePaths.add(gpPath);
			inputFilePaths.addAll(authPubKeys);
			inputFilePaths.addAll(userKey);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			GlobalParameters gp = Utility.readGlobalParameters(gpPath);

			PublicKeys pubKeys = new PublicKeys();
			for (String path : authPubKeys) {
				pubKeys.subscribeAuthority(Utility.readPublicKeys(path));
			}

            Message om = DCPABE.generateRandomMessage(gp);
            AccessStructure arho = AccessStructure.buildFromPolicy(policy);
            Ciphertext oct = DCPABE.encrypt(om, arho, gp, pubKeys);

            byte[] cipherAsBytes = Utility.toBytes(oct);
            try (
					ByteArrayInputStream input = new ByteArrayInputStream(cipherAsBytes);
				 	ObjectInputStream ois = new ObjectInputStream(input)
			) {
                Ciphertext nct = (Ciphertext) ois.readObject();

				if (debug) {
					System.out.println(arho);
				}

				PersonalKeys pks = new PersonalKeys(username);
				for (String path : userKey) {
					pks.addKey(Utility.readPersonalKey(path));
				}
				Message dm = DCPABE.decrypt(nct, pks, gp);

				boolean equalMessage = Arrays.equals(om.getM(), dm.getM());

				if (equalMessage) {
					if (debug) {
						System.out.println("message successfully encrypted and decrypted");
						System.out.println("Message: " + Arrays.toString(dm.getM()));
					}
				} else {
					throw new RuntimeException("check failed");
				}
            } catch (IllegalStateException | DataLengthException  e) {
				e.printStackTrace();			}
		}
	}

	@Command(name = "decrypt", aliases = "dec", description = "Decrypts a file.")
	static class Decrypt extends ForcibleCommand {

		@Parameters(index = "1", description = "User name")
		String username;

		@Parameters(index = "2", description = "Path to encrypted file")
		String ciphertext;

		@Parameters(index = "3", description = "output file name")
		String plaintext;

		@Parameters(index = "4", arity = "1..*", paramLabel = "<userKey>", description = "List of personal key files necessary to satisfy encrypt file policy")
		List<String> personalKeyPaths;

		@Override
		public void setFilesForValidation() {
			inputFilePaths.add(gpPath);
			inputFilePaths.addAll(personalKeyPaths);
			outputFilePaths = Arrays.asList(plaintext);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			try (
        			FileInputStream input = new FileInputStream(ciphertext);
        			ObjectInputStream oIn = new ObjectInputStream(input)
			) {
				GlobalParameters gp = Utility.readGlobalParameters(gpPath);

				PersonalKeys pks = new PersonalKeys(username);
				for (String path : personalKeyPaths) {
					pks.addKey(Utility.readPersonalKey(path));
				}

				Ciphertext ct = Utility.readCiphertext(oIn);
				Message m = DCPABE.decrypt(ct, pks, gp);
				PaddedBufferedBlockCipher aes = Utility.initializeAES(m.getM(), false);
				try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(plaintext))) {
					encryptOrDecryptPayload(aes, oIn, bos);
					bos.flush();
				}
			} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
				e.printStackTrace();
			}
		}
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

	@Command(name ="encrypt", aliases = "enc", description = "Encrypts a file.")
	static class Encrypt extends ForcibleCommand {

		@Parameters(index = "1", paramLabel = "<src>", description = "source file path")
		String plaintext;

		@Parameters(index = "2", description = "access policy for encryption, in terms of attributes and AND/OR operators")
		String policy;

		@Parameters(index = "3", paramLabel = "<out>", description = "encrypted file path")
		String ciphertext;

		@Parameters(index = "4", arity = "1..*", paramLabel = "<pubKey>", description = "files containing public keys of the attributes used in policy")
		List<String> authorityPubKeyPaths;

		@Override
		public void setFilesForValidation() {
			inputFilePaths.add(gpPath);
			inputFilePaths.addAll(authorityPubKeyPaths);
			outputFilePaths = Arrays.asList(ciphertext);
		}

		@Override
		public void commandBody() throws ClassNotFoundException, IOException {
			GlobalParameters gp = Utility.readGlobalParameters(gpPath);

			PublicKeys pks = new PublicKeys();
			for (String path : authorityPubKeyPaths) {
				pks.subscribeAuthority(Utility.readPublicKeys(path));
			}

			AccessStructure arho = AccessStructure.buildFromPolicy(policy);
			Message m = DCPABE.generateRandomMessage(gp);
			Ciphertext ct = DCPABE.encrypt(m, arho, gp, pks);

			try (
					FileOutputStream fos = new FileOutputStream(ciphertext);
					ObjectOutputStream oos = new ObjectOutputStream(fos);

					FileInputStream fis = new FileInputStream(plaintext);
					BufferedInputStream bis = new BufferedInputStream(fis);
			) {
				oos.writeObject(ct);
                PaddedBufferedBlockCipher aes = Utility.initializeAES(m.getM(), true);
				encryptOrDecryptPayload(aes, bis, oos);
			} catch (DataLengthException | InvalidCipherTextException | IllegalStateException e) {
				e.printStackTrace();
			}
		}
	}
	@Command(name = "help", description = "Shows a list of commands or help for one command.")
    static class Help implements Runnable {

        @Parameters(index = "0..1",defaultValue = "") String command;

        @Override
        public void run() {
            if (command.equals("")) {
                cmd.usage(System.out);
            } else if (!cmd.getSubcommands().containsKey(command)) {
                System.out.println("Unknown command: " + command);
            } else {
                cmd.getSubcommands().get(command).usage(System.out);
            }
        }
	}

	static CommandLine getCommandLine() {
		return cmd;
	}
}
