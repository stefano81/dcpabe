package sg.edu.ntu.sce.sands.crypto.utility;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import sg.edu.ntu.sce.sands.crypto.dcpabe.Ciphertext;
import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.io.*;
import java.util.Arrays;
import java.util.Map;

/*******************************************************************
 * IBM Confidential                                                *
 *                                                                 *
 * Copyright IBM Corp. 2019                                        *
 *                                                                 *
 * The source code for this program is not published or otherwise  *
 * divested of its trade secrets, irrespective of what has         *
 * been deposited with the U.S. Copyright Office.                  *
 *******************************************************************/
@SuppressWarnings("unchecked")
public class Utility {
    public static GlobalParameters readGlobalParameters(String globalParametersPath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream inputGlobalParameters = new ObjectInputStream(new FileInputStream(globalParametersPath))) {
            return (GlobalParameters) inputGlobalParameters.readObject();
        }
    }

    public static void writePublicKeys(String publicKeysPath, Map<String, PublicKey> publicKeys) throws IOException {
        try (
                FileOutputStream fos = new FileOutputStream(publicKeysPath);
                ObjectOutputStream outputPublicKey = new ObjectOutputStream(fos)) {
            //oos.writeObject(ak.getAuthorityID());
            outputPublicKey.writeObject(publicKeys);
        }

    }

    public static void writeSecretKeys(String secretKeyPath, Map<String, SecretKey> secretKeys) throws IOException {
        try (
                FileOutputStream fos = new FileOutputStream(secretKeyPath);
                ObjectOutputStream outputSecretKey = new ObjectOutputStream(fos)) {
            //oos.writeObject(ak.getAuthorityID());
            outputSecretKey.writeObject(secretKeys);
        }

    }

    public static Map<String, SecretKey> readSecretKeys(String secretKeysPath) throws IOException, ClassNotFoundException {
        try (
                FileInputStream fis = new FileInputStream(secretKeysPath);
                ObjectInputStream secretKeys = new ObjectInputStream(fis)) {
            return (Map<String, SecretKey>) secretKeys.readObject();
        }
    }

    public static void writePersonalKey(String personalKeyPath, PersonalKey personalKey) throws IOException {
        try (
                FileOutputStream fos = new FileOutputStream(personalKeyPath);
                ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(personalKey);
        }
    }

    public static void writeGlobalParameters(String globalParameterPath, GlobalParameters globalParameters) throws IOException {
        try (
                FileOutputStream fos = new FileOutputStream(globalParameterPath);
                ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(globalParameters);
        }
    }

    public static Map<String, PublicKey> readPublicKeys(String publicKeysPath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream publicKeys = new ObjectInputStream(new FileInputStream(publicKeysPath))) {
            return (Map<String, PublicKey>) publicKeys.readObject();
        }
    }

    public static PersonalKey readPersonalKey(String personalKeyPath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream personalKey = new ObjectInputStream(new FileInputStream(personalKeyPath))) {
            return (PersonalKey) personalKey.readObject();
        }
    }

    public static PaddedBufferedBlockCipher initializeAES(byte[] key, boolean encrypt) {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        int BLOCKSIZE = 16;
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(Arrays.copyOfRange(key, 0, 192 / 8)), new byte[BLOCKSIZE]);
        aes.init(encrypt, ivAndKey);
        return aes;
    }

    public static Ciphertext readCiphertext(ObjectInputStream input) throws IOException, ClassNotFoundException {
        return (Ciphertext) input.readObject();
    }

    public static byte[] toBytes(Ciphertext oct) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(oct);
            }

            return  baos.toByteArray();
        }
    }
}
