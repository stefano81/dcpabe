package sg.edu.ntu.sce.sands.crypto.utility;

import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.io.*;
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
        try (ObjectOutputStream outputPublicKey = new ObjectOutputStream(new FileOutputStream(publicKeysPath))) {
            //oos.writeObject(ak.getAuthorityID());
            outputPublicKey.writeObject(publicKeys);
        }
    }

    public static void writeSecretKeys(String secretKeyPath, Map<String, SecretKey> secretKeys) throws IOException {
        try (ObjectOutputStream outputSecretKey = new ObjectOutputStream(new FileOutputStream(secretKeyPath))) {
            //oos.writeObject(ak.getAuthorityID());
            outputSecretKey.writeObject(secretKeys);
        }
    }

    public static Map<String, SecretKey> readSecretKeys(String secretKeysPath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream secretKeys = new ObjectInputStream(new FileInputStream(secretKeysPath))) {
            return (Map<String, SecretKey>) secretKeys.readObject();
        }
    }

    public static void writePersonalKey(String personalKeyPath, PersonalKey personalKey) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(personalKeyPath))) {
            oos.writeObject(personalKey);
        }
    }

    public static void writeGlobalParameters(String globalParameterPath, GlobalParameters globalParameters) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(globalParameterPath))) {
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
}
