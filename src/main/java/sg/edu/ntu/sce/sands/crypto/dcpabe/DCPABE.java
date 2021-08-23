package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure.MatrixElement;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.util.ArrayList;
import java.util.List;

public class DCPABE {
    public static GlobalParameters globalSetup(int lambda) {
        GlobalParameters params = new GlobalParameters();

        params.setPairingParameters(new TypeA1CurveGenerator(3, lambda).generate());
        Pairing pairing = PairingFactory.getPairing(params.getPairingParameters());

        params.setG1(pairing.getG1().newRandomElement().getImmutable());

        return params;
    }

    public static AuthorityKeys authoritySetup(String authorityID, GlobalParameters GP, String... attributes) {
        AuthorityKeys authorityKeys = new AuthorityKeys(authorityID);

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element eg1g1 = pairing.pairing(GP.getG1(), GP.getG1()).getImmutable();
        for (String attribute : attributes) {
            Element ai = pairing.getZr().newRandomElement().getImmutable();
            Element yi = pairing.getZr().newRandomElement().getImmutable();

            authorityKeys.getPublicKeys().put(attribute, new PublicKey(
                    eg1g1.powZn(ai).toBytes(),
                    GP.getG1().powZn(yi).toBytes()));

            authorityKeys.getSecretKeys().put(attribute, new SecretKey(ai.toBytes(), yi.toBytes()));
        }

        return authorityKeys;
    }

    public static Ciphertext encrypt(Message message, AccessStructure arho, GlobalParameters GP, PublicKeys pks) {
        Ciphertext ct = new Ciphertext();

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element M = pairing.getGT().newZeroElement();
        M.setFromBytes(message.getM());
        M = M.getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element eg1g1 = pairing.pairing(GP.getG1(), GP.getG1()).getImmutable();

        List<Element> v = new ArrayList<Element>(arho.getL());

        v.add(s);

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
        }

        List<Element> w = new ArrayList<>();
        w.add(pairing.getZr().newZeroElement().getImmutable());
        for (int i = 1; i < arho.getL(); i++) {
            w.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        ct.setC0(M.mul(eg1g1.powZn(s)).toBytes()); // C_0

        for (int x = 0; x < arho.getN(); x++) {
            Element lambdax = dotProduct(arho.getRow(x), v, pairing.getZr().newZeroElement(), pairing);
            Element wx = dotProduct(arho.getRow(x), w, pairing.getZr().newZeroElement(), pairing);

            Element rx = pairing.getZr().newRandomElement().getImmutable();

            Element c1x1 = eg1g1.powZn(lambdax);
            Element c1x2 = pairing.getGT().newElement();
            c1x2.setFromBytes(pks.getPK(arho.rho(x)).getEg1g1ai());
            c1x2.powZn(rx);

            ct.setC1(c1x1.mul(c1x2).toBytes());

            ct.setC2(GP.getG1().powZn(rx).toBytes());

            Element c3x = pairing.getG1().newElement();
            c3x.setFromBytes(pks.getPK(arho.rho(x)).getG1yi());
            ct.setC3(c3x.powZn(rx).mul(GP.getG1().powZn(wx)).toBytes());
        }

        return ct;
    }

    public static Message decrypt(Ciphertext CT, PersonalKeys pks, GlobalParameters GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(pks.getAttributes());

        if (null == toUse || toUse.isEmpty()) throw new IllegalArgumentException("Not satisfying");

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element HGID = pairing.getG1().newElement();
        HGID.setFromHash(pks.getUserID().getBytes(), 0, pks.getUserID().getBytes().length);
        HGID = HGID.getImmutable();

        Element t = pairing.getGT().newOneElement();

        for (Integer x : toUse) {
            Element c3x = pairing.getG1().newElement();
            c3x.setFromBytes(CT.getC3(x));
            Element p1 = pairing.pairing(HGID, c3x);

            Element key = pairing.getG1().newElement();
            key.setFromBytes(pks.getKey(CT.getAccessStructure().rho(x)).getKey());

            Element c2x = pairing.getG1().newElement();
            c2x.setFromBytes(CT.getC2(x));
            Element p2 = pairing.pairing(key, c2x);

            Element c1x = pairing.getGT().newElement();
            c1x.setFromBytes(CT.getC1(x));
            t.mul(c1x.mul(p1).mul(p2.invert()));
        }

        Element c0 = pairing.getGT().newElement();
        c0.setFromBytes(CT.getC0());
        c0.mul(t.invert());

        return new Message(c0.toBytes());
    }

    public static PersonalKey keyGen(String userID, String attribute, SecretKey sk, GlobalParameters GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element HGID = pairing.getG1().newElement();
        HGID.setFromHash(userID.getBytes(), 0, userID.getBytes().length);
        Element ai = pairing.getZr().newElement();
        ai.setFromBytes(sk.getAi());
        Element yi = pairing.getZr().newElement();
        yi.setFromBytes(sk.getYi());

        return new PersonalKey(attribute, GP.getG1().powZn(ai).mul(HGID.powZn(yi)).toBytes());
    }

    private static Element dotProduct(List<MatrixElement> v1, List<Element> v2, Element element, Pairing pairing) {
        if (v1.size() != v2.size()) throw new IllegalArgumentException("different length");
        if (element.isImmutable()) throw new IllegalArgumentException("immutable");

        if (!element.isZero())
            element.setToZero();

        for (int i = 0; i < v1.size(); i++) {
            Element e = pairing.getZr().newElement();
            switch (v1.get(i)) {
                case MINUS_ONE:
                    e.setToOne().negate();
                    break;
                case ONE:
                    e.setToOne();
                    break;
                case ZERO:
                    e.setToZero();
                    break;
            }
            element.add(e.mul(v2.get(i).getImmutable()));
        }

        return element.getImmutable();
    }

    public static Message generateRandomMessage(GlobalParameters GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element M = pairing.getGT().newRandomElement().getImmutable();

        return new Message(M.toBytes());
    }
}
