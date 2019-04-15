package sg.edu.ntu.sce.sands.crypto.dcpabe;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

@JsonSerialize(using = GlobalParameters.Serializer.class)
@JsonDeserialize(using = GlobalParameters.Deserializer.class)
public class GlobalParameters implements Serializable {
    private static final long serialVersionUID = 1L;
    private PairingParameters pairingParameters;
    private Element g1;

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }

    public void setPairingParameters(PairingParameters pairingParameters) {
        this.pairingParameters = pairingParameters;
    }

    public Element getG1() {
        return g1;
    }

    public void setG1(Element g1) {
        this.g1 = g1;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(pairingParameters);
        out.writeObject(g1.toBytes());
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        pairingParameters = (PairingParameters) in.readObject();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        g1 = pairing.getG1().newElement();
        g1.setFromBytes((byte[]) in.readObject());
        g1 = g1.getImmutable();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GlobalParameters that = (GlobalParameters) o;
        return Objects.equals(pairingParameters, that.pairingParameters) &&
                Objects.equals(g1, that.g1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pairingParameters, g1);
    }

    @Override
    public String toString() {
        return pairingParameters.toString() + g1.toString();
    }

    static class Serializer extends JsonSerializer {
        @Override
        public void serialize(Object o, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            if (!(o instanceof GlobalParameters))
                throw new RuntimeException("Unable to serialize GlobalParameters, wrong class " + o.getClass().getCanonicalName());

            GlobalParameters gp = (GlobalParameters) o;

            jsonGenerator.writeStartObject();

            try (
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(gp.pairingParameters);

                jsonGenerator.writeBinaryField("pairingParameters", baos.toByteArray());
            }
            jsonGenerator.writeBinaryField("g1", gp.g1.toBytes());
            jsonGenerator.writeEndObject();
        }
    }

    static class Deserializer extends JsonDeserializer {
        @Override
        public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
            JsonNode node = jsonParser.getCodec().readTree(jsonParser);

            if (!node.isObject()) throw new RuntimeException("Unable to de-serialize GlobalParameters, not an object");

            PairingParameters pairingParameters = null;
            byte[] g1Bytes = null;

            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                final Map.Entry<String, JsonNode> field = it.next();

                final String fieldName = field.getKey();
                final JsonNode fieldValue = field.getValue();

                /*if (!fieldValue.isBinary())
                    throw new RuntimeException("Unable to deserialize GlobalParameters: wrong value type for field " + fieldName);*/

                if ("pairingParameters".equals(fieldName)) {
                    try (
                            ByteArrayInputStream bais = new ByteArrayInputStream(field.getValue().binaryValue());
                            ObjectInputStream ois = new ObjectInputStream(bais);
                    ) {
                        pairingParameters = (PairingParameters) ois.readObject();
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException("Unable to deserialize GlobalParameters: unable to deserialize  " + fieldName);
                    }

                } else if ("g1".equals(fieldName)) {
                    g1Bytes = fieldValue.binaryValue();
                } else {
                    throw new RuntimeException("Unable to deserialize GlobalParameters: unknown field " + fieldName);
                }
            }

            if (null == pairingParameters)
                throw new RuntimeException("Unable to deserialize GlobalParameters: missing field pairingParameters");
            if (null == g1Bytes) throw new RuntimeException("Unable to deserialize GlobalParameters: missing field g1");

            Pairing pairing = PairingFactory.getPairing(pairingParameters);
            Element g1 = pairing.getG1().newElement();
            g1.setFromBytes(g1Bytes);
            g1 = g1.getImmutable();

            final GlobalParameters gp = new GlobalParameters();
            gp.setPairingParameters(pairingParameters);
            gp.setG1(g1);

            return gp;
        }
    }
}
