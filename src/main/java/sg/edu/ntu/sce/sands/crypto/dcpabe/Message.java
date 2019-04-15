package sg.edu.ntu.sce.sands.crypto.dcpabe;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;

public class Message {
    private final byte[] m;

    @JsonCreator
    public Message(
            @JsonProperty("m") byte[] m) {
        this.m = m;
    }

    public byte[] getM() {
        return m;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Message message = (Message) o;
        return Arrays.equals(getM(), message.getM());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getM());
    }
}