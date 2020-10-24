package sg.edu.ntu.sce.sands.crypto.utility;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine.IVersionProvider;
import sg.edu.ntu.sce.sands.crypto.DCPABETool;

public class VersionProvider implements IVersionProvider {

    @Override
    public String[] getVersion() {
        List<String> lines = new ArrayList<>();
        try {
            File properties = new File(DCPABETool.class.getResource("/project.properties").toURI());
            lines = Files.readAllLines(properties.toPath());
        } catch (IOException | URISyntaxException e) {
            e.printStackTrace();
        }
        String version = "null";
        for (String line : lines) {
            if (line.startsWith("version")) {
                version = line.split("=")[1];
                break;
            }
        }
        return new String[] {String.format("DCPABE version: %s", version)};
    }

}
