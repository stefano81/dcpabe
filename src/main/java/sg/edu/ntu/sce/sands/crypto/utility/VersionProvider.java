package sg.edu.ntu.sce.sands.crypto.utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import picocli.CommandLine.IVersionProvider;
import sg.edu.ntu.sce.sands.crypto.DCPABETool;

public class VersionProvider implements IVersionProvider {

    @Override
    public String[] getVersion() {
        try (
                InputStream is = DCPABETool.class.getResourceAsStream("/project.properties");
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        ) {
            String version = null;
            while (reader.ready()) {
                String line = reader.readLine();
                if (line.startsWith("version")) {
                    version = line.split("=")[1];
                    break;
                }
            }

            return new String[]{
                    "DCPABE version: " + version
            };
        } catch (IOException e) {
            throw new RuntimeException("Unable to access version information");
        }
    }
}
