package sg.edu.ntu.sce.sands.crypto;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(headerHeading = "@|bold,underline Usage|@:%n%n", synopsisHeading = "", descriptionHeading = "%n@|bold,underline Description|@: ", parameterListHeading = "%n@|bold,underline Parameters|@:%n", optionListHeading = "%n@|bold,underline Options|@:%n")
abstract class BasicCommand implements Runnable {

    @ArgGroup(exclusive = true)
    ExclusiveOption option;

    static class ExclusiveOption {
        @Option(names = { "-h", "--help" }, usageHelp = true, description = "Displays this help and exit")
        boolean help;
    }

    @Parameters(index = "0", paramLabel = "<gpfile>", description = "Path to Global Parameters File")
    String gpPath;

    List<String> inputFilePaths;
    List<String> outputFilePaths;

    // this variable becomes an Option in the child ForcibleCommand
    boolean overwriteEnabled;

    abstract public void setFilesForValidation();

    abstract public void commandBody() throws ClassNotFoundException, IOException;

    @Override
    public void run() {
        inputFilePaths = new ArrayList<>();
        outputFilePaths = new ArrayList<>();
        setFilesForValidation();
        validateFileInput();
        if (!overwriteEnabled) {
            validateFileOutput();
        }
        try {
            commandBody();
        } catch (ClassNotFoundException | IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }

    public void validateFileInput() {
        for (String path : inputFilePaths) {
            File f = new File(path);
            if (!f.exists()) {
                String CommandName = this.getClass().getAnnotation(Command.class).name();
                CommandLine subCommand = DCPABETool.getCommandLine().getSubcommands().get(CommandName);
                throw new ParameterException(subCommand, "File not found: " + path);
            }
        }
    }

    public void validateFileOutput() {
        for (String path : outputFilePaths) {
            File f = new File(path);
            if (f.exists()) {
                String CommandName = this.getClass().getAnnotation(Command.class).name();
                CommandLine subCommand = DCPABETool.getCommandLine().getSubcommands().get(CommandName);
                String error_msg = String.format("File already exists: %s. Use -f flag to overwrite.", path);
                throw new ParameterException(subCommand, error_msg);
            }
        }
    }

    static abstract class ForcibleCommand extends BasicCommand {

        @Option(names = { "-f", "--force" }, description = "Enables overwriting. Disabled by default")
        void setForceOverwrite(boolean forceFlag) {
            this.overwriteEnabled = forceFlag;
        }
    }
}
