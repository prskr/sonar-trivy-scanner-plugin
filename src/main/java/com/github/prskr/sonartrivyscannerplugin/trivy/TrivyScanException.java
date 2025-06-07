package com.github.prskr.sonartrivyscannerplugin.trivy;

public class TrivyScanException extends RuntimeException {
    private final String commandOutput;

    public TrivyScanException(String message, String commandOutput) {
        super(message);
        this.commandOutput = commandOutput;
    }

    public String getCommandOutput() {
        return commandOutput;
    }
}
