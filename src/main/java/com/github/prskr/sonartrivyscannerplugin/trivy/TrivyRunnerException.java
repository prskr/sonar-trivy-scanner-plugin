package com.github.prskr.sonartrivyscannerplugin.trivy;

public class TrivyRunnerException extends RuntimeException {
    public TrivyRunnerException(String message) {
        super(message);
    }

    public TrivyRunnerException(String message, Throwable cause) {
        super(message, cause);
    }
}
