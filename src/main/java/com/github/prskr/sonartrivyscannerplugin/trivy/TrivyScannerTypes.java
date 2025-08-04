package com.github.prskr.sonartrivyscannerplugin.trivy;

public enum TrivyScannerTypes {
    Vuln("vuln"),
    Misconfig("misconfig"),
    Secret("secret"),
    License("license"),
    ;
    private String name;

    TrivyScannerTypes(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
