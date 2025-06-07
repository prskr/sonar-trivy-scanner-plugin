package com.github.prskr.sonartrivyscannerplugin.trivy;

import com.github.prskr.sonartrivyscannerplugin.utils.compression.Decompressor;
import com.github.prskr.sonartrivyscannerplugin.utils.compression.TarGzDecompressor;
import com.github.prskr.sonartrivyscannerplugin.utils.compression.ZipDecompressor;

public enum OSType {
    MacOS,
    Linux,
    Windows;

    public String getArchiveExtension() {
        return switch (this) {
            case MacOS, Linux -> ".tar.gz";
            case Windows -> ".zip";
        };
    }

    public String executableExtension() {
        return switch (this) {
            case MacOS, Linux -> "";
            case Windows -> ".exe";
        };
    }

    public String systemDependentBinaryName(String baseName) {
        return baseName + executableExtension();
    }

    public Decompressor Decompressor() {
        return switch (this) {
            case MacOS, Linux -> new TarGzDecompressor();
            case Windows -> new ZipDecompressor();
        };
    }
}
