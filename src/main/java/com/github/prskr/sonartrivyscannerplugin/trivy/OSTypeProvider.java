package com.github.prskr.sonartrivyscannerplugin.trivy;

import org.apache.commons.lang3.SystemUtils;

public abstract class OSTypeProvider {
    public static OSType getOSType() {
        if (SystemUtils.IS_OS_MAC_OSX) {
            return OSType.MacOS;
        } else if (SystemUtils.IS_OS_LINUX) {
            return OSType.Linux;
        } else if (SystemUtils.IS_OS_WINDOWS) {
            return OSType.Windows;
        } else {
            throw new UnsupportedOperationException("Unsupported operating system: " + SystemUtils.OS_NAME);
        }
    }
}
