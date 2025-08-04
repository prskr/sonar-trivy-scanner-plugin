package com.github.prskr.sonartrivyscannerplugin;

import com.github.prskr.sonartrivyscannerplugin.sensors.DefaultTrivyIssueReporter;
import com.github.prskr.sonartrivyscannerplugin.sensors.TrivyScanner;
import com.github.prskr.sonartrivyscannerplugin.trivy.TrivyBinaryRunner;
import com.github.prskr.sonartrivyscannerplugin.trivy.TrivyScannerFetcher;
import org.sonar.api.Plugin;

public class TrivyPlugin implements Plugin {
    public void define(Context context) {
        context.addExtensions(TrivyScannerFetcher.class, TrivyBinaryRunner.class, DefaultTrivyIssueReporter.class, TrivyScanner.class);
        context.addExtensions(TrivyScannerConfiguration.getPropertyDefinitions());
    }
}
