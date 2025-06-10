package com.github.prskr.sonartrivyscannerplugin.sensors;

import com.github.prskr.sonartrivyscannerplugin.trivy.*;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.scanner.sensor.ProjectSensor;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;


public class TrivyScanner implements ProjectSensor {

    private static final Logger LOGGER = Loggers.get(TrivyScanner.class);
    private final TrivyRunner trivyRunner;
    private final TrivyIssuerReporter issuerReporter;

    public TrivyScanner(TrivyRunner trivyRunner, TrivyIssuerReporter issuerReporter) {
        this.trivyRunner = trivyRunner;
        this.issuerReporter = issuerReporter;
    }

    public void describe(SensorDescriptor sensorDescriptor) {
        sensorDescriptor.name("Trivy-Scanner");
    }

    public void execute(SensorContext sensorContext)  {
        try {
            var scanRequest = new TrivyRunRequest(
                    sensorContext.fileSystem().baseDir(),
                    sensorContext.fileSystem().workDir(),
                    null
            );

            var scanResult = this.trivyRunner.run(scanRequest);

            issuerReporter.reportIssues(sensorContext, scanResult);
        } catch (TrivyRunnerException e) {
            LOGGER.error("Error while preparing Trivy scan: " + e.getMessage(), e);
            throw e;
        } catch (TrivyScanException e) {
            LOGGER.error("Error while performing Trivy scan: {} - output: {}", e.getMessage(), e.getCommandOutput(), e);
            throw e;
        }
    }

}
