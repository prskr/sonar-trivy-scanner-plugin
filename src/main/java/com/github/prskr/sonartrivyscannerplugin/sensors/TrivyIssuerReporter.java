package com.github.prskr.sonartrivyscannerplugin.sensors;

import com.github.prskr.sonartrivyscannerplugin.trivy.Run;
import org.sonar.api.batch.sensor.SensorContext;

import java.util.List;

public interface TrivyIssuerReporter {
    void reportIssues(SensorContext sensorContext, List<Run> scanResult);
}
