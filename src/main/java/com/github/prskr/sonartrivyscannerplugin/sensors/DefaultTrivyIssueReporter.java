package com.github.prskr.sonartrivyscannerplugin.sensors;

import com.github.prskr.sonartrivyscannerplugin.TrivyScannerConstants;
import com.github.prskr.sonartrivyscannerplugin.trivy.Region;
import com.github.prskr.sonartrivyscannerplugin.trivy.ReportingDescriptor;
import com.github.prskr.sonartrivyscannerplugin.trivy.Result;
import com.github.prskr.sonartrivyscannerplugin.trivy.Run;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rules.RuleType;
import org.sonar.api.scanner.ScannerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@ScannerSide
public class DefaultTrivyIssueReporter implements TrivyIssuerReporter {
    private static final Logger LOGGER = Loggers.get(DefaultTrivyIssueReporter.class);

    @Override
    public void reportIssues(final SensorContext sensorContext, final List<Run> scanResult) {
        LOGGER.info("Processing Trivy scan results");
        for (var run : scanResult) {
            this.handleRun(sensorContext, run);
        }
    }

    private void handleRun(
            final SensorContext sensorContext,
            final Run run
    ) {
        var rulesByID = run.getTool()
                .getDriver()
                .getRules()
                .stream()
                .collect(Collectors.toMap(ReportingDescriptor::getId, r -> r));

        for (var result : run.getResults()) {
            handleResult(sensorContext, rulesByID, result);
        }
    }

    private void handleResult(
            final SensorContext sensorContext,
            final Map<String, ReportingDescriptor> rulesByID,
            final Result result
    ) {
        final var ruleId = result.getRuleId();
        final var locations = result.getLocations();

        final var rule = rulesByID.get(ruleId);
        Region region = null;
        InputFile issueFile = null;

        if (!locations.isEmpty()) {
            final var location = locations.get(0);
            final var physicalLocation = location.getPhysicalLocation();
            region = physicalLocation.getRegion();

            // Ensure that if the region is not null, it has valid start and end positions
            if (region != null && Objects.equals(region.getStartLine(), region.getEndLine()) && Objects.equals(region.getStartColumn(), region.getEndColumn())) {
                region.setEndColumn(region.getStartColumn() + 1);
            }

            final var artifactLocation = physicalLocation.getArtifactLocation();
            final String issueFileUri = artifactLocation.getUri();
            issueFile = sensorContext.fileSystem().inputFile(f -> f.toString().equals(issueFileUri));
        }

        LOGGER.info("Processing rule: {}", ruleId);

        sensorContext.newAdHocRule()
                .engineId(TrivyScannerConstants.ENGINE_ID)
                .ruleId(ruleId)
                .name(ruleId)
                .description(rule.getHelp().getText())
                .severity(mapSeverity(rule))
                .type(RuleType.VULNERABILITY)
                .save();

        final var issue = sensorContext.newExternalIssue();

        NewIssueLocation issueLocation;

        if (issueFile != null && region != null) {
            issueLocation = issue.newLocation()
                    .on(issueFile)
                    .at(issueFile.newRange(region.getStartLine(), region.getStartColumn(), region.getEndLine(), region.getEndColumn()))
                    .message(rule.getFullDescription().getText());
        } else {
            LOGGER.warn("Issue cannot be linked to a specific file or region, falling back to project level");
            issueLocation = issue.newLocation()
                    .on(sensorContext.project())
                    .message(rule.getFullDescription().getText());
        }


        issue
                .at(issueLocation)
                .engineId(TrivyScannerConstants.ENGINE_ID)
                .ruleId(ruleId)
                .type(RuleType.VULNERABILITY)
                .severity(mapSeverity(rule))
                .save();
    }

    private static Severity mapSeverity(ReportingDescriptor descriptor) {
        final Map<String, Severity> cveToSonarQubeSeverity = Map.of(
                "CRITICAL", Severity.BLOCKER,
                "HIGH", Severity.CRITICAL,
                "MEDIUM", Severity.MAJOR,
                "LOW", Severity.MINOR,
                "NONE", Severity.INFO
        );

        for (var tag : descriptor.getProperties().getTags()) {
            if (cveToSonarQubeSeverity.containsKey(tag)) {
                return cveToSonarQubeSeverity.get(tag);
            }
        }

        return Severity.INFO;
    }

}
