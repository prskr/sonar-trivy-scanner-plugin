package com.github.prskr.sonartrivyscannerplugin.trivy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.prskr.sonartrivyscannerplugin.TrivyScannerConfiguration;
import com.github.prskr.sonartrivyscannerplugin.TrivyScannerConstants;
import org.sonar.api.scanner.ScannerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.sonar.api.config.Configuration;

@ScannerSide
public class TrivyBinaryRunner implements TrivyRunner {

    private static final Logger LOGGER = Loggers.get(TrivyBinaryRunner.class);
    private final TrivyScannerFetcher trivyScannerFetcher;
    private final Configuration configuration;
    private final ObjectMapper mapper;

    public TrivyBinaryRunner(TrivyScannerFetcher trivyScannerFetcher, Configuration config) {
        this.trivyScannerFetcher = trivyScannerFetcher;
        this.configuration = config;
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());
    }


    @Override
    public List<Run> run(TrivyRunRequest request) throws TrivyRunnerException, TrivyScanException {
        String trivyScannerPath;

        try {
            trivyScannerPath = this.trivyScannerFetcher.trivyScannerBinaryPath(this.configuration.get(TrivyScannerConfiguration.TRIVY_BINARY_VERSION));
        } catch (URISyntaxException | IOException | RuntimeException e) {
            throw new TrivyRunnerException("Error while resolving Trivy scanner executable path", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TrivyRunnerException("Trivy scanner fetch was interrupted", e);
        }

        int exitCode;
        Process trivyScanProcess;
        Path trivyOutputPath = request.outputDirectory().toPath().resolve("trivy_scan_result.sarif");

        LOGGER.info(
                "Starting Trivy scan on directory {} with trivy from {}. Results will be stored at {}",
                request.targetDirectory(),
                trivyScannerPath,
                trivyOutputPath
        );

        var trivyCommandBuilder = CommandBuilder.builder(trivyScannerPath)
                .withPositionalArgument("fs")
                .withFlag("format", "sarif")
                .withFlag("output", trivyOutputPath.toString())
                .withFlag("quiet")
                .withFlag("skip-version-check")
                .withFlag("timeout", "5m");

        trivyCommandBuilder = FlagsProcessor.processFlags(trivyCommandBuilder, this.configuration)
                .withPositionalArgument(request.targetDirectory().getAbsolutePath());


        try {
            trivyScanProcess = new ProcessBuilder()
                    .command(trivyCommandBuilder.build())
                    .directory(request.targetDirectory())
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.PIPE)
                    .start();

            if (trivyScanProcess.waitFor(5, TimeUnit.MINUTES)) {
                exitCode = trivyScanProcess.exitValue();
            } else {
                trivyScanProcess.destroyForcibly();
                throw new TrivyRunnerException("Trivy scan timed out after 5 minutes");
            }

        } catch (IOException e) {
            throw new TrivyRunnerException("Error while executing Trivy scan", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TrivyRunnerException("Trivy scan was interrupted", e);
        }

        try {
            LOGGER.info("Trivy scan finished with exit code {}. Collecting results.", exitCode);

            String errorOutput;
            try (var errorReader = trivyScanProcess.errorReader()) {
                errorOutput = errorReader.lines().collect(Collectors.joining());
            }

            if (exitCode != 0) {
                throw new TrivyScanException("Trivy scan process failed with exit code: " + exitCode, errorOutput);
            }
        } catch (IOException e) {
            throw new TrivyRunnerException("Error checking Trivy scan result", e);
        }

        SarifSchema210 scanResult;

        try (InputStream trivyOutputStream = Files.newInputStream(trivyOutputPath)) {
            scanResult = this.mapper.readValue(trivyOutputStream, SarifSchema210.class);
        } catch (IOException e) {
            throw new TrivyRunnerException("Error while parsing Trivy scan result", e);
        }

        return scanResult.getRuns();
    }
}
