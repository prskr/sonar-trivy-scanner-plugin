package com.github.prskr.sonartrivyscannerplugin.trivy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.Nullable;
import org.apache.commons.lang3.SystemUtils;
import org.sonar.api.scanner.ScannerSide;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

@ScannerSide
public class TrivyScannerFetcher {

    private static final String TRIVY_BINARY_BASE_NAME = "trivy";
    private static final String TRIVY_BINARY_DIR_NAME = "trivy";
    private static final OSType osType = OSTypeProvider.getOSType();

    private static final Map<OSType, Map<String, String>> TRIVY_DOWNLOAD_URLS = Map.of(
            OSType.MacOS, Map.of(
                    "aarch64", "https://get.trivy.dev/trivy?type=tar.gz&version=%s&os=macos&arch=arm64",
                    "amd64", "https://get.trivy.dev/trivy?type=tar.gz&version=%s&os=macos&arch=amd64"
            ),
            OSType.Linux, Map.of(
                    "amd64", "https://get.trivy.dev/trivy?type=tar.gz&version=%s&os=linux&arch=amd64",
                    "aarch64", "https://get.trivy.dev/trivy?type=tar.gz&version=%s&os=linux&arch=arm64"
            ),
            OSType.Windows, Map.of(
                    "amd64", "https://get.trivy.dev/trivy?type=zip&version=%s&os=windows&arch=amd64"
            )
    );

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    public TrivyScannerFetcher() {
        objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule());

        httpClient = HttpClient
                .newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public TrivyScannerFetcher(ObjectMapper objectMapper, HttpClient httpClient) {
        this.objectMapper = objectMapper;
        this.httpClient = httpClient;
    }

    /**
     * Downloads the Trivy scanner binary for the specified version.
     * If the version is null or empty and the binary is not found in the system PATH,
     * it fetches the latest version from GitHub.
     *
     * @param version The version of Trivy to download, or null to either use the system installed one or fetch the latest one.
     * @return The path to the resolved Trivy scanner binary.
     * @throws URISyntaxException If the URI is malformed.
     * @throws IOException If an I/O error occurs during download.
     * @throws InterruptedException If the download process is interrupted.
     */
    public final String trivyScannerBinaryPath(@Nullable String version) throws URISyntaxException, IOException, InterruptedException {
        if (version == null || version.isEmpty()) {

            var binaryName = osType.systemDependentBinaryName(TRIVY_BINARY_BASE_NAME);
            var existingBinary = lookPath(binaryName);
            if (existingBinary != null) {
                return existingBinary;
            }
        }
        version = ensureTrivyVersion(version);

        var outPath = Files.createDirectories(Path.of(SystemUtils.JAVA_IO_TMPDIR, TRIVY_BINARY_DIR_NAME, version));
        var executablePath = outPath.resolve(osType.systemDependentBinaryName(TRIVY_BINARY_BASE_NAME));

        if (Files.exists(executablePath)) {
            return executablePath.toString();
        }

        var request = HttpRequest.newBuilder()
                .uri(new URI(String.format(determineTrivyDownloadUrl(osType, SystemUtils.OS_ARCH, version))))
                .GET()
                .build();

        var downloadFile = File.createTempFile(TRIVY_BINARY_BASE_NAME, osType.getArchiveExtension());

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofFile(downloadFile.toPath()));

        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch latest version: " + response.statusCode());
        }



        try(var inputStream = new BufferedInputStream(Files.newInputStream(response.body()))) {
            osType.Decompressor().DecompressTo(inputStream, outPath);
        }

        executablePath.toFile().setExecutable(true);

        return executablePath.toString();
    }

    public final String determineTrivyDownloadUrl(OSType osType, String osArch, String version)  {
        version = ensureTrivyVersion(version);

        var downloadURI = TRIVY_DOWNLOAD_URLS
                .getOrDefault(osType, Map.of())
                .getOrDefault(osArch, null);

        if(downloadURI == null) {
            throw new IllegalArgumentException("Unsupported OS or architecture: " + osType + ", " + SystemUtils.OS_ARCH);
        }

        return String.format(downloadURI, version);
    }

    private static @Nullable String lookPath(String binaryName) {
        String pathEnv = System.getenv("PATH");
        if (pathEnv == null || pathEnv.isBlank()) return null;

        String[] paths = pathEnv.split(File.pathSeparator);
        for (String path : paths) {
            if (path.isBlank()) continue;
            File file = new File(path, binaryName.trim());
            if (file.exists() && file.isFile() && file.canExecute()) {
                return file.getAbsolutePath();
            }
        }
        return null;
    }

    private  String ensureTrivyVersion(@Nullable String version) {
        if (version == null || version.isEmpty()) {
            try {
                version = getLatestVersion().tagName();
            } catch (IOException | InterruptedException | URISyntaxException e) {
                throw new RuntimeException("Failed to fetch the latest Trivy version", e);
            }
        }
        return version.startsWith("v") ? version.substring(1) : version; // Remove leading 'v' if present
    }

    private GitHubRelease getLatestVersion() throws URISyntaxException, IOException, InterruptedException {
        var request = HttpRequest.newBuilder()
                .uri(new URI("https://api.github.com/repos/aquasecurity/trivy/releases/latest"))
                .timeout(Duration.from(Duration.ofMillis(500)))
                .GET()
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch latest version: " + response.statusCode());
        }

        return objectMapper.readValue(response.body(), GitHubRelease.class);
    }
}
