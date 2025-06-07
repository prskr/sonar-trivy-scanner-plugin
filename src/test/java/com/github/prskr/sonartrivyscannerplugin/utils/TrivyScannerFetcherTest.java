package com.github.prskr.sonartrivyscannerplugin.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.prskr.sonartrivyscannerplugin.trivy.OSType;
import com.github.prskr.sonartrivyscannerplugin.trivy.TrivyScannerFetcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TrivyScannerFetcherTest {

    private ObjectMapper objectMapper;
    private HttpClient httpClient;
    private TrivyScannerFetcher fetcher;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        fetcher = new TrivyScannerFetcher(objectMapper, httpClient);
    }

    @Test
    @Disabled
    void testDownloadTrivyScanner() throws URISyntaxException, IOException, InterruptedException {
        var executablePath = fetcher.trivyScannerBinaryPath(null);
        assertTrue(executablePath.toFile().exists(), "The downloaded Trivy scanner executable does not exist.");
    }

    @ParameterizedTest
    @MethodSource("testDetermineTrivyDownloadUrlArgs")
    void testDetermineTrivyDownloadUrl(OSType osType, String osArch, String Version, String wantedUrl) {
        String url = fetcher.determineTrivyDownloadUrl(osType, osArch, Version);

        assertEquals(wantedUrl, url, "The determined URL does not match the expected URL.");
    }

    private static Stream<Arguments> testDetermineTrivyDownloadUrlArgs() {
        return Stream.of(
                Arguments.of(OSType.Linux, "amd64", "1.23", "https://get.trivy.dev/trivy?type=tar.gz&version=1.23&os=linux&arch=amd64"),
                Arguments.of(OSType.Linux, "aarch64", "1.23", "https://get.trivy.dev/trivy?type=tar.gz&version=1.23&os=linux&arch=arm64"),
                Arguments.of(OSType.Linux, "amd64", "v1.23", "https://get.trivy.dev/trivy?type=tar.gz&version=1.23&os=linux&arch=amd64"),
                Arguments.of(OSType.Linux, "aarch64", "v1.23", "https://get.trivy.dev/trivy?type=tar.gz&version=1.23&os=linux&arch=arm64")
        );
    }
}
