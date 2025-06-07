package com.github.prskr.sonartrivyscannerplugin.sensors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class TrivyScannerTest {

    @Test
    void testParseScanResults() throws IOException {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        var scanResults = mapper.readValue(getClass().getResourceAsStream("/scan_result_sarif.json"), SarifSchema210.class);

        assertFalse(scanResults.getRuns().isEmpty());
    }
}
