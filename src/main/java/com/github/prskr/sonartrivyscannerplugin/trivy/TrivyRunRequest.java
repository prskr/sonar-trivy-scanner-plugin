package com.github.prskr.sonartrivyscannerplugin.trivy;

import jakarta.annotation.Nullable;

import java.io.File;

public record TrivyRunRequest(
        File targetDirectory,
        File outputDirectory,
        @Nullable String trivyVersion)
{ }
