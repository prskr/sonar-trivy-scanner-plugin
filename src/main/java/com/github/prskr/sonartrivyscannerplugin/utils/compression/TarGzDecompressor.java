package com.github.prskr.sonartrivyscannerplugin.utils.compression;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class TarGzDecompressor implements Decompressor{
    public TarGzDecompressor() {
    }

    @Override
    public void DecompressTo(InputStream inputStream, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);
        TarArchiveInputStream tarArchiveInputStream = new TarArchiveInputStream(new GzipCompressorInputStream(inputStream));

        for (TarArchiveEntry entry; (entry = tarArchiveInputStream.getNextEntry()) != null;) {
            Path extractTo = outputDirectory.resolve(entry.getName());
            if (entry.isDirectory()) {
                Files.createDirectories(extractTo);
            } else {
                Files.createDirectories(extractTo.getParent());
                Files.copy(tarArchiveInputStream, extractTo, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
