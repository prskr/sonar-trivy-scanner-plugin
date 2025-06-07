package com.github.prskr.sonartrivyscannerplugin.utils.compression;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

public interface Decompressor {
    void DecompressTo(InputStream inputStream, Path outputDirectory) throws IOException;
}
