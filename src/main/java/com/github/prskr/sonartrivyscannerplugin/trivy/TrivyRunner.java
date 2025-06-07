package com.github.prskr.sonartrivyscannerplugin.trivy;

import java.util.List;

public interface TrivyRunner {
    List<Run> run(TrivyRunRequest request) throws TrivyRunnerException;
}
