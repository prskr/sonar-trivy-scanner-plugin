package com.github.prskr.sonartrivyscannerplugin.trivy;

import org.sonar.api.config.Configuration;

import java.util.Optional;
import java.util.Set;

import static com.github.prskr.sonartrivyscannerplugin.TrivyScannerConfiguration.*;

public abstract class FlagsProcessor {
    private FlagsProcessor() {
    }

    private static final Set<CommandFlag> TRIVY_FLAGS = Set.of(
            // Server configuration
            new StringFlag(TRIVY_SERVER_URL, "server"),
            // Scan flags
            new MutliValueFlag(TRIVY_FLAGS_SCAN_SCANNERS, "scanners"),
            new IntegerFlag(TRIVY_FLAGS_SCAN_PARALLELISM, "parallel"),
            new BooleanFlag(TRIVY_FLAGS_SCAN_DISABLE_TELEMETRY, "disable-telemetry"),
            // Vulnerability flags
            new BooleanFlag(TRIVY_FLAGS_VULN_IGNORE_UNFIXED, "ignore-unfixed"),
            new MutliValueFlag(TRIVY_FLAGS_VULN_SEVERITY_SOURCE, "vuln-severity-source"),
            // Misconfiguration flags
            new StringFlag(TRIVY_FLAGS_MISC_HELM_KUBE_VERSION, "helm-kube-version"),
            new MutliValueFlag(TRIVY_FLAGS_MISC_HELM_API_VERSIONS, "helm-api-versions"),
            new MutliValueFlag(TRIVY_FLAGS_MISC_HELM_INLINE_VALUES, "helm-set"),
            new MutliValueFlag(TRIVY_FLAGS_MISC_HELM_VALUES_FILE, "helm-values")
    );

    public static CommandBuilder processFlags(CommandBuilder commandBuilder, Configuration configuration) {
        var flags = TRIVY_FLAGS
                .stream()
                .flatMap(f -> f.toArgument(configuration).stream())
                .toList();

        return commandBuilder.withArguments(flags);
    }

    private interface CommandFlag {
        Optional<CommandBuilder.CommandArgument> toArgument(Configuration configuration);
    }

    private record StringFlag(String configKey, String flagKey) implements CommandFlag {

        @Override
        public Optional<CommandBuilder.CommandArgument> toArgument(Configuration configuration) {
            return configuration.get(this.configKey).map(value -> new CommandBuilder.Flag(this.flagKey, value));
        }
    }

    private record IntegerFlag(String configKey, String flagKey) implements CommandFlag {

        @Override
        public Optional<CommandBuilder.CommandArgument> toArgument(Configuration configuration) {
            return configuration.getInt(this.configKey)
                    .map(value -> new CommandBuilder.Flag(this.flagKey, String.valueOf(value)));
        }
    }

    private record BooleanFlag(String configKey, String flagKey) implements CommandFlag {

        @Override
        public Optional<CommandBuilder.CommandArgument> toArgument(Configuration configuration) {
            return configuration.getBoolean(this.configKey)
                    .filter(value -> value)
                    .map(value -> new CommandBuilder.NoValueFlag(this.flagKey));
        }
    }

    private record MutliValueFlag(String configKey, String flagKey) implements CommandFlag {

        @Override
        public Optional<CommandBuilder.CommandArgument> toArgument(Configuration configuration) {
            if (!configuration.hasKey(this.configKey)) {
                return Optional.empty();
            }

            var values = configuration.getStringArray(this.configKey);
            if (values.length == 0) {
                return Optional.empty();
            }

            return Optional.of(new CommandBuilder.Flag(this.flagKey, String.join(",", values)));
        }
    }
}
