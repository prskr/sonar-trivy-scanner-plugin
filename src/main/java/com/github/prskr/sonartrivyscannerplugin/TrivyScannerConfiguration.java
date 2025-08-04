package com.github.prskr.sonartrivyscannerplugin;

import com.github.prskr.sonartrivyscannerplugin.trivy.TrivyScannerTypes;
import com.github.prskr.sonartrivyscannerplugin.trivy.VulnerabilitySeveritySource;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.PropertyFieldDefinition;
import org.sonar.api.resources.Qualifiers;

import java.util.Arrays;
import java.util.List;

public class TrivyScannerConfiguration {
    private TrivyScannerConfiguration() {}

    private static final String SCANNER_CATEGORY = "Trivy Scanner";
    private static final String SERVER_CATEGORY = "Trivy Server";
    private static final String BINARY_CATEGORY = "Trivy Binary";
    private static final String SCAN_FLAGS_CATEGORY = "Trivy Scan";
    private static final String MISCONFIGURATION_FLAGS_CATEGORY = "Trivy Misconfiguration";
    private static final String VULNERABILITY_FLAGS_CATEGORY = "Trivy Vulnerabilities";

    // Binary configuration
    public static final String TRIVY_BINARY_VERSION = "sonar.trivy.binaryVersion";
    // Server configuration
    public static final String TRIVY_SERVER_URL = "sonar.trivy.serverUrl";
    // Scan flags
    public static final String TRIVY_FLAGS_SCAN_SCANNERS = "sonar.trivy.scan.scanners";
    public static final String TRIVY_FLAGS_SCAN_PARALLELISM = "sonar.trivy.scan.parallelism";
    public static final String TRIVY_FLAGS_SCAN_DISABLE_TELEMETRY = "sonar.trivy.scan.disableTelemetry";
    // Vulnerability flags
    public static final String TRIVY_FLAGS_VULN_IGNORE_UNFIXED = "sonar.trivy.vuln.ignoreUnfixed";
    public static final String TRIVY_FLAGS_VULN_SEVERITY_SOURCE = "sonar.trivy.vuln.severitySource";
    // Misconfiguration flags
    public static final String TRIVY_FLAGS_MISC_HELM_API_VERSIONS = "sonar.trivy.misc.helmApiVersions";
    public static final String TRIVY_FLAGS_MISC_HELM_KUBE_VERSION = "sonar.trivy.misc.helmKubeVersion";
    public static final String TRIVY_FLAGS_MISC_HELM_INLINE_VALUES = "sonar.trivy.misc.helmInlineValues";
    public static final String TRIVY_FLAGS_MISC_HELM_VALUES_FILE = "sonar.trivy.flags.misc.helmValuesFile";

    public static List<PropertyDefinition> getPropertyDefinitions() {
        return Arrays.asList(
                // Binary configuration
                PropertyDefinition.builder(TRIVY_BINARY_VERSION)
                        .category(SCANNER_CATEGORY)
                        .subCategory(BINARY_CATEGORY)
                        .name("Trivy Version")
                        .description("Trivy version to use for scanning. If not set, will check for an existing trivy binary and use that one, if no binary present, it will download the latest version.")
                        .defaultValue(TrivyScannerConstants.TRIVY_VERSION_LATEST)
                        .build(),
                // Server configuration
                PropertyDefinition.builder(TRIVY_SERVER_URL)
                        .category(SCANNER_CATEGORY)
                        .subCategory(SERVER_CATEGORY)
                        .name("Trivy Server URL")
                        .description("URL of the Trivy server to use for scanning. If not set, will download DB and run Trivy in local mode.")
                        .defaultValue("")
                        .build(),
                // Scan flags
                PropertyDefinition.builder(TRIVY_FLAGS_SCAN_SCANNERS)
                        .category(SCANNER_CATEGORY)
                        .subCategory(SCAN_FLAGS_CATEGORY)
                        .name("Scanners to use")
                        .description("Configure what to detect")
                        .type(PropertyType.SINGLE_SELECT_LIST)
                        .options(Arrays.stream(TrivyScannerTypes.values()).map(TrivyScannerTypes::getName).toList())
                        .defaultValue("vuln,secret")
                        .multiValues(true)
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_SCAN_PARALLELISM)
                        .category(SCANNER_CATEGORY)
                        .subCategory(SCAN_FLAGS_CATEGORY)
                        .name("Parallelism")
                        .description("Number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism")
                        .type(PropertyType.INTEGER)
                        .defaultValue("5")
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_SCAN_DISABLE_TELEMETRY)
                        .category(SCANNER_CATEGORY)
                        .subCategory(SCAN_FLAGS_CATEGORY)
                        .name("Disable Telemetry")
                        .description("Disable Trivy telemetry. This is recommended for production use.")
                        .type(PropertyType.BOOLEAN)
                        .defaultValue("true")
                        .build(),
                // Vulnerability flags
                PropertyDefinition.builder(TRIVY_FLAGS_VULN_IGNORE_UNFIXED)
                        .category(SCANNER_CATEGORY)
                        .subCategory(VULNERABILITY_FLAGS_CATEGORY)
                        .name("Ignore Unfixed Vulnerabilities")
                        .description("Ignore vulnerabilities that are not fixed in the latest version of the package")
                        .type(PropertyType.BOOLEAN)
                        .defaultValue("false")
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_VULN_SEVERITY_SOURCE)
                        .category(SCANNER_CATEGORY)
                        .subCategory(VULNERABILITY_FLAGS_CATEGORY)
                        .name("Vulnerability Severity Source")
                        .description("Order of data sources for selecting vulnerability severity level")
                        .type(PropertyType.SINGLE_SELECT_LIST)
                        .options(Arrays.stream(VulnerabilitySeveritySource.values()).map(VulnerabilitySeveritySource::getSourceName).toList())
                        .defaultValue(VulnerabilitySeveritySource.Auto.getSourceName())
                        .multiValues(true)
                        .build(),

                // Misconfiguration flags
                PropertyDefinition.builder(TRIVY_FLAGS_MISC_HELM_API_VERSIONS)
                        .category(SCANNER_CATEGORY)
                        .subCategory(MISCONFIGURATION_FLAGS_CATEGORY)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
                        .name("Helm API Versions")
                        .description("Available API versions used for Capabilities.APIVersions. This flag is the same as the api-versions flag of the helm template command. (can specify multiple or separate values with commas: policy/v1/PodDisruptionBudget,apps/v1/Deployment)")
                        .defaultValue("")
                        .multiValues(true)
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_MISC_HELM_KUBE_VERSION)
                        .category(SCANNER_CATEGORY)
                        .subCategory(MISCONFIGURATION_FLAGS_CATEGORY)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
                        .name("Helm Kube Version")
                        .description("Kubernetes version used for Capabilities.KubeVersion. This flag is the same as the kube-version flag of the helm template command.")
                        .defaultValue("")
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_MISC_HELM_INLINE_VALUES)
                        .category(SCANNER_CATEGORY)
                        .subCategory(MISCONFIGURATION_FLAGS_CATEGORY)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
                        .name("Helm Inline Values")
                        .description("specify Helm values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
                        .defaultValue("")
                        .multiValues(true)
                        .build(),
                PropertyDefinition.builder(TRIVY_FLAGS_MISC_HELM_VALUES_FILE)
                        .category(SCANNER_CATEGORY)
                        .subCategory(MISCONFIGURATION_FLAGS_CATEGORY)
                        .onlyOnQualifiers(Qualifiers.PROJECT)
                        .name("Specify Helm Values File")
                        .description("specify paths to override the Helm values.yaml files")
                        .defaultValue("")
                        .multiValues(true)
                        .build()
        );
    }
}
