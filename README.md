# sonar-trivy-scanner-plugin

[![Maven](https://github.com/prskr/sonar-trivy-scanner-plugin/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/prskr/sonar-trivy-scanner-plugin/actions/workflows/maven.yml)

A SonarQube plugin that integrates [Trivy](https://trivy.dev/) security scanner to detect vulnerabilities in your code during SonarQube analysis.

This is currently a work in progress.
The goal is to create a SonarQube plugin that integrates with Trivy to scan for vulnerabilities in your codebase.
It purposely does not rely on some previous trivy run and instead runs trivy as part of the analysis to ensure that the step cannot be skipped.

## Overview

This plugin enables SonarQube to leverage Trivy's powerful vulnerability scanning capabilities, providing comprehensive security analysis for your projects.
The plugin handles cross-platform compatibility and automatically manages Trivy binary deployment across different operating systems if desired or no existing installation could be found.

## Features

- **Cross-Platform Support**: Automatically detects and handles Windows, macOS, and Linux environments
- **Automatic Binary Management**: Downloads and extracts the appropriate Trivy binary for your platform
- **Seamless Integration**: Works as a standard SonarQube plugin with minimal configuration

## Installation

### Prerequisites
 
- SonarQube Server (compatible version)
- Java 17 or higher

### From Release

1. Download the latest plugin JAR from the [releases page](../../releases)
2. Copy the JAR file to your SonarQube's `extensions/plugins/` directory
3. Restart SonarQube server


### Building from Source

``` bash
# Clone the repository
git clone https://github.com/prskr/sonar-trivy-scanner-plugin.git
cd sonar-trivy-scanner-plugin

# Build the plugin
./mvnw clean package

# Copy the generated JAR to SonarQube plugins directory
cp target/sonar-trivy-scanner-plugin-*.jar $SONARQUBE_HOME/extensions/plugins/
```

## Configuration

The plugin automatically detects your operating system and configures itself accordingly.
No manual configuration is required for basic usage.

### Advanced Configuration

Additional configuration options may be available through SonarQube's administration interface under the Trivy Scanner section *(coming soon)*.

## Usage

Once installed, the plugin will automatically run Trivy scans during your SonarQube analysis.
The security vulnerabilities detected by Trivy will appear as issues in your SonarQube project dashboard.

## Development

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## Support

- **Issues**: Report bugs and request features via [GitHub Issues](../../issues)
- **Documentation**: Check the [SonarQube Plugin Documentation](https://docs.sonarqube.org/latest/extend/developing-plugin/)
- **Trivy Documentation**: Visit [Trivy's official documentation](https://trivy.dev/)

**Note**: This plugin requires network access to download Trivy binaries on first use (if not already present on system and available in the `$PATH`).
Ensure the machine where you're running the SonarScanner has appropriate internet connectivity or configure proxy settings if needed.
