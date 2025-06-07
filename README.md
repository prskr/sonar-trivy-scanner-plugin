# sonar-trivy-scanner-plugin

This is currently a work in progress.
The goal is to create a SonarQube plugin that integrates with Trivy to scan for vulnerabilities in your codebase.
It purposely does not rely on some previous trivy run and instead runs trivy as part of the analysis to ensure that the step cannot be skipped.