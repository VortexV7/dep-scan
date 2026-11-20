// Sample Jenkins pipeline: scan with DepScan (Stage 3). Copy into your repo root.
// DepScan auto-detects JENKINS_URL and switches to plain logs.
pipeline {
    agent any
    tools {
        jdk 'jdk17'
    }
    stages {
        stage('Download DepScan') {
            steps {
                sh 'curl -sL -o dep-scan.jar "https://github.com/VortexV7/dep-scan/releases/download/v0.5.0/dep-scan-0.5.0.jar"'
            }
        }
        stage('Scan') {
            steps {
                // Exit code 1 fails the build only when --fail-on is breached.
                sh 'java -jar dep-scan.jar scan . --format sarif --fail-on critical --out depscan.sarif'
                sh 'java -jar dep-scan.jar report . --format html --out depscan-report.html'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'depscan.sarif, depscan-report.html', allowEmptyArchive: true
            // If the Warnings Next Generation plugin is installed, it can
            // parse depscan.sarif as a SARIF report.
        }
    }
}
