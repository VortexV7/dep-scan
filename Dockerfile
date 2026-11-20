# DepScan Docker image (Stage 3). Multi-stage: build the fat jar, then run it
# on a slim JRE. Usage:
#   docker build -t dep-scan:0.5.0 .
#   docker run --rm -v "$PWD:/work" -w /work dep-scan:0.5.0 scan . --fail-on critical
#   docker run --rm -v "$PWD:/work" -w /work dep-scan:0.5.0 report . --format pdf --out depscan-report.pdf
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /work
COPY --from=build /src/target/dep-scan-*.jar /opt/dep-scan/dep-scan.jar
ENTRYPOINT ["java", "-jar", "/opt/dep-scan/dep-scan.jar"]
CMD ["scan", "--help"]
