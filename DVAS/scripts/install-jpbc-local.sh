#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JPBC_VERSION="2.0.0"

API_JAR="${PROJECT_ROOT}/libs/jpbc-api-${JPBC_VERSION}.jar"
PLAF_JAR="${PROJECT_ROOT}/libs/jpbc-plaf-${JPBC_VERSION}.jar"

for jar_file in "${API_JAR}" "${PLAF_JAR}"; do
    if [[ ! -f "${jar_file}" ]]; then
        echo "Missing required JPBC JAR: ${jar_file}" >&2
        exit 1
    fi
done

mvn -N \
    org.apache.maven.plugins:maven-install-plugin:3.1.3:install-file \
    -Dfile="${API_JAR}" \
    -DgroupId=it.unisa.dia.gas \
    -DartifactId=jpbc-api \
    -Dversion="${JPBC_VERSION}" \
    -Dpackaging=jar \
    -DgeneratePom=true

mvn -N \
    org.apache.maven.plugins:maven-install-plugin:3.1.3:install-file \
    -Dfile="${PLAF_JAR}" \
    -DgroupId=it.unisa.dia.gas \
    -DartifactId=jpbc-plaf \
    -Dversion="${JPBC_VERSION}" \
    -Dpackaging=jar \
    -DgeneratePom=true

echo "JPBC ${JPBC_VERSION} installed successfully."
