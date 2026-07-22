# Expects the fat jar to already be built on the host (see README: `mvn install -DskipTests` from the
# repo root first) — this just packages it, rather than re-running the whole multi-module Maven reactor
# inside the image.
FROM eclipse-temurin:21-jre

WORKDIR /app
COPY target/oid4vp-demo-verifier.jar app.jar

EXPOSE 8090
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
