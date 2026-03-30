# Multi-stage Dockerfile for kms-service
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY build.gradle .
COPY common common
COPY kms-service kms-service

RUN chmod +x gradlew && ./gradlew :kms-service:bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S aikms && adduser -S aikms -G aikms
USER aikms
WORKDIR /app

COPY --from=build /workspace/kms-service/build/libs/*.jar app.jar

EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
