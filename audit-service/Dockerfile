FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY build.gradle .
COPY common common
COPY audit-service audit-service

RUN chmod +x gradlew && ./gradlew :audit-service:bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S aikms && adduser -S aikms -G aikms
USER aikms
WORKDIR /app

COPY --from=build /workspace/audit-service/build/libs/*.jar app.jar

EXPOSE 8083
ENTRYPOINT ["java", "-jar", "app.jar"]
