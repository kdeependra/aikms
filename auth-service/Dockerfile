FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY build.gradle .
COPY common common
COPY auth-service auth-service

RUN chmod +x gradlew && ./gradlew :auth-service:bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S aikms && adduser -S aikms -G aikms
USER aikms
WORKDIR /app

COPY --from=build /workspace/auth-service/build/libs/*.jar app.jar

EXPOSE 8082
ENTRYPOINT ["java", "-jar", "app.jar"]
