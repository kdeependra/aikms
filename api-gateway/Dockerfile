FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY build.gradle .
COPY api-gateway api-gateway

RUN chmod +x gradlew && ./gradlew :api-gateway:bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S aikms && adduser -S aikms -G aikms
USER aikms
WORKDIR /app

COPY --from=build /workspace/api-gateway/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
