FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY build.gradle .
COPY hsm-simulator hsm-simulator

RUN chmod +x gradlew && ./gradlew :hsm-simulator:bootJar -x test --no-daemon

FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S aikms && adduser -S aikms -G aikms
USER aikms
WORKDIR /app

COPY --from=build /workspace/hsm-simulator/build/libs/*.jar app.jar

EXPOSE 8090
ENTRYPOINT ["java", "-jar", "app.jar"]
