
FROM openjdk:17-slim AS builder


RUN apt-get update && \
    apt-get install -y findutils git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY gradlew .
COPY gradle gradle/

COPY build.gradle settings.gradle ./

RUN chmod +x gradlew

RUN ./gradlew dependencies --no-daemon

COPY src ./src

RUN ./gradlew clean build -x test --no-daemon


FROM openjdk:17-slim

RUN addgroup --system --gid 1000 spring && adduser --system --uid 1000 --ingroup spring spring
USER spring

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar


EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]