# Debian/Ubuntu 계열 JRE (amd64/arm64 모두 제공)
FROM eclipse-temurin:17-jre-jammy

# spring 사용자/그룹 생성 (Debian 표준 명령)
RUN groupadd -r spring \
 && useradd -r -g spring -d /home/spring -s /usr/sbin/nologin spring \
 && mkdir -p /app /home/spring

WORKDIR /app

# 빌드 산출물 복사 (권한도 함께 설정)
ARG JAR_FILE=build/libs/*.jar
COPY --chown=spring:spring ${JAR_FILE} /app/app.jar

# 비루트 실행
USER spring

EXPOSE 8080
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]