# Builds the User Storage provider and bakes it into the Keycloak image.
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package

FROM quay.io/keycloak/keycloak:26.8.2
COPY --from=build /build/target/keycloak-user-service-spi.jar /opt/keycloak/providers/
