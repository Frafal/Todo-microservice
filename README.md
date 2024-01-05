# Todo Microservice
Java 17, springboot3

## Run docker first:

docker run --name keycloak-ms -p 9090:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -e KC_LOG_LEVEL=DEBUG quay.io/keycloak/keycloak:21.1.0 start-dev

create realm: SpringBootKeycloak

add client:  login-app

add role: user

set role to User




#### retrive token from keycloak curl

curl \
-d "client_id=login-app" \
-d "username=user1" \
-d "password=password" \
-d "grant_type=password" \
"http://localhost:9090/realms/SpringBootKeycloak/protocol/openid-connect/token"