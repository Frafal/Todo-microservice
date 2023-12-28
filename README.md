docker pull keycloak/keycloak:17.0.0
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=password keycloak/keycloak:17.0.0  start-dev


curl --location 'http://localhost:9090/realms/MyAppRealm/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=<YOUR_USER_NAME>' \
--data-urlencode 'password=<YOUR_USER_PASSWORD>' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_id=My-Awesome-App' \
--data-urlencode 'client_secret=<KEYCLOAK_CLIENT_SECRET>' \
--data-urlencode 'scope=openid'



curl \
-d "client_id=login-app" \
-d "username=user1" \
-d "password=password" \
-d "grant_type=password" \
"http://localhost:9090/realms/SpringBootKeycloak/protocol/openid-connect/token"