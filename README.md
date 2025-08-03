# relaxed-validation-signed-jwt-keycloak-auth-provider

Custom [Keycloak Authentication Provider](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) to relax the validation performed against Signed JWT Clients.

## Usage

Utilize the following steps to build, deploy and configure the provider within an instance of Keycloak/Red Hat Build of Keycloak.

### Build

Build the project using Maven

```shell
mvn clean install
```

### Deploy

Deploy the provider within an instance of Keycloak/Red Hat Build of Keycloak by copying the previously built JAR file to the `providers` directory within the Keycloak instance. In both the Keycloak and Red Hat Build of Keycloak images, this is located in the `/opt/keycloak/providers` directory.

### Configuration

Once the provider has been added to Keycloak, it must be enabled at a Realm and client level.

#### Realm Configuration

Settings must be applied at a Realm level in order to configure how client authentication is performed.

Configure an _Authentication Flow_ which leverages the provider 

1. Login to Keycloak
2. Select the desired _Realm_
3. Select **Authentication** on the left hand navigation bar
4. Duplicate the configuration of the _clients_ flow by selecting the "kabob" on the right side next to _clients_ and the select **duplicate**
5. Click **Add Execution**
6. Select **Relaxed Validation Signed Jwt** and click **Add**
7. Under the _Requirement_ column, select **Alternate** from the dropdown
8. Enable the flow by selecting the _Action_ dropdown and select **Bind flow**.
9. Select **Client authentication flow** and click **Save**

On the _flows_ page, confirm that the newly created flow is in use by the _Client authentication flow_.

_Note:_ You can customize the the list of executions that are associated to this flow. 

#### Client Configuration

Within each _client_ that wants to use the functionality provided by the provider, configure the following.

_Note:_ When creating the client, the _Client Authentication_ option must be enabled on the _Capability config_ page

1. Login to Keycloak
2. Select the desired _Realm_
3. Select the desired _Client_
4. On the _Credentials_ tab, select **Relaxed Validation Signed Jwt** from _Client Authenticator field.
5. Select the **Save** button
6. Set the _JWKS URL_ by selecting the _Keys_, toggle the **Use JWKS URL** option and enter the location of the JWKS Keys.
7. Select the **Save** button

### Testing

There are several methods that can be used to verify the provider and the Keycloak instance has been configured. 

#### Client Credentials Grant

To perform this verification, the **Direct access grants** checkbox must be enabled on the _Authentication flow_ option within the _Capability config_ section on the Client _Settings_ page.

Perform the following request

```shell
curl -L -X POST "https://<KEYCLOAK_URL>/realms/<YOUR_REALM>/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=<YOUR_SIGNED_JWT>"
```

#### Password Grant

To perform this verification, the **Direct access grants** checkbox must be enabled on the _Authentication flow_ option within the _Capability config_ section on the Client _Settings_ page.

Perform the following request

```shell
curl -L -X POST "https://<KEYCLOAK_URL>/realms/<YOUR_REALM>/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=<USERNAME>" \
  --data-urlencode "password=<PASSWORD>" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=<YOUR_SIGNED_JWT>"
```
