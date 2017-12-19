# About
Oauth2 is a skeleton of flask WEB APP, which supports OpenID connect.

# Configuration
Copy config.example to config.json and replace ```client_id```, ```client_secret```
and ```discovery_url``` with your values.

## Dynamic registration
If your open ID provider supports dynamic registration use following simplified configuration:
```json
{
  "app_name": "jz-oauth2",
  "base_url": "http://localhost:5000",
  "dynamic_registration": true,
  "discovery_url": "https://mojeid.cz/.well-known/openid-configuration/"
}
```
