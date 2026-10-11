### Security: bearer-key sensors move to a key-bound identity by themselves

- A daemon started with an API key, against a platform whose hello lists `key_bind`, makes its own Ed25519 key in `<state dir>/identity/` (0600 in 0700), binds it with one call authenticated by the API key (`Client.BindKey`, `POST /api/v2/sensor/identity/bind`, with a proof of possession) and signs every request from then on. The platform retires the API key in the same step (one way); the sensor keeps its id, tenant and grant.
- An identity in the state directory now wins over a configured `API_KEY` (the sensor warns to remove it).
- The key and a marker are written before the call; if the answer is lost, the next start binds the same key again or confirms it with a request signed by that key.
- A refusal (the organization requires an administrator's approval, or the sensor cannot bind) removes the generated key; the sensor keeps its API key and says to re-pair it.
- `SENSOR_KEY_BIND=off` keeps the API key. A bearer-key sensor now sends one extra hello at start.
