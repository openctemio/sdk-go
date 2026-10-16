### Security: shared mode and the sensor's identity scope must agree

- A sensor whose identity is enrolled with scope `instance` refuses to start
  unless shared mode is on, and shared mode refuses to start on an identity
  that belongs to an organization.
