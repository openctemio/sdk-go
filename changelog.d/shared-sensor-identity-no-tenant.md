### Fixed: a shared sensor's signed jobs are verified without a tenant id

- A shared sensor belongs to no organization, so its identity has no tenant id.
  Signed-job verification now requires the sensor id only in shared mode (the
  signed statement names the organization); an organization sensor without a
  tenant id is still refused at start.
