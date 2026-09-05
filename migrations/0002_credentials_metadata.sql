-- Non-secret, provider-specific extras that don't fit the fixed columns --
-- currently just the Atlas project (group) id: the friend's Service
-- Account is granted access to a specific project they already created,
-- and provisioning needs to know which one.
ALTER TABLE credentials ADD COLUMN metadata TEXT;
