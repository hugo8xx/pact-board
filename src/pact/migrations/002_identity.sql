-- How a signed-in person maps to a human on the board. Any OAuth server can sign people in;
-- the board matches its verified email once and then remembers its `sub`.
ALTER TABLE humans ADD COLUMN email text;
ALTER TABLE humans ADD COLUMN auth_issuer text;
ALTER TABLE humans ADD COLUMN auth_sub text;
CREATE UNIQUE INDEX humans_email_idx ON humans (lower(email));
CREATE UNIQUE INDEX humans_auth_idx ON humans (auth_issuer, auth_sub);
