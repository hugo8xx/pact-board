-- Project context: knowledge every agent of a project reads (decisions, conventions, links).
-- One row per note; every write is also kept in context_note_versions.
CREATE TABLE context_notes (
  project_id   text NOT NULL REFERENCES projects(id),
  key          text NOT NULL CHECK (key ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
  title        text NOT NULL,
  body         text NOT NULL,
  pinned       boolean NOT NULL DEFAULT false,
  version      integer NOT NULL,
  updated_by   text NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  archived_at  timestamptz,
  PRIMARY KEY (project_id, key)
);

CREATE TABLE context_note_versions (
  id          bigserial PRIMARY KEY,
  project_id  text NOT NULL,
  key         text NOT NULL,
  version     integer NOT NULL,
  title       text NOT NULL,
  body        text,
  archived    boolean NOT NULL DEFAULT false,
  updated_by  text NOT NULL,
  at          timestamptz NOT NULL DEFAULT now(),
  erased_at   timestamptz,
  UNIQUE (project_id, key, version),
  FOREIGN KEY (project_id, key) REFERENCES context_notes (project_id, key)
);
