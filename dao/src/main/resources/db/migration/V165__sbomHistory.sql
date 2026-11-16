-- Keep the history of the SBOMs uploaded for repositories of type SBOM, and the SBOM that each run of such a
-- repository analyzed. The contents of the SBOMs are kept in the "sbomStorage", addressed by their SHA-256 checksum.

CREATE TABLE repository_sboms
(
    id              bigserial PRIMARY KEY,
    repository_id   bigint    NOT NULL REFERENCES repositories ON DELETE CASCADE,
    sha256          text      NOT NULL,
    file_name       text      NOT NULL,
    format          text      NOT NULL,
    spec_version    text      NOT NULL,
    size            bigint    NOT NULL,
    component_count integer   NOT NULL,
    root_components jsonb     NOT NULL,
    warnings        jsonb     NOT NULL,
    uploaded_at     timestamp NOT NULL,
    uploaded_by     text      NULL,
    is_current      boolean   NOT NULL DEFAULT FALSE
);

CREATE INDEX repository_sboms_repository_id ON repository_sboms (repository_id);

-- A repository has at most one current SBOM, the one that its runs analyze.
CREATE UNIQUE INDEX repository_sboms_current ON repository_sboms (repository_id) WHERE is_current;

CREATE TABLE ort_run_sboms
(
    ort_run_id         bigint    PRIMARY KEY REFERENCES ort_runs ON DELETE CASCADE,
    repository_sbom_id bigint    NULL REFERENCES repository_sboms ON DELETE SET NULL,
    sha256             text      NOT NULL,
    file_name          text      NOT NULL,
    format             text      NOT NULL,
    spec_version       text      NOT NULL,
    size               bigint    NOT NULL,
    component_count    integer   NOT NULL,
    source_url         text      NULL,
    analyzed_at        timestamp NOT NULL
);
