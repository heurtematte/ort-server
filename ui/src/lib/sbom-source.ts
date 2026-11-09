/*
 * Copyright (C) 2026 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

/** The kinds of sources of the SBOM of a repository of type SBOM. */
export type SbomSourceKind =
  | 'DEPENDENCY_TRACK_PROJECT'
  | 'SBOMIFY_COMPONENT'
  | 'SBOMIFY_PRODUCT'
  | 'DOCUMENT';

const UUID_PATTERN =
  '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';

const DEPENDENCY_TRACK_PROJECT = new RegExp(
  `^https?://[^?#]+?/projects/${UUID_PATTERN}/?(?:[?#].*)?$`
);

const SBOMIFY_PAGE =
  /^https?:\/\/[^?#]+?\/(?:public\/)?(component|product)\/[A-Za-z0-9_-]+\/?(?:[?#].*)?$/;

const sbomSourceLabels: Record<SbomSourceKind, string> = {
  DEPENDENCY_TRACK_PROJECT: 'Dependency-Track project',
  SBOMIFY_COMPONENT: 'sbomify component',
  SBOMIFY_PRODUCT: 'sbomify product',
  DOCUMENT: 'SBOM document',
};

/**
 * Return the kind of source that the URL of a repository of type SBOM refers to, as ORT Server
 * detects it, or undefined if it is not an HTTP(S) URL. ORT Server confirms the kind with the
 * server when the repository is created.
 */
export function detectSbomSource(url: string): SbomSourceKind | undefined {
  const trimmed = url.trim();
  if (!/^https?:\/\/[^/]+/.test(trimmed)) return undefined;
  if (DEPENDENCY_TRACK_PROJECT.test(trimmed)) return 'DEPENDENCY_TRACK_PROJECT';

  const sbomify = SBOMIFY_PAGE.exec(trimmed);
  if (sbomify) {
    return sbomify[1] === 'product' ? 'SBOMIFY_PRODUCT' : 'SBOMIFY_COMPONENT';
  }

  return 'DOCUMENT';
}

/** Return the label of the given kind of SBOM source. */
export function getSbomSourceLabel(kind: SbomSourceKind): string {
  return sbomSourceLabels[kind];
}

/** The meaning of the revision of a run of a repository of type SBOM. */
export const SBOM_REVISION_DESCRIPTION =
  "The version of the Dependency-Track project or sbomify component to analyze, or 'latest'. " +
  'Leave it empty to analyze the version of the repository URL. A revision cannot be used for ' +
  'SBOM documents.';
