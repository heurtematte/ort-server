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

import { AxiosError } from 'axios';

import type { PutRepositorySbomData, RepositorySbom } from '@/api';
import { getRepositorySbomContent, putRepositorySbom } from '@/api/sdk.gen';

/**
 * The file types offered when choosing an SBOM to upload. ORT Server detects the format from the
 * content, so this only preselects the usual file names in the file dialog.
 */
export const SBOM_FILE_ACCEPT = [
  '.json',
  '.xml',
  '.yaml',
  '.yml',
  '.spdx',
  '.jsonld',
  'application/json',
  'application/xml',
  'text/xml',
  'text/plain',
].join(',');

/**
 * Upload the given [file] as the SBOM of the repository with the given ID, replacing an existing
 * one, and return the information about the stored SBOM. Errors are thrown as Axios errors, which
 * carry the message of ORT Server, for instance if the file is not a valid SBOM.
 */
export async function uploadRepositorySbom(
  repositoryId: number,
  file: File
): Promise<RepositorySbom> {
  const { data } = await putRepositorySbom({
    path: { repositoryId },
    query: { fileName: file.name },
    // The API documentation describes the binary body as an array of bytes. Send the file as it
    // is instead of serializing it as JSON; ORT Server detects its format from the content.
    body: file as unknown as PutRepositorySbomData['body'],
    bodySerializer: null,
    headers: { 'Content-Type': 'application/octet-stream' },
    throwOnError: true,
  });

  return data;
}

/** Download the SBOM uploaded for the repository with the given ID as a file. */
export async function fetchRepositorySbomContent(
  repositoryId: number
): Promise<Blob> {
  const { data } = await getRepositorySbomContent({
    path: { repositoryId },
    responseType: 'blob',
    throwOnError: true,
  });

  return data as Blob;
}

/** Return whether the given error means that no SBOM was uploaded for a repository. */
export function isSbomNotFound(error: unknown): boolean {
  return error instanceof AxiosError && error.response?.status === 404;
}

/** Let the browser save the given [blob] as a file with the given name. */
export function saveBlob(blob: Blob, fileName: string): void {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  window.URL.revokeObjectURL(url);
}
