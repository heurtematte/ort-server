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

import { AxiosError, AxiosHeaders } from 'axios';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getRepositorySbomContent, putRepositorySbom } from '@/api/sdk.gen';
import { createRepositoryAndCredentials } from '@/lib/repository-credentials';
import {
  createRepositoryWithSbom,
  fetchRepositorySbomContent,
  isSbomNotFound,
  uploadRepositorySbom,
} from '@/lib/repository-sbom';

vi.mock('@/api/sdk.gen', () => ({
  getRepositorySbomContent: vi.fn(),
  putRepositorySbom: vi.fn(),
}));

vi.mock('@/lib/repository-credentials', () => ({
  createRepositoryAndCredentials: vi.fn(),
}));

const storedSbom = {
  componentCount: 2,
  fileName: 'bom.cdx.json',
  format: 'CycloneDX JSON',
  mediaType: 'application/vnd.cyclonedx+json',
  sha256: '0'.repeat(64),
  size: 42,
  specVersion: '1.6',
  uploadedAt: '2026-11-13T12:00:00Z',
};

const axiosError = (status: number) =>
  new AxiosError('Request failed', 'ERR_BAD_REQUEST', undefined, undefined, {
    status,
    statusText: '',
    headers: {},
    config: { headers: new AxiosHeaders() },
    data: {},
  });

describe('repository SBOM', () => {
  beforeEach(() => {
    vi.mocked(putRepositorySbom).mockReset();
    vi.mocked(getRepositorySbomContent).mockReset();
    vi.mocked(createRepositoryAndCredentials).mockReset();
  });

  it('uploads the file as the raw body with its name', async () => {
    vi.mocked(putRepositorySbom).mockResolvedValue({
      data: storedSbom,
    } as unknown as Awaited<ReturnType<typeof putRepositorySbom>>);
    const file = new File(['{"bomFormat":"CycloneDX"}'], 'bom.cdx.json');

    const result = await uploadRepositorySbom(7, file);

    expect(result).toEqual(storedSbom);
    expect(putRepositorySbom).toHaveBeenCalledWith({
      path: { repositoryId: 7 },
      query: { fileName: 'bom.cdx.json' },
      body: file,
      bodySerializer: null,
      headers: { 'Content-Type': 'application/octet-stream' },
      throwOnError: true,
    });
  });

  it('propagates the errors of ORT Server', async () => {
    const error = axiosError(400);
    vi.mocked(putRepositorySbom).mockRejectedValue(error);

    await expect(
      uploadRepositorySbom(7, new File(['not an SBOM'], 'notes.txt'))
    ).rejects.toBe(error);
  });

  it('downloads the content as a blob', async () => {
    const blob = new Blob(['{}']);
    vi.mocked(getRepositorySbomContent).mockResolvedValue({
      data: blob,
    } as unknown as Awaited<ReturnType<typeof getRepositorySbomContent>>);

    expect(await fetchRepositorySbomContent(7)).toBe(blob);
    expect(getRepositorySbomContent).toHaveBeenCalledWith({
      path: { repositoryId: 7 },
      responseType: 'blob',
      throwOnError: true,
    });
  });

  it('recognizes that no SBOM was uploaded', () => {
    expect(isSbomNotFound(axiosError(404))).toBe(true);
    expect(isSbomNotFound(axiosError(500))).toBe(false);
    expect(isSbomNotFound(new Error('Network Error'))).toBe(false);
    expect(isSbomNotFound(undefined)).toBe(false);
  });

  describe('createRepositoryWithSbom', () => {
    const repository = {
      id: 7,
      organizationId: 1,
      productId: 2,
      type: 'SBOM' as const,
      url: 'upload:bom.cdx.json',
    };
    const values = {
      description: '',
      name: '',
      type: 'SBOM' as const,
      url: 'upload:bom.cdx.json',
      username: '',
      password: '',
    };

    beforeEach(() => {
      vi.mocked(createRepositoryAndCredentials).mockResolvedValue({
        repository,
      });
    });

    it('only creates the repository without a file', async () => {
      expect(await createRepositoryWithSbom(2, values)).toEqual({
        repository,
      });
      expect(putRepositorySbom).not.toHaveBeenCalled();
    });

    it('uploads the file once the repository is created', async () => {
      vi.mocked(putRepositorySbom).mockResolvedValue({
        data: storedSbom,
      } as unknown as Awaited<ReturnType<typeof putRepositorySbom>>);
      const file = new File(['{}'], 'bom.cdx.json');

      expect(await createRepositoryWithSbom(2, values, file)).toEqual({
        repository,
        sbomUploaded: true,
      });
      expect(createRepositoryAndCredentials).toHaveBeenCalledWith({
        productId: 2,
        values,
      });
      expect(vi.mocked(putRepositorySbom).mock.calls[0]?.[0].path).toEqual({
        repositoryId: 7,
      });
    });

    it('returns the error of a failed upload with the created repository', async () => {
      const error = axiosError(400);
      vi.mocked(putRepositorySbom).mockRejectedValue(error);

      expect(
        await createRepositoryWithSbom(2, values, new File(['x'], 'x.txt'))
      ).toEqual({ repository, sbomError: error });
    });
  });
});
