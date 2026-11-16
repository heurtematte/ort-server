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

// @vitest-environment jsdom

import { screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { RepositorySbom } from '@/api';
import {
  getRepositorySbomVersions,
  postRepositorySbomVersionRestore,
} from '@/api/sdk.gen';
import { SbomHistory } from '@/routes/organizations/$orgId/products/$productId/repositories/$repoId/_repo-layout/sbom/-components/sbom-history';
import { renderInteractiveWithRouter } from '../fixtures/render-interactive';

vi.mock('@/api/sdk.gen', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/sdk.gen')>()),
  getRepositorySbomVersions: vi.fn(),
  postRepositorySbomVersionRestore: vi.fn(),
}));

vi.mock('@/lib/toast', () => ({
  toast: { info: vi.fn() },
  toastError: vi.fn(),
}));

const sbom = (id: number, fileName: string, current: boolean) =>
  ({
    id,
    current,
    fileName,
    format: 'CycloneDX JSON',
    mediaType: 'application/vnd.cyclonedx+json',
    specVersion: '1.6',
    size: 42,
    sha256: `${id}`.repeat(64).slice(0, 64),
    uploadedAt: '2026-11-16T12:00:00Z',
    uploadedBy: 'alice',
    componentCount: 3,
  }) as RepositorySbom;

const renderHistory = (canWrite = true) =>
  renderInteractiveWithRouter(
    <SbomHistory repositoryId={7} canWrite={canWrite} />,
    { path: '/', withQueryClient: true }
  );

describe('SbomHistory', () => {
  beforeEach(() => {
    vi.mocked(getRepositorySbomVersions).mockResolvedValue({
      data: [
        sbom(2, 'second.cdx.json', true),
        sbom(1, 'first.cdx.json', false),
      ],
    } as unknown as Awaited<ReturnType<typeof getRepositorySbomVersions>>);
    vi.mocked(postRepositorySbomVersionRestore).mockReset();
  });

  it('lists the uploaded SBOMs and marks the current one', async () => {
    renderHistory();

    const current = (await screen.findByText('second.cdx.json')).closest('tr')!;
    expect(within(current).getByText('Current')).toBeVisible();
    expect(
      within(current).queryByRole('button', { name: 'Use this version' })
    ).toBeNull();

    const previous = screen.getByText('first.cdx.json').closest('tr')!;
    expect(within(previous).queryByText('Current')).toBeNull();
    expect(
      within(previous).getByRole('button', { name: 'Use this version' })
    ).toBeEnabled();
  });

  it('makes an SBOM from the history the current SBOM', async () => {
    vi.mocked(postRepositorySbomVersionRestore).mockResolvedValue({
      data: sbom(1, 'first.cdx.json', true),
    } as unknown as Awaited<
      ReturnType<typeof postRepositorySbomVersionRestore>
    >);
    const { user } = renderHistory();

    const previous = (await screen.findByText('first.cdx.json')).closest('tr')!;
    await user.click(
      within(previous).getByRole('button', { name: 'Use this version' })
    );

    expect(
      vi.mocked(postRepositorySbomVersionRestore).mock.calls[0]?.[0].path
    ).toEqual({ repositoryId: 7, sbomId: 1 });
  });

  it('does not let users without write permission change the current SBOM', async () => {
    renderHistory(false);

    const previous = (await screen.findByText('first.cdx.json')).closest('tr')!;
    expect(
      within(previous).getByRole('button', { name: 'Use this version' })
    ).toBeDisabled();
  });
});
