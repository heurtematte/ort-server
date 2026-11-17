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

import type {
  Identifier,
  Package,
  VulnerabilityRating,
  VulnerabilityWithDetails,
} from '@/api';
import { getRunPackages, getRunVulnerabilities } from '@/api/sdk.gen';
import {
  compareRuns,
  fetchRunContents,
  formatIdentifier,
  isPreparing,
} from '@/lib/run-comparison';

vi.mock('@/api/sdk.gen', () => ({
  getRunPackages: vi.fn(),
  getRunVulnerabilities: vi.fn(),
}));

const identifier = (name: string, version: string): Identifier => ({
  type: 'Maven',
  namespace: 'org.example',
  name,
  version,
});

const pkg = (name: string, version: string) =>
  ({ identifier: identifier(name, version) }) as unknown as Package;

const vulnerability = (
  externalId: string,
  name: string,
  version: string,
  rating: VulnerabilityRating = 'HIGH'
) =>
  ({
    vulnerability: { externalId, summary: `${externalId} summary` },
    identifier: identifier(name, version),
    rating,
  }) as unknown as VulnerabilityWithDetails;

describe('compareRuns', () => {
  it('finds added and removed packages and changed versions', () => {
    const comparison = compareRuns(
      {
        packages: [
          pkg('kept', '1.0'),
          pkg('updated', '1.0'),
          pkg('gone', '2.0'),
        ],
        vulnerabilities: [],
      },
      {
        packages: [
          pkg('kept', '1.0'),
          pkg('updated', '1.1'),
          pkg('new', '3.0'),
        ],
        vulnerabilities: [],
      }
    );

    expect(comparison.addedPackages).toEqual([identifier('new', '3.0')]);
    expect(comparison.removedPackages).toEqual([identifier('gone', '2.0')]);
    expect(comparison.changedPackages).toEqual([
      {
        coordinates: 'Maven:org.example:updated',
        fromVersions: ['1.0'],
        toVersions: ['1.1'],
      },
    ]);
  });

  it('matches vulnerabilities by their ID and the package they affect in any version', () => {
    const comparison = compareRuns(
      {
        packages: [],
        vulnerabilities: [
          vulnerability('CVE-1', 'lib', '1.0'),
          vulnerability('CVE-2', 'lib', '1.0'),
        ],
      },
      {
        packages: [],
        vulnerabilities: [
          vulnerability('CVE-1', 'lib', '1.1'),
          vulnerability('CVE-3', 'other', '2.0', 'MEDIUM'),
          vulnerability('CVE-4', 'other', '2.0', 'CRITICAL'),
        ],
      }
    );

    expect(
      comparison.newVulnerabilities.map((v) => v.vulnerability.externalId)
    ).toEqual(['CVE-4', 'CVE-3']);
    expect(
      comparison.fixedVulnerabilities.map((v) => v.vulnerability.externalId)
    ).toEqual(['CVE-2']);
  });

  it('reports no differences between identical runs', () => {
    const contents = {
      packages: [pkg('lib', '1.0')],
      vulnerabilities: [vulnerability('CVE-1', 'lib', '1.0')],
    };

    expect(compareRuns(contents, contents)).toEqual({
      addedPackages: [],
      removedPackages: [],
      changedPackages: [],
      newVulnerabilities: [],
      fixedVulnerabilities: [],
    });
  });
});

describe('fetchRunContents', () => {
  beforeEach(() => {
    vi.mocked(getRunPackages).mockReset();
    vi.mocked(getRunVulnerabilities).mockReset();
  });

  it('fetches all pages of the packages and vulnerabilities of a run', async () => {
    const packages = Array.from({ length: 150 }, (_, i) => pkg(`p${i}`, '1'));
    vi.mocked(getRunPackages).mockImplementation((async (options: {
      query: { offset: number; limit: number };
    }) => ({
      data: {
        data: packages.slice(
          options.query.offset,
          options.query.offset + options.query.limit
        ),
        pagination: { totalCount: packages.length },
      },
    })) as unknown as typeof getRunPackages);
    vi.mocked(getRunVulnerabilities).mockResolvedValue({
      data: {
        data: [vulnerability('CVE-1', 'p1', '1')],
        pagination: { totalCount: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof getRunVulnerabilities>>);

    const contents = await fetchRunContents(7);

    expect(contents.packages).toHaveLength(150);
    expect(contents.vulnerabilities).toHaveLength(1);
    expect(getRunPackages).toHaveBeenCalledTimes(2);
    expect(getRunPackages).toHaveBeenLastCalledWith({
      path: { runId: 7 },
      query: { limit: 100, offset: 100 },
      throwOnError: true,
    });
  });
});

describe('run comparison helpers', () => {
  it('recognizes that ORT Server prepares the data of a run', () => {
    const error = (status: number) =>
      new AxiosError('Request failed', 'ERR', undefined, undefined, {
        status,
        statusText: '',
        headers: {},
        config: { headers: new AxiosHeaders() },
        data: {},
      });

    expect(isPreparing(error(503))).toBe(true);
    expect(isPreparing(error(500))).toBe(false);
    expect(isPreparing(new Error('Network Error'))).toBe(false);
  });

  it('formats identifiers with their version', () => {
    expect(formatIdentifier(identifier('lib', '1.0'))).toBe(
      'Maven:org.example:lib:1.0'
    );
  });
});
