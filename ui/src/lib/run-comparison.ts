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

import type {
  Identifier,
  Package,
  PagedResponseVulnerabilityWithDetails,
  VulnerabilityRating,
  VulnerabilityWithDetails,
} from '@/api';
import { getRunPackages, getRunVulnerabilities } from '@/api/sdk.gen';

/** The maximum number of items that the endpoints of ORT Server return per page. */
const PAGE_SIZE = 100;

/** The packages and vulnerabilities of a run that are compared with those of another run. */
export type RunContents = {
  packages: Package[];
  vulnerabilities: VulnerabilityWithDetails[];
};

/** A package whose versions differ between two runs. */
export type PackageVersionChange = {
  /** The coordinates of the package without version, such as 'Maven:org.example:library'. */
  coordinates: string;
  /** The versions of the package in the base run. */
  fromVersions: string[];
  /** The versions of the package in the compared run. */
  toVersions: string[];
};

/** The differences between the packages and vulnerabilities of a base run and a compared run. */
export type RunComparison = {
  /** The packages of the compared run that the base run does not have in any version. */
  addedPackages: Identifier[];
  /** The packages of the base run that the compared run does not have in any version. */
  removedPackages: Identifier[];
  /** The packages that both runs have, but in different versions. */
  changedPackages: PackageVersionChange[];
  /** The vulnerabilities of the compared run that do not affect the same package in the base run. */
  newVulnerabilities: VulnerabilityWithDetails[];
  /** The vulnerabilities of the base run that no longer affect the same package in the compared run. */
  fixedVulnerabilities: VulnerabilityWithDetails[];
};

/** Fetch all pages of a paged list, using [fetchPage] to fetch the page that starts at an offset. */
async function fetchAllPages<T>(
  fetchPage: (
    offset: number
  ) => Promise<{ data: T[]; pagination: { totalCount: number } }>
): Promise<T[]> {
  const items: T[] = [];
  let totalCount = Number.POSITIVE_INFINITY;

  while (items.length < totalCount) {
    const page = await fetchPage(items.length);
    totalCount = page.pagination.totalCount;
    if (page.data.length === 0) break;
    items.push(...page.data);
  }

  return items;
}

/**
 * Fetch the packages and the vulnerabilities of the run with the given ID. While ORT Server prepares
 * the vulnerabilities of a run, the request fails with status 503, see [isPreparing].
 */
export async function fetchRunContents(runId: number): Promise<RunContents> {
  const [packages, vulnerabilities] = await Promise.all([
    fetchAllPages(async (offset) => {
      const { data } = await getRunPackages({
        path: { runId },
        query: { limit: PAGE_SIZE, offset },
        throwOnError: true,
      });
      return data;
    }),
    fetchAllPages(async (offset) => {
      const { data } = await getRunVulnerabilities({
        path: { runId },
        query: { limit: PAGE_SIZE, offset },
        throwOnError: true,
      });
      // Without asking for an asynchronous response, there is no response with status 202.
      return data as PagedResponseVulnerabilityWithDetails;
    }),
  ]);

  return { packages, vulnerabilities };
}

/** Return whether the given error means that ORT Server is still preparing the data of a run. */
export function isPreparing(error: unknown): boolean {
  return error instanceof AxiosError && error.response?.status === 503;
}

/** Return the coordinates of the given identifier without version, which identify a package across runs. */
export function getCoordinates(identifier: Identifier): string {
  return [identifier.type, identifier.namespace, identifier.name].join(':');
}

/** Return the coordinates of the given identifier including its version. */
export function formatIdentifier(identifier: Identifier): string {
  return [getCoordinates(identifier), identifier.version].join(':');
}

const RATING_ORDER: Record<VulnerabilityRating, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  NONE: 4,
};

/** Group the identifiers of the given packages by their coordinates without version. */
function groupByCoordinates(packages: Package[]): Map<string, Identifier[]> {
  const groups = new Map<string, Identifier[]>();

  for (const pkg of packages) {
    const coordinates = getCoordinates(pkg.identifier);
    groups.set(coordinates, [
      ...(groups.get(coordinates) ?? []),
      pkg.identifier,
    ]);
  }

  return groups;
}

const vulnerabilityKey = (vulnerability: VulnerabilityWithDetails) =>
  `${vulnerability.vulnerability.externalId}|${getCoordinates(vulnerability.identifier)}`;

/** Return the given vulnerabilities, without duplicates, the most severe first. */
function sortVulnerabilities(
  vulnerabilities: VulnerabilityWithDetails[]
): VulnerabilityWithDetails[] {
  return [
    ...new Map(vulnerabilities.map((v) => [vulnerabilityKey(v), v])).values(),
  ].sort(
    (a, b) =>
      RATING_ORDER[a.rating] - RATING_ORDER[b.rating] ||
      a.vulnerability.externalId.localeCompare(b.vulnerability.externalId) ||
      formatIdentifier(a.identifier).localeCompare(
        formatIdentifier(b.identifier)
      )
  );
}

const sortedVersions = (identifiers: Identifier[]) =>
  [...new Set(identifiers.map((id) => id.version))].sort();

/**
 * Compare the packages and vulnerabilities of a [base] run with those of a [compared] run.
 * Packages are matched by their coordinates without version, so that an update of a package is a
 * version change rather than a removed and an added package. A vulnerability is new if it did not
 * affect the same package, in any version, in the base run, and fixed if it no longer affects it.
 */
export function compareRuns(
  base: RunContents,
  compared: RunContents
): RunComparison {
  const basePackages = groupByCoordinates(base.packages);
  const comparedPackages = groupByCoordinates(compared.packages);

  const addedPackages = [...comparedPackages.entries()]
    .filter(([coordinates]) => !basePackages.has(coordinates))
    .flatMap(([, identifiers]) => identifiers);

  const removedPackages = [...basePackages.entries()]
    .filter(([coordinates]) => !comparedPackages.has(coordinates))
    .flatMap(([, identifiers]) => identifiers);

  const changedPackages = [...comparedPackages.entries()]
    .flatMap(([coordinates, identifiers]) => {
      const baseIdentifiers = basePackages.get(coordinates);
      if (!baseIdentifiers) return [];

      const fromVersions = sortedVersions(baseIdentifiers);
      const toVersions = sortedVersions(identifiers);
      return fromVersions.join() === toVersions.join()
        ? []
        : [{ coordinates, fromVersions, toVersions }];
    })
    .sort((a, b) => a.coordinates.localeCompare(b.coordinates));

  const baseVulnerabilities = new Set(
    base.vulnerabilities.map(vulnerabilityKey)
  );
  const comparedVulnerabilities = new Set(
    compared.vulnerabilities.map(vulnerabilityKey)
  );

  const byIdentifier = (a: Identifier, b: Identifier) =>
    formatIdentifier(a).localeCompare(formatIdentifier(b));

  return {
    addedPackages: addedPackages.sort(byIdentifier),
    removedPackages: removedPackages.sort(byIdentifier),
    changedPackages,
    newVulnerabilities: sortVulnerabilities(
      compared.vulnerabilities.filter(
        (v) => !baseVulnerabilities.has(vulnerabilityKey(v))
      )
    ),
    fixedVulnerabilities: sortVulnerabilities(
      base.vulnerabilities.filter(
        (v) => !comparedVulnerabilities.has(vulnerabilityKey(v))
      )
    ),
  };
}
