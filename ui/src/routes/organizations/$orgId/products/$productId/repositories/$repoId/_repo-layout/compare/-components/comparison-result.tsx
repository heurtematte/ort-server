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

import type { ReactNode } from 'react';

import type { Identifier, VulnerabilityWithDetails } from '@/api';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatIdentifier, type RunComparison } from '@/lib/run-comparison';

const Section = ({
  title,
  description,
  count,
  children,
}: {
  title: string;
  description: string;
  count: number;
  children: ReactNode;
}) => (
  <Card>
    <CardHeader>
      <CardTitle>
        {title} ({count})
      </CardTitle>
      <CardDescription>{description}</CardDescription>
    </CardHeader>
    <CardContent>
      {count === 0 ? (
        <div className='text-muted-foreground'>None.</div>
      ) : (
        children
      )}
    </CardContent>
  </Card>
);

const PackageTable = ({ identifiers }: { identifiers: Identifier[] }) => (
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Package</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {identifiers.map((identifier) => (
        <TableRow key={formatIdentifier(identifier)}>
          <TableCell className='break-all whitespace-normal'>
            {formatIdentifier(identifier)}
          </TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
);

const VulnerabilityTable = ({
  vulnerabilities,
}: {
  vulnerabilities: VulnerabilityWithDetails[];
}) => (
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Vulnerability</TableHead>
        <TableHead>Rating</TableHead>
        <TableHead>Package</TableHead>
        <TableHead>Summary</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {vulnerabilities.map((vulnerability) => (
        <TableRow
          key={`${vulnerability.vulnerability.externalId}|${formatIdentifier(vulnerability.identifier)}`}
        >
          <TableCell className='font-semibold'>
            {vulnerability.vulnerability.externalId}
          </TableCell>
          <TableCell>
            <Badge variant='outline'>{vulnerability.rating}</Badge>
          </TableCell>
          <TableCell className='break-all whitespace-normal'>
            {formatIdentifier(vulnerability.identifier)}
          </TableCell>
          <TableCell className='whitespace-normal'>
            {vulnerability.vulnerability.summary}
          </TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
);

/** The differences between the packages and vulnerabilities of two runs. */
export const ComparisonResult = ({
  comparison,
  fromIndex,
  toIndex,
}: {
  comparison: RunComparison;
  fromIndex: number;
  toIndex: number;
}) => (
  <div className='flex flex-col gap-4'>
    <Section
      title='New vulnerabilities'
      description={`Vulnerabilities of run #${toIndex} that did not affect the same package in run #${fromIndex}.`}
      count={comparison.newVulnerabilities.length}
    >
      <VulnerabilityTable vulnerabilities={comparison.newVulnerabilities} />
    </Section>
    <Section
      title='Fixed vulnerabilities'
      description={`Vulnerabilities of run #${fromIndex} that no longer affect the same package in run #${toIndex}.`}
      count={comparison.fixedVulnerabilities.length}
    >
      <VulnerabilityTable vulnerabilities={comparison.fixedVulnerabilities} />
    </Section>
    <Section
      title='Added packages'
      description={`Packages of run #${toIndex} that run #${fromIndex} does not have in any version.`}
      count={comparison.addedPackages.length}
    >
      <PackageTable identifiers={comparison.addedPackages} />
    </Section>
    <Section
      title='Removed packages'
      description={`Packages of run #${fromIndex} that run #${toIndex} does not have in any version.`}
      count={comparison.removedPackages.length}
    >
      <PackageTable identifiers={comparison.removedPackages} />
    </Section>
    <Section
      title='Changed versions'
      description='Packages that both runs have, but in different versions.'
      count={comparison.changedPackages.length}
    >
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Package</TableHead>
            <TableHead>Run #{fromIndex}</TableHead>
            <TableHead>Run #{toIndex}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {comparison.changedPackages.map((change) => (
            <TableRow key={change.coordinates}>
              <TableCell className='break-all whitespace-normal'>
                {change.coordinates}
              </TableCell>
              <TableCell>{change.fromVersions.join(', ')}</TableCell>
              <TableCell>{change.toVersions.join(', ')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Section>
  </div>
);
