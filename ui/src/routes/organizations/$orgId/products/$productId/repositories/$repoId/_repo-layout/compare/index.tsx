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

import { useQuery } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import type { OrtRunSummary } from '@/api';
import { getRepositoryRunsOptions } from '@/api/@tanstack/react-query.gen';
import { LoadingIndicator } from '@/components/loading-indicator';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  compareRuns,
  fetchRunContents,
  isPreparing,
} from '@/lib/run-comparison';
import { ComparisonResult } from './-components/comparison-result';

/** The maximum number of runs offered for comparison, the latest first. */
const RUN_LIMIT = 100;

const describeRun = (run: OrtRunSummary) =>
  [
    `#${run.index}`,
    run.revision,
    new Date(run.createdAt).toLocaleString(),
    run.status,
  ]
    .filter(Boolean)
    .join(' · ');

const RunSelect = ({
  id,
  label,
  runs,
  value,
  onChange,
}: {
  id: string;
  label: string;
  runs: OrtRunSummary[];
  value: number | undefined;
  onChange: (index: number) => void;
}) => (
  <div className='flex flex-col gap-2'>
    <Label htmlFor={id}>{label}</Label>
    <Select
      value={value?.toString()}
      onValueChange={(selected) => onChange(Number.parseInt(selected))}
    >
      <SelectTrigger id={id} className='w-full'>
        <SelectValue placeholder='Select a run' />
      </SelectTrigger>
      <SelectContent>
        {runs.map((run) => (
          <SelectItem key={run.id} value={run.index.toString()}>
            {describeRun(run)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  </div>
);

const CompareRunsPage = () => {
  const params = Route.useParams();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  const repositoryId = Number.parseInt(params.repoId);

  const { data: runs, isPending: runsPending } = useQuery({
    ...getRepositoryRunsOptions({
      path: { repositoryId },
      query: { limit: RUN_LIMIT, sort: '-index' },
    }),
  });

  // By default, compare the latest run with the one before.
  const toIndex = search.to ?? runs?.data[0]?.index;
  const fromIndex = search.from ?? runs?.data[1]?.index;
  const fromRun = runs?.data.find((run) => run.index === fromIndex);
  const toRun = runs?.data.find((run) => run.index === toIndex);

  const comparison = useQuery({
    queryKey: ['run-comparison', fromRun?.id, toRun?.id],
    queryFn: async () => {
      const [base, compared] = await Promise.all([
        fetchRunContents(fromRun!.id),
        fetchRunContents(toRun!.id),
      ]);
      return compareRuns(base, compared);
    },
    enabled: fromRun !== undefined && toRun !== undefined,
    // ORT Server answers with 503 while it prepares the vulnerabilities of a run.
    retry: (failureCount, error) => isPreparing(error) && failureCount < 20,
    retryDelay: 3000,
  });

  const select = (key: 'from' | 'to') => (index: number) =>
    navigate({ search: (prev) => ({ ...prev, [key]: index }) });

  return (
    <div className='flex flex-col gap-4'>
      <Card>
        <CardHeader>
          <CardTitle>Compare runs</CardTitle>
          <CardDescription>
            Compare the packages and vulnerabilities of two runs of this
            repository, for instance of two versions of its SBOM. Packages are
            matched by their coordinates without version, and vulnerabilities by
            their ID and the package they affect.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {runsPending && <LoadingIndicator />}
          {runs && runs.data.length < 2 && (
            <div className='text-muted-foreground'>
              At least two runs are needed for a comparison.
            </div>
          )}
          {runs && runs.data.length >= 2 && (
            <div className='grid grid-cols-1 gap-4 md:grid-cols-2'>
              <RunSelect
                id='base-run'
                label='Base run'
                runs={runs.data}
                value={fromIndex}
                onChange={select('from')}
              />
              <RunSelect
                id='compared-run'
                label='Compared run'
                runs={runs.data}
                value={toIndex}
                onChange={select('to')}
              />
            </div>
          )}
        </CardContent>
      </Card>

      {comparison.isFetching && !comparison.data && (
        <Card>
          <CardContent className='flex items-center gap-2 pt-6'>
            <LoadingIndicator />
            Loading the packages and vulnerabilities of the runs...
          </CardContent>
        </Card>
      )}

      {comparison.error && (
        <Card>
          <CardContent className='text-destructive pt-6'>
            Unable to compare the runs: {comparison.error.message}
          </CardContent>
        </Card>
      )}

      {comparison.data && fromRun && toRun && (
        <ComparisonResult
          comparison={comparison.data}
          fromIndex={fromRun.index}
          toIndex={toRun.index}
        />
      )}
    </div>
  );
};

const compareSearchSchema = z.object({
  from: z.number().int().positive().optional(),
  to: z.number().int().positive().optional(),
});

export const Route = createFileRoute(
  '/organizations/$orgId/products/$productId/repositories/$repoId/_repo-layout/compare/'
)({
  validateSearch: compareSearchSchema,
  component: CompareRunsPage,
});
