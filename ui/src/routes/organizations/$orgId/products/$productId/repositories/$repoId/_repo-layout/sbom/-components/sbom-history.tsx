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

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, History } from 'lucide-react';

import type { RepositorySbom } from '@/api';
import {
  getRepositorySbomQueryKey,
  getRepositorySbomVersionsOptions,
  getRepositorySbomVersionsQueryKey,
  postRepositorySbomVersionRestoreMutation,
} from '@/api/@tanstack/react-query.gen';
import { LoadingIndicator } from '@/components/loading-indicator';
import { TimestampWithUTC } from '@/components/timestamp-with-utc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
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
import { ApiError } from '@/lib/api-error';
import {
  fetchRepositorySbomVersionContent,
  saveBlob,
} from '@/lib/repository-sbom';
import { toast, toastError } from '@/lib/toast';

type SbomHistoryProps = {
  repositoryId: number;
  /** Whether the user may change the current SBOM of the repository. */
  canWrite: boolean;
};

/**
 * The history of the SBOMs uploaded for a repository of type SBOM, from which an SBOM can be
 * downloaded or made the current SBOM again.
 */
export const SbomHistory = ({ repositoryId, canWrite }: SbomHistoryProps) => {
  const queryClient = useQueryClient();
  const path = { repositoryId };

  const {
    data: versions,
    isPending,
    error,
  } = useQuery({ ...getRepositorySbomVersionsOptions({ path }) });

  const restore = useMutation({
    ...postRepositorySbomVersionRestoreMutation(),
    async onSuccess(sbom) {
      queryClient.setQueryData(getRepositorySbomQueryKey({ path }), sbom);
      await queryClient.invalidateQueries({
        queryKey: getRepositorySbomVersionsQueryKey({ path }),
      });
      toast.info('Use SBOM', {
        description: `"${sbom.fileName}" is the current SBOM again. Runs started from now on analyze it.`,
      });
    },
    onError(error: ApiError) {
      toastError('Unable to use the SBOM', error);
    },
  });

  async function handleDownload(sbom: RepositorySbom) {
    try {
      saveBlob(
        await fetchRepositorySbomVersionContent(repositoryId, sbom.id),
        sbom.fileName
      );
    } catch (error) {
      toastError('Unable to download the SBOM', error);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
        <CardDescription>
          The SBOMs uploaded for this repository, the latest first. An SBOM
          stays here when another one is uploaded or when it is no longer used,
          and can be used again. The SBOMs page of each run shows the SBOM that
          the run analyzed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isPending && <LoadingIndicator />}

        {error && (
          <div className='text-destructive'>
            Unable to load the history of the SBOMs.
          </div>
        )}

        {versions?.length === 0 && (
          <div className='text-muted-foreground'>No SBOM was uploaded yet.</div>
        )}

        {versions && versions.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Components</TableHead>
                <TableHead>Uploaded</TableHead>
                <TableHead>SHA-256</TableHead>
                <TableHead>
                  <span className='sr-only'>Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {versions.map((sbom) => (
                <TableRow key={sbom.id}>
                  <TableCell className='break-all whitespace-normal'>
                    {sbom.fileName}
                    {sbom.current && <Badge className='ml-2'>Current</Badge>}
                  </TableCell>
                  <TableCell>
                    {sbom.format} {sbom.specVersion}
                  </TableCell>
                  <TableCell>{sbom.componentCount}</TableCell>
                  <TableCell>
                    <TimestampWithUTC timestamp={sbom.uploadedAt} />
                    {sbom.uploadedBy && ` by ${sbom.uploadedBy}`}
                  </TableCell>
                  <TableCell className='font-mono text-xs' title={sbom.sha256}>
                    {sbom.sha256.slice(0, 12)}
                  </TableCell>
                  <TableCell>
                    <div className='flex justify-end gap-2'>
                      <Button
                        variant='outline'
                        size='sm'
                        onClick={() => handleDownload(sbom)}
                      >
                        <Download className='h-4 w-4' />
                        Download
                      </Button>
                      {!sbom.current && (
                        <Button
                          variant='outline'
                          size='sm'
                          disabled={!canWrite || restore.isPending}
                          onClick={() =>
                            restore.mutate({
                              path: { repositoryId, sbomId: sbom.id },
                            })
                          }
                        >
                          <History className='h-4 w-4' />
                          Use this version
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
};
