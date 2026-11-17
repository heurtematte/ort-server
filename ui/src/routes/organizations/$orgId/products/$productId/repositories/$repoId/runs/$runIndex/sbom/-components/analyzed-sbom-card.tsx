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
import { Download } from 'lucide-react';
import type { ReactNode } from 'react';

import { getRunSbomOptions } from '@/api/@tanstack/react-query.gen';
import { TimestampWithUTC } from '@/components/timestamp-with-utc';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { formatFileSize } from '@/helpers/format-file-size';
import {
  fetchRunSbomContent,
  isSbomNotFound,
  saveBlob,
} from '@/lib/repository-sbom';
import { toastError } from '@/lib/toast';

const Property = ({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) => (
  <div className='grid grid-cols-[12rem_1fr] gap-2'>
    <div className='font-semibold'>{label}</div>
    <div className='break-all'>{children}</div>
  </div>
);

/**
 * The SBOM that a run of a repository of type SBOM analyzed, which can be downloaded. Nothing is
 * shown for a run that analyzed no SBOM.
 */
export const AnalyzedSbomCard = ({ runId }: { runId: number }) => {
  const { data: sbom } = useQuery({
    ...getRunSbomOptions({ path: { runId } }),
    // Most runs analyze source code instead of an SBOM, which is not an error to retry.
    retry: (failureCount, error) => !isSbomNotFound(error) && failureCount < 3,
  });

  if (!sbom) return null;

  async function handleDownload(fileName: string) {
    try {
      saveBlob(await fetchRunSbomContent(runId), fileName);
    } catch (error) {
      toastError('Unable to download the SBOM', error);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Analyzed SBOM</CardTitle>
        <CardDescription>
          {sbom.sourceUrl
            ? 'The SBOM that this run obtained from the source of the repository and analyzed.'
            : 'The SBOM uploaded for the repository that this run analyzed.'}
        </CardDescription>
      </CardHeader>
      <CardContent className='flex flex-col gap-4'>
        <div className='flex flex-col gap-2'>
          <Property label='File'>{sbom.fileName}</Property>
          <Property label='Format'>
            {sbom.format} {sbom.specVersion}
          </Property>
          <Property label='Size'>{formatFileSize(sbom.size)}</Property>
          <Property label='Components'>{sbom.componentCount}</Property>
          {sbom.sourceUrl && (
            <Property label='Source'>{sbom.sourceUrl}</Property>
          )}
          <Property label='Obtained'>
            <TimestampWithUTC timestamp={sbom.analyzedAt} />
          </Property>
          <Property label='SHA-256'>
            <span className='font-mono text-sm'>{sbom.sha256}</span>
          </Property>
        </div>
        <div>
          <Button
            variant='outline'
            onClick={() => handleDownload(sbom.fileName)}
          >
            <Download className='h-4 w-4' />
            Download
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
