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

import {
  useMutation,
  useQuery,
  useQueryClient,
  useSuspenseQuery,
} from '@tanstack/react-query';
import { createFileRoute, Link } from '@tanstack/react-router';
import { Download, Upload } from 'lucide-react';
import { useRef, type ChangeEvent, type ReactNode } from 'react';

import {
  deleteRepositorySbomMutation,
  getRepositoryOptions,
  getRepositorySbomOptions,
  getRepositorySbomQueryKey,
} from '@/api/@tanstack/react-query.gen';
import { withRepositoryPermission } from '@/components/authorization';
import { DeleteDialog } from '@/components/delete-dialog';
import { LoadingIndicator } from '@/components/loading-indicator';
import { TimestampWithUTC } from '@/components/timestamp-with-utc';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { formatFileSize } from '@/helpers/format-file-size';
import { useRepositoryPermission } from '@/hooks/use-authorization';
import { ApiError } from '@/lib/api-error';
import {
  fetchRepositorySbomContent,
  isSbomNotFound,
  saveBlob,
  SBOM_FILE_ACCEPT,
  uploadRepositorySbom,
} from '@/lib/repository-sbom';
import { toast, toastError } from '@/lib/toast';

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

const RepositorySbomPage = () => {
  const params = Route.useParams();
  const queryClient = useQueryClient();
  const fileInput = useRef<HTMLInputElement>(null);

  const repositoryId = Number.parseInt(params.repoId);
  const { isAllowed: canWrite } = useRepositoryPermission(
    repositoryId,
    'WRITE'
  );

  const { data: repository } = useSuspenseQuery({
    ...getRepositoryOptions({ path: { repositoryId } }),
  });

  const isSbomRepository = repository.type === 'SBOM';
  const sbomQueryKey = getRepositorySbomQueryKey({ path: { repositoryId } });

  const {
    data: sbom,
    isPending,
    error,
  } = useQuery({
    ...getRepositorySbomOptions({ path: { repositoryId } }),
    enabled: isSbomRepository,
    // A missing SBOM is a normal state, not an error to retry.
    retry: (failureCount, error) => !isSbomNotFound(error) && failureCount < 3,
  });

  const noSbom = isSbomNotFound(error);

  const upload = useMutation({
    mutationFn: (file: File) => uploadRepositorySbom(repositoryId, file),
    onSuccess(data) {
      queryClient.setQueryData(sbomQueryKey, data);
      toast.info('Upload SBOM', {
        description: `"${data.fileName}" (${data.format} ${data.specVersion}, ${data.componentCount} components) was uploaded. Runs started from now on analyze it.`,
      });
    },
    onError(error) {
      toastError('Unable to upload the SBOM', error);
    },
  });

  const remove = useMutation({
    ...deleteRepositorySbomMutation(),
    async onSuccess() {
      await queryClient.resetQueries({ queryKey: sbomQueryKey });
      toast.info('Delete SBOM', {
        description:
          'The uploaded SBOM was deleted. Runs analyze the SBOM of the repository URL again.',
      });
    },
    onError(error: ApiError) {
      toastError('Unable to delete the SBOM', error);
    },
  });

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    // Reset the input, so that choosing the same file again uploads it again.
    event.target.value = '';
    if (file) upload.mutate(file);
  }

  async function handleDownload() {
    if (!sbom) return;

    try {
      saveBlob(await fetchRepositorySbomContent(repositoryId), sbom.fileName);
    } catch (error) {
      toastError('Unable to download the SBOM', error);
    }
  }

  if (!isSbomRepository) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>SBOM</CardTitle>
          <CardDescription>
            Only repositories of type SBOM analyze an uploaded SBOM. This
            repository is of type {repository.type}.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>SBOM</CardTitle>
        <CardDescription>
          The SBOM that runs of this repository analyze. An uploaded SBOM takes
          precedence over the SBOM of the repository URL. CycloneDX (JSON, XML)
          and SPDX 2 (JSON, YAML, tag-value, XML) and 3 (JSON-LD) are supported;
          the format is detected from the content.
        </CardDescription>
      </CardHeader>
      <CardContent className='flex flex-col gap-6'>
        {isPending && <LoadingIndicator />}

        {noSbom && (
          <div className='text-muted-foreground'>
            No SBOM was uploaded. Runs analyze the SBOM of the repository URL,{' '}
            <span className='break-all'>{repository.url}</span>.
          </div>
        )}

        {error && !noSbom && (
          <div className='text-destructive'>
            Unable to load the information about the uploaded SBOM.
          </div>
        )}

        {sbom && (
          <div className='flex flex-col gap-2'>
            <Property label='File'>{sbom.fileName}</Property>
            <Property label='Format'>
              {sbom.format} {sbom.specVersion}
            </Property>
            <Property label='Size'>{formatFileSize(sbom.size)}</Property>
            <Property label='Components'>{sbom.componentCount}</Property>
            {sbom.rootComponents && sbom.rootComponents.length > 0 && (
              <Property label='Described components'>
                {sbom.rootComponents.join(', ')}
              </Property>
            )}
            <Property label='Uploaded'>
              <TimestampWithUTC timestamp={sbom.uploadedAt} />
              {sbom.uploadedBy && ` by ${sbom.uploadedBy}`}
            </Property>
            <Property label='SHA-256'>
              <span className='font-mono text-sm'>{sbom.sha256}</span>
            </Property>
          </div>
        )}

        {sbom?.warnings && sbom.warnings.length > 0 && (
          <Alert>
            <AlertTitle>Warnings</AlertTitle>
            <AlertDescription>
              <ul className='list-disc pl-4'>
                {sbom.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        <div className='flex flex-wrap gap-2'>
          <input
            ref={fileInput}
            type='file'
            accept={SBOM_FILE_ACCEPT}
            className='hidden'
            onChange={handleFileChange}
          />
          <Button
            onClick={() => fileInput.current?.click()}
            disabled={canWrite !== true || upload.isPending}
          >
            <Upload className='h-4 w-4' />
            {upload.isPending
              ? 'Uploading...'
              : sbom
                ? 'Replace SBOM'
                : 'Upload SBOM'}
          </Button>
          {sbom && (
            <>
              <Button variant='outline' onClick={handleDownload}>
                <Download className='h-4 w-4' />
                Download
              </Button>
              <DeleteDialog
                thingName='uploaded SBOM'
                description='Runs started afterwards analyze the SBOM of the repository URL again.'
                uiComponent={
                  <Button variant='destructive' disabled={remove.isPending}>
                    Delete SBOM
                  </Button>
                }
                onDelete={() => remove.mutate({ path: { repositoryId } })}
                disabled={canWrite !== true}
              />
            </>
          )}
          {sbom && (
            <Button variant='outline' asChild>
              <Link
                to='/organizations/$orgId/products/$productId/repositories/$repoId/create-run'
                params={{
                  orgId: params.orgId,
                  productId: params.productId,
                  repoId: params.repoId,
                }}
              >
                Create a run
              </Link>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export const Route = createFileRoute(
  '/organizations/$orgId/products/$productId/repositories/$repoId/_repo-layout/sbom/'
)({
  component: withRepositoryPermission('READ', RepositorySbomPage),
});
