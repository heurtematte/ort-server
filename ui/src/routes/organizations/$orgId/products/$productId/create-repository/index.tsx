/*
 * Copyright (C) 2024 The ORT Server Authors (See <https://github.com/eclipse-apoapsis/ort-server/blob/main/NOTICE>)
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

import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { Loader2 } from 'lucide-react';
import { useState, type ChangeEvent } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import { zRepositoryType } from '@/api/zod.gen';
import { withProductPermission } from '@/components/authorization';
import { OptionalInput } from '@/components/form/optional-input.tsx';
import { PasswordInput } from '@/components/form/password-input';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ApiError } from '@/lib/api-error';
import { repositoryCreated } from '@/lib/entity-cache';
import {
  createRepositoryWithSbom,
  SBOM_FILE_ACCEPT,
  type CreateRepositoryWithSbomResult,
} from '@/lib/repository-sbom';
import {
  detectSbomSource,
  getSbomSourceLabel,
  getSbomUploadUrl,
} from '@/lib/sbom-source';
import { toast, toastError } from '@/lib/toast';
import { getRepositoryTypeLabel } from '@/lib/types';
import {
  createRepositoryFormSchema,
  type CreateRepositoryFormValues,
} from '@/schemas';

/** Whether the SBOM of a repository of type SBOM comes from a URL or from an uploaded file. */
type SbomInput = 'url' | 'file';

interface CreateRepositoryFormProps {
  isPending: boolean;
  /** Called with the values of the form and, for an SBOM to upload, the file. */
  onSubmit: (
    values: CreateRepositoryFormValues,
    sbomFile?: File
  ) => Promise<void> | void;
}

export const CreateRepositoryForm = ({
  isPending,
  onSubmit,
}: CreateRepositoryFormProps) => {
  const form = useForm<CreateRepositoryFormValues>({
    resolver: zodResolver(createRepositoryFormSchema),
    defaultValues: {
      description: '',
      name: '',
      url: '',
      type: 'GIT',
      username: '',
      password: '',
    },
    mode: 'onChange',
  });

  const [type, url] = useWatch({
    control: form.control,
    name: ['type', 'url'],
  });
  const [sbomInput, setSbomInput] = useState<SbomInput>('url');
  const [sbomFile, setSbomFile] = useState<File>();

  const isSbomRepository = type === 'SBOM';
  const isSbomUpload = isSbomRepository && sbomInput === 'file';
  const sbomSource = isSbomRepository ? detectSbomSource(url) : undefined;

  function switchSbomInput(input: SbomInput) {
    setSbomInput(input);
    setSbomFile(undefined);
    form.setValue('url', '', { shouldValidate: true });

    // Uploaded SBOMs need no credentials.
    if (input === 'file') {
      form.setValue('username', '');
      form.setValue('password', '', { shouldValidate: true });
    }
  }

  function handleSbomFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    setSbomFile(file);
    form.setValue('url', file ? getSbomUploadUrl(file.name) : '', {
      shouldValidate: true,
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add Repository</CardTitle>
      </CardHeader>
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit((values) =>
            onSubmit(values, isSbomUpload ? sbomFile : undefined)
          )}
          className='space-y-8'
        >
          <CardContent className='space-y-4'>
            <div className='grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]'>
              {isSbomUpload ? (
                <div className='flex flex-col gap-2'>
                  <Label htmlFor='sbom-file'>SBOM file</Label>
                  <Input
                    id='sbom-file'
                    type='file'
                    accept={SBOM_FILE_ACCEPT}
                    onChange={handleSbomFileChange}
                  />
                  <p className='text-muted-foreground text-sm'>
                    A CycloneDX or SPDX document, whose format is detected from
                    its content. It is uploaded once the repository is created,
                    and can be replaced on the SBOM page of the repository.
                  </p>
                </div>
              ) : (
                <FormField
                  control={form.control}
                  name='url'
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>URL</FormLabel>
                      <FormControl autoFocus>
                        <Input {...field} />
                      </FormControl>
                      {isSbomRepository && (
                        <FormDescription>
                          {sbomSource
                            ? `Source: ${getSbomSourceLabel(sbomSource)}. ORT Server confirms it with the server when the repository is created.`
                            : 'The URL of a Dependency-Track project page, of a sbomify component or product page, or of an SBOM document.'}
                        </FormDescription>
                      )}
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}
              <FormField
                control={form.control}
                name='type'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Type</FormLabel>
                    <Select
                      onValueChange={(value) => {
                        field.onChange(value);
                        if (value !== 'SBOM' && sbomInput === 'file') {
                          switchSbomInput('url');
                        }
                      }}
                      defaultValue={field.value}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder='Select a type' />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {Object.values(zRepositoryType.enum).map((type) => (
                          <SelectItem key={type} value={type}>
                            {getRepositoryTypeLabel(type)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            {isSbomRepository && (
              <div className='flex flex-col gap-2'>
                <Label>SBOM</Label>
                <RadioGroup
                  value={sbomInput}
                  onValueChange={(value) => switchSbomInput(value as SbomInput)}
                  className='flex flex-wrap gap-6'
                >
                  <div className='flex items-center gap-2'>
                    <RadioGroupItem value='url' id='sbom-input-url' />
                    <Label htmlFor='sbom-input-url'>From the URL</Label>
                  </div>
                  <div className='flex items-center gap-2'>
                    <RadioGroupItem value='file' id='sbom-input-file' />
                    <Label htmlFor='sbom-input-file'>Upload a file</Label>
                  </div>
                </RadioGroup>
              </div>
            )}
            <FormField
              control={form.control}
              name='name'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <OptionalInput {...field} />
                  </FormControl>
                  {isSbomRepository && (
                    <FormDescription>
                      {isSbomUpload
                        ? 'If empty, the repository is named after the component that the SBOM describes at the first run.'
                        : 'If empty, the repository is named after the project or component of its source at the first run.'}
                    </FormDescription>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name='description'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <OptionalInput {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {!isSbomUpload && (
              <div className='grid gap-4 md:grid-cols-2'>
                <FormField
                  control={form.control}
                  name='username'
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Username</FormLabel>
                      <FormControl>
                        <OptionalInput
                          placeholder='(optional, only needed for private repositories)'
                          {...field}
                          onChange={(event: ChangeEvent<HTMLInputElement>) => {
                            field.onChange(event);
                            void form.trigger(['username', 'password']);
                          }}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name='password'
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>
                        Password or Personal Access Token (PAT)
                      </FormLabel>
                      <FormControl>
                        <PasswordInput
                          {...field}
                          placeholder='(optional, only needed for private repositories)'
                          onChange={(event: ChangeEvent<HTMLInputElement>) => {
                            field.onChange(event);
                            void form.trigger(['username', 'password']);
                          }}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}
          </CardContent>
          <CardFooter>
            <Button
              type='submit'
              disabled={isPending || !form.formState.isValid}
            >
              {isPending ? (
                <>
                  <span className='sr-only'>Adding repository...</span>
                  <Loader2 size={16} className='mx-3 animate-spin' />
                </>
              ) : (
                'Add'
              )}
            </Button>
          </CardFooter>
        </form>
      </Form>
    </Card>
  );
};

export const CreateRepositoryPage = () => {
  const navigate = useNavigate();
  const params = Route.useParams();
  const queryClient = useQueryClient();

  const { mutateAsync, isPending } = useMutation({
    mutationFn: ({
      values,
      sbomFile,
    }: {
      values: CreateRepositoryFormValues;
      sbomFile?: File;
    }) =>
      createRepositoryWithSbom(
        Number.parseInt(params.productId),
        values,
        sbomFile
      ),
    onSuccess({
      repository,
      credentialsError,
      sbomUploaded,
      sbomError,
    }: CreateRepositoryWithSbomResult) {
      repositoryCreated(queryClient, repository.productId);

      if (credentialsError) {
        toastError(
          `Repository ${repository.url} was added, but its credentials could not be stored. ` +
            'Add the missing entries under the repository’s Secrets and Infrastructure Services.',
          credentialsError
        );
      } else if (sbomError) {
        toastError(
          `Repository ${repository.url} was added, but its SBOM could not be uploaded. ` +
            'Upload it again on the SBOM page of the repository.',
          sbomError
        );
      } else {
        toast.info('Add Repository', {
          description: sbomUploaded
            ? `Repository ${repository.url} added successfully with its SBOM.`
            : `Repository ${repository.url} added successfully.`,
        });
      }

      const repositoryParams = {
        orgId: params.orgId,
        productId: params.productId,
        repoId: repository.id.toString(),
      };

      // After an upload, show the SBOM, which tells whether it was stored.
      if (sbomUploaded || sbomError) {
        navigate({
          to: '/organizations/$orgId/products/$productId/repositories/$repoId/sbom',
          params: repositoryParams,
        });
      } else {
        navigate({
          to: '/organizations/$orgId/products/$productId/repositories/$repoId',
          params: repositoryParams,
        });
      }
    },
    onError(error: ApiError) {
      if (error.response?.status === 409) {
        toastError(
          'A repository with the same URL and name already exists in this product.',
          error
        );
      } else {
        toastError(error.message, error);
      }
    },
  });

  async function onSubmit(values: CreateRepositoryFormValues, sbomFile?: File) {
    await mutateAsync({ values, sbomFile });
  }

  return <CreateRepositoryForm isPending={isPending} onSubmit={onSubmit} />;
};

export const Route = createFileRoute(
  '/organizations/$orgId/products/$productId/create-repository/'
)({
  component: withProductPermission('CREATE_REPOSITORY', CreateRepositoryPage),
});
