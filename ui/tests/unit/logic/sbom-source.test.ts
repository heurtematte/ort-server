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

import { describe, expect, it } from 'vitest';

import { detectSbomSource, getSbomSourceLabel } from '@/lib/sbom-source';

describe('SBOM source', () => {
  it('detects Dependency-Track projects from the URL of their page', () => {
    expect(
      detectSbomSource(
        'https://sbom.eclipse.org/projects/583d447a-ca3e-45b9-8eaf-464889a4b2c7'
      )
    ).toBe('DEPENDENCY_TRACK_PROJECT');
    expect(
      detectSbomSource(
        'https://example.org/dtrack/projects/583d447a-ca3e-45b9-8eaf-464889a4b2c7/'
      )
    ).toBe('DEPENDENCY_TRACK_PROJECT');
  });

  it('detects sbomify components and products', () => {
    expect(detectSbomSource('https://app.sbomify.com/component/Ab3_x-9/')).toBe(
      'SBOMIFY_COMPONENT'
    );
    expect(
      detectSbomSource('https://app.sbomify.com/public/product/eP_4dk8ixV/')
    ).toBe('SBOMIFY_PRODUCT');
  });

  it('treats other HTTP(S) URLs as SBOM documents', () => {
    expect(
      detectSbomSource('https://example.org/releases/1.0/bom.cdx.json')
    ).toBe('DOCUMENT');
    expect(
      detectSbomSource(
        'https://sbom.eclipse.org/projects/583d447a-ca3e-45b9-8eaf-464889a4b2c7/components'
      )
    ).toBe('DOCUMENT');
  });

  it('detects nothing for other URLs', () => {
    expect(detectSbomSource('')).toBeUndefined();
    expect(detectSbomSource('git@github.com:org/repo.git')).toBeUndefined();
  });

  it('provides labels for the kinds of sources', () => {
    expect(getSbomSourceLabel('DEPENDENCY_TRACK_PROJECT')).toBe(
      'Dependency-Track project'
    );
  });
});
