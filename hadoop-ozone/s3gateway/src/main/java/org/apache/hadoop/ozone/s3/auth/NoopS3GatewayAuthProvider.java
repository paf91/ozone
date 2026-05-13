/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.ozone.s3.auth;

import javax.ws.rs.container.ContainerRequestContext;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo;

/**
 * Existing non-secure S3 Gateway behavior: do not enforce local S3 auth.
 */
final class NoopS3GatewayAuthProvider implements S3GatewayAuthProvider {
  @Override
  public S3Principal authenticate(ContainerRequestContext context,
      SignatureInfo signatureInfo) {
    return null;
  }

  @Override
  public void authorize(S3Principal principal, S3Action action, String bucket,
      String keyOrPrefix) throws OS3Exception {
    // Existing non-secure behavior intentionally allows all S3 requests.
  }
}
