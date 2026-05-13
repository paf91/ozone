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

import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.ACCESS_DENIED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.util.S3Consts.COPY_SOURCE_HEADER;
import static org.apache.hadoop.ozone.s3.util.S3Utils.wrapOS3Exception;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.ozone.s3.S3GatewayHttpServer;
import org.apache.hadoop.ozone.s3.VirtualHostStyleFilter;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo;
import org.apache.hadoop.ozone.s3.util.S3Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Enforces optional local S3 Gateway auth after virtual host style rewriting.
 */
@Provider
@PreMatching
@Priority(S3GatewayAuthFilter.PRIORITY)
public class S3GatewayAuthFilter implements ContainerRequestFilter {
  public static final int PRIORITY = VirtualHostStyleFilter.PRIORITY
      + (S3GatewayHttpServer.FILTER_PRIORITY_DO_AFTER / 2);

  private static final Logger LOG =
      LoggerFactory.getLogger(S3GatewayAuthFilter.class);

  @Inject
  private S3GatewayAuthProviderFactory authProviderFactory;

  @Inject
  private SignatureInfo signatureInfo;

  @Override
  public void filter(ContainerRequestContext context) throws IOException {
    if (!authProviderFactory.isStrictLocalAuthEnabled()) {
      return;
    }

    try {
      rejectPresignedUrl(context);

      S3GatewayAuthProvider authProvider = authProviderFactory.getProvider();
      S3Principal principal = authProvider.authenticate(context, signatureInfo);
      S3GatewayAuthRequest request = S3GatewayAuthRequest.fromContext(context);
      authProvider.authorize(principal, request.getAction(),
          request.getBucket(), request.getKeyOrPrefix());
      authorizeCopySourceIfNeeded(context, authProvider, principal);

      context.setProperty(S3Principal.CONTEXT_PROPERTY, principal);
    } catch (OS3Exception ex) {
      throw wrapOS3Exception(ex);
    } catch (RuntimeException ex) {
      LOG.debug("Local S3 Gateway auth failed", ex);
      throw wrapOS3Exception(S3ErrorTable.newError(ACCESS_DENIED));
    }
  }

  private void rejectPresignedUrl(ContainerRequestContext context) {
    if (context.getHeaderString(HttpHeaders.AUTHORIZATION) == null
        && (context.getUriInfo().getQueryParameters()
            .containsKey("X-Amz-Algorithm")
            || context.getUriInfo().getQueryParameters()
            .containsKey("X-Amz-Signature"))) {
      OS3Exception ex = S3ErrorTable.newError(NOT_IMPLEMENTED,
          "presigned-url");
      ex.setErrorMessage("Presigned URL authentication is not supported by "
          + "S3 Gateway local authentication.");
      throw ex;
    }
  }

  private void authorizeCopySourceIfNeeded(ContainerRequestContext context,
      S3GatewayAuthProvider authProvider, S3Principal principal) {
    String copySource = context.getHeaderString(COPY_SOURCE_HEADER);
    if (StringUtils.isBlank(copySource)) {
      return;
    }

    S3GatewayAuthRequest request = S3GatewayAuthRequest.fromContext(context);
    if (request.getAction() != S3Action.PUT_OBJECT
        && request.getAction() != S3Action.UPLOAD_PART) {
      return;
    }

    SourceObject source = parseCopySource(copySource);
    authProvider.authorize(principal, S3Action.GET_OBJECT,
        source.bucket, source.key);
  }

  private SourceObject parseCopySource(String copySource) {
    String normalized = StringUtils.removeStart(copySource, "/");
    int slash = normalized.indexOf('/');
    if (slash <= 0 || slash == normalized.length() - 1) {
      throw S3ErrorTable.newError(ACCESS_DENIED, copySource);
    }
    try {
      return new SourceObject(normalized.substring(0, slash),
          S3Utils.urlDecode(normalized.substring(slash + 1)));
    } catch (UnsupportedEncodingException ex) {
      throw S3ErrorTable.newError(ACCESS_DENIED, copySource, ex);
    }
  }

  private static final class SourceObject {
    private final String bucket;
    private final String key;

    private SourceObject(String bucket, String key) {
      this.bucket = bucket;
      this.key = key;
    }
  }
}
