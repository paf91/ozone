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
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.MISSING_SECURITY_HEADER;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.S3_AUTHINFO_CREATION_ERROR;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.SIGNATURE_DOES_NOT_MATCH;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.container.ContainerRequestContext;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo.Version;
import org.apache.hadoop.util.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Local JSON file backed S3 Gateway auth provider.
 */
@Singleton
public class LocalFileS3GatewayAuthProvider implements S3GatewayAuthProvider {
  private static final Logger LOG =
      LoggerFactory.getLogger(LocalFileS3GatewayAuthProvider.class);

  private final OzoneConfiguration conf;
  private final AtomicReference<LocalS3CredentialStore> store =
      new AtomicReference<>(LocalS3CredentialStore.empty());
  private final AtomicLong nextReloadTimeMillis = new AtomicLong();

  private volatile Path credentialsFile;
  private volatile long reloadIntervalMillis;
  private volatile boolean allowListAllBuckets;
  private volatile boolean strictLocalAuthEnabled;
  private volatile boolean failOnInvalidConfig;
  private volatile boolean invalidSnapshot;

  @Inject
  public LocalFileS3GatewayAuthProvider(OzoneConfiguration conf) {
    this.conf = conf;
  }

  @PostConstruct
  public void initialize() {
    try {
      configure();
      if (strictLocalAuthEnabled) {
        reload(true);
      }
    } catch (IOException ex) {
      if (failOnInvalidConfig) {
        throw new IllegalStateException(
            "Invalid S3 Gateway local auth configuration", ex);
      }
      LOG.warn("S3 Gateway local auth configuration is invalid; requests "
          + "will fail closed until it is fixed: {}", ex.getMessage());
      invalidSnapshot = true;
    }
  }

  @Override
  public S3Principal authenticate(ContainerRequestContext context,
      SignatureInfo signatureInfo) throws OS3Exception {
    LocalS3CredentialStore currentStore = currentStore();

    if (signatureInfo == null || signatureInfo.getVersion() == Version.NONE) {
      throw S3ErrorTable.newError(MISSING_SECURITY_HEADER, "Authorization");
    }
    if (signatureInfo.getVersion() != Version.V4) {
      throw S3ErrorTable.newError(S3_AUTHINFO_CREATION_ERROR,
          String.valueOf(signatureInfo.getVersion()));
    }

    String accessKey = signatureInfo.getAwsAccessId();
    String providedSignature = signatureInfo.getSignature();
    String stringToSign = signatureInfo.getStringToSign();
    if (StringUtils.isAnyBlank(accessKey, providedSignature, stringToSign)) {
      throw S3ErrorTable.newError(ACCESS_DENIED);
    }

    String secretKey = currentStore.getSecretKey(accessKey);
    if (!S3GatewayLocalAuthSignature.matches(stringToSign, providedSignature,
        secretKey)) {
      throw S3ErrorTable.newError(SIGNATURE_DOES_NOT_MATCH, accessKey);
    }
    return currentStore.authenticate(accessKey);
  }

  @Override
  public void authorize(S3Principal principal, S3Action action, String bucket,
      String keyOrPrefix) throws OS3Exception {
    if (principal != null && action == S3Action.LIST_ALL_MY_BUCKETS
        && allowListAllBuckets) {
      return;
    }
    currentStore().authorize(principal, action, bucket, keyOrPrefix);
  }

  private void configure() throws IOException {
    strictLocalAuthEnabled =
        S3GatewayLocalAuthConfig.isStrictLocalAuthEnabled(conf);
    failOnInvalidConfig = S3GatewayLocalAuthConfig.failOnInvalidConfig(conf);
    if (!strictLocalAuthEnabled) {
      return;
    }
    S3GatewayLocalAuthConfig.validateStartupConfiguration(conf);
    credentialsFile = S3GatewayLocalAuthConfig.credentialsFile(conf);
    reloadIntervalMillis = S3GatewayLocalAuthConfig.reloadIntervalMillis(conf);
    allowListAllBuckets = S3GatewayLocalAuthConfig.allowListAllBuckets(conf);
  }

  private LocalS3CredentialStore currentStore() throws OS3Exception {
    if (!strictLocalAuthEnabled) {
      return LocalS3CredentialStore.empty();
    }

    if (reloadIntervalMillis > 0) {
      long now = Time.monotonicNow();
      long next = nextReloadTimeMillis.get();
      if (now >= next && nextReloadTimeMillis.compareAndSet(next,
          now + reloadIntervalMillis)) {
        try {
          reload(false);
        } catch (IOException ex) {
          store.set(LocalS3CredentialStore.empty());
          invalidSnapshot = true;
          LOG.warn("Failed to reload S3 Gateway local auth credentials; "
              + "requests will fail closed: {}", ex.getMessage());
        }
      }
    }

    if (invalidSnapshot) {
      OS3Exception ex = S3ErrorTable.newError(ACCESS_DENIED);
      ex.setErrorMessage("S3 Gateway local authentication is unavailable "
          + "because the credential configuration is invalid.");
      throw ex;
    }
    return store.get();
  }

  private void reload(boolean startup) throws IOException {
    LocalS3CredentialStore loaded =
        LocalS3CredentialStore.load(credentialsFile);
    store.set(loaded);
    invalidSnapshot = false;
    if (reloadIntervalMillis > 0) {
      nextReloadTimeMillis.set(Time.monotonicNow() + reloadIntervalMillis);
    }
    if (startup) {
      LOG.info("Loaded S3 Gateway local auth credentials from {} with {} "
          + "enabled users", credentialsFile, loaded.size());
    } else {
      LOG.debug("Reloaded S3 Gateway local auth credentials from {} with {} "
          + "enabled users", credentialsFile, loaded.size());
    }
  }
}
