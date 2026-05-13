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

import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_ALLOW_LIST_ALL_BUCKETS;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_ALLOW_LIST_ALL_BUCKETS_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_PERMISSIVE;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_STRICT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_ENABLED;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_ENABLED_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_FAIL_ON_INVALID_CONFIG;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_FAIL_ON_INVALID_CONFIG_DEFAULT;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL;
import static org.apache.hadoop.ozone.s3.S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL_DEFAULT;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.OzoneSecurityUtil;

/**
 * Configuration helpers for local S3 Gateway authentication.
 */
public final class S3GatewayLocalAuthConfig {
  private S3GatewayLocalAuthConfig() {
  }

  public static boolean isLocalAuthEnabled(OzoneConfiguration conf) {
    return conf.getBoolean(OZONE_S3G_LOCAL_AUTH_ENABLED,
        OZONE_S3G_LOCAL_AUTH_ENABLED_DEFAULT);
  }

  public static boolean isStrictLocalAuthEnabled(OzoneConfiguration conf) {
    return isLocalAuthEnabled(conf) && !isPermissive(conf);
  }

  public static boolean failOnInvalidConfig(OzoneConfiguration conf) {
    return conf.getBoolean(OZONE_S3G_LOCAL_AUTH_FAIL_ON_INVALID_CONFIG,
        OZONE_S3G_LOCAL_AUTH_FAIL_ON_INVALID_CONFIG_DEFAULT);
  }

  public static boolean allowListAllBuckets(OzoneConfiguration conf) {
    return conf.getBoolean(OZONE_S3G_LOCAL_AUTH_ALLOW_LIST_ALL_BUCKETS,
        OZONE_S3G_LOCAL_AUTH_ALLOW_LIST_ALL_BUCKETS_DEFAULT);
  }

  public static long reloadIntervalMillis(OzoneConfiguration conf)
      throws IOException {
    long interval = conf.getTimeDuration(OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL,
        OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL_DEFAULT, TimeUnit.MILLISECONDS);
    if (interval < 0) {
      throw new IOException(OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL
          + " must be greater than or equal to 0");
    }
    return interval;
  }

  public static Path credentialsFile(OzoneConfiguration conf)
      throws IOException {
    String file = conf.getTrimmed(OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE,
        OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE_DEFAULT);
    if (StringUtils.isBlank(file)) {
      throw new IOException(OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE
          + " must be set when local S3 Gateway authentication is enabled");
    }
    return Paths.get(file);
  }

  public static void validateStartupConfiguration(OzoneConfiguration conf)
      throws IOException {
    if (!isLocalAuthEnabled(conf)) {
      return;
    }

    validateCompatibilityMode(conf);
    if (OzoneSecurityUtil.isSecurityEnabled(conf)) {
      throw new IOException(OZONE_S3G_LOCAL_AUTH_ENABLED
          + " cannot be enabled when ozone.security.enabled=true");
    }

    if (isStrictLocalAuthEnabled(conf) && failOnInvalidConfig(conf)) {
      LocalS3CredentialStore.load(credentialsFile(conf));
      reloadIntervalMillis(conf);
    }
  }

  static boolean isPermissive(OzoneConfiguration conf) {
    return OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_PERMISSIVE.equals(
        compatibilityMode(conf));
  }

  private static String compatibilityMode(OzoneConfiguration conf) {
    return conf.getTrimmed(OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE,
            OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_DEFAULT)
        .toLowerCase(Locale.ROOT);
  }

  private static void validateCompatibilityMode(OzoneConfiguration conf)
      throws IOException {
    String mode = compatibilityMode(conf);
    if (!OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_STRICT.equals(mode)
        && !OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_PERMISSIVE.equals(mode)) {
      throw new IOException(OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE
          + " must be one of: "
          + OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_STRICT + ", "
          + OZONE_S3G_LOCAL_AUTH_COMPATIBILITY_MODE_PERMISSIVE);
    }
  }
}
