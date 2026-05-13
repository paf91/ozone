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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.s3.S3GatewayConfigKeys;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo.Version;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for local S3 Gateway SigV4 authentication.
 */
public class TestLocalFileS3GatewayAuthProvider {
  private static final String ACCESS_KEY = "taiga";
  private static final String SECRET_KEY = "taiga-secret";
  private static final String STRING_TO_SIGN = "AWS4-HMAC-SHA256\n"
      + "20260513T000000Z\n"
      + "20260513/us-east-1/s3/aws4_request\n"
      + "0000000000000000000000000000000000000000000000000000000000000000";

  @TempDir
  private Path tempDir;

  @Test
  public void validSigV4RequestPasses() throws Exception {
    LocalFileS3GatewayAuthProvider provider = providerWithCredentials();

    S3Principal principal = provider.authenticate(null,
        signatureInfo(ACCESS_KEY, SECRET_KEY));

    assertThat(principal.getAccessKey()).isEqualTo(ACCESS_KEY);
  }

  @Test
  public void wrongSecretFailsSignatureValidation() throws Exception {
    LocalFileS3GatewayAuthProvider provider = providerWithCredentials();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> provider.authenticate(null,
            signatureInfo(ACCESS_KEY, "wrong-secret")));

    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.SIGNATURE_DOES_NOT_MATCH
        .getCode());
  }

  @Test
  public void unknownAccessKeyFails() throws Exception {
    LocalFileS3GatewayAuthProvider provider = providerWithCredentials();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> provider.authenticate(null,
            signatureInfo("unknown", SECRET_KEY)));

    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.INVALID_ACCESS_KEY_ID
        .getCode());
  }

  @Test
  public void missingAuthorizationFailsInStrictMode() throws Exception {
    LocalFileS3GatewayAuthProvider provider = providerWithCredentials();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> provider.authenticate(null,
            new SignatureInfo.Builder(Version.NONE).build()));

    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.MISSING_SECURITY_HEADER
        .getCode());
  }

  @Test
  public void disabledLocalAuthUsesNoopProvider() {
    OzoneConfiguration conf = new OzoneConfiguration();
    LocalFileS3GatewayAuthProvider localProvider =
        new LocalFileS3GatewayAuthProvider(conf);
    localProvider.initialize();

    S3GatewayAuthProviderFactory factory =
        new S3GatewayAuthProviderFactory(conf, localProvider);

    assertThat(factory.isStrictLocalAuthEnabled()).isFalse();
    assertThat(factory.getProvider())
        .isInstanceOf(NoopS3GatewayAuthProvider.class);
  }

  private LocalFileS3GatewayAuthProvider providerWithCredentials()
      throws IOException {
    Path file = tempDir.resolve("s3g-credentials.json");
    Files.write(file, validJson().getBytes(UTF_8));

    OzoneConfiguration conf = new OzoneConfiguration();
    conf.setBoolean(S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_ENABLED, true);
    conf.set(S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_CREDENTIALS_FILE,
        file.toString());
    conf.set(S3GatewayConfigKeys.OZONE_S3G_LOCAL_AUTH_RELOAD_INTERVAL, "0");

    LocalFileS3GatewayAuthProvider provider =
        new LocalFileS3GatewayAuthProvider(conf);
    provider.initialize();
    return provider;
  }

  private SignatureInfo signatureInfo(String accessKey, String secretKey) {
    return new SignatureInfo.Builder(Version.V4)
        .setAwsAccessId(accessKey)
        .setSignature(S3GatewayLocalAuthSignature.calculateSignature(
            STRING_TO_SIGN, secretKey))
        .setStringToSign(STRING_TO_SIGN)
        .build();
  }

  private String validJson() {
    return "{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [\n"
        + "    {\"accessKey\":\"" + ACCESS_KEY + "\","
        + "\"secretKey\":\"" + SECRET_KEY + "\","
        + "\"enabled\":true,\"allow\":[\n"
        + "      {\"bucket\":\"taiga-files\",\"prefix\":\"*\","
        + "\"actions\":[\"PutObject\"]}\n"
        + "    ]}\n"
        + "  ]\n"
        + "}";
  }
}
