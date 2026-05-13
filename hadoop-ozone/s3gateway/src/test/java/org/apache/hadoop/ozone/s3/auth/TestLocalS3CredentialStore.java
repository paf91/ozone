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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for local S3 credential file parsing and authorization.
 */
public class TestLocalS3CredentialStore {
  private static final String SECRET = "taiga-secret";

  @TempDir
  private Path tempDir;

  @Test
  public void validConfigLoadsEnabledUsers() throws Exception {
    LocalS3CredentialStore store = load(validJson());

    S3Principal principal = store.authenticate("taiga");

    assertThat(principal.getAccessKey()).isEqualTo("taiga");
    assertThat(principal.getPrincipal()).isEqualTo("taiga");
    assertThat(principal.getDisplayName()).isEqualTo("taiga service user");
    assertThat(store.size()).isEqualTo(1);
  }

  @Test
  public void duplicateAccessKeyFails() {
    IOException ex = assertThrows(IOException.class, () -> load("{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [\n"
        + "    {\"accessKey\":\"taiga\",\"secretKey\":\"" + SECRET
        + "\",\"enabled\":true},\n"
        + "    {\"accessKey\":\"taiga\",\"secretKey\":\"other\","
        + "\"enabled\":false}\n"
        + "  ]\n"
        + "}"));

    assertThat(ex.getMessage()).contains("Duplicate local S3 accessKey");
    assertThat(ex.getMessage()).doesNotContain(SECRET);
  }

  @Test
  public void missingSecretKeyFails() {
    IOException ex = assertThrows(IOException.class, () -> load("{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [ {\"accessKey\":\"taiga\",\"enabled\":true} ]\n"
        + "}"));

    assertThat(ex.getMessage()).contains("missing secretKey");
  }

  @Test
  public void disabledUserIsIgnored() throws Exception {
    LocalS3CredentialStore store = load("{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [\n"
        + "    {\"accessKey\":\"disabled\",\"secretKey\":\"" + SECRET
        + "\",\"enabled\":false}\n"
        + "  ]\n"
        + "}");

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> store.authenticate("disabled"));
    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.INVALID_ACCESS_KEY_ID
        .getCode());
  }

  @Test
  public void invalidJsonFailsWithoutSecretInMessage() {
    IOException ex = assertThrows(IOException.class, () -> load("{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [{\"accessKey\":\"taiga\","
        + "\"secretKey\":\"" + SECRET + "\"\n"
        + "}"));

    assertThat(ex.getMessage()).contains("Invalid local S3 credential file");
    assertThat(ex.toString()).doesNotContain(SECRET);
  }

  @Test
  public void allowedUserCanPutObjectInConfiguredBucket() throws Exception {
    LocalS3CredentialStore store = load(validJson());
    S3Principal principal = store.authenticate("taiga");

    assertDoesNotThrow(() -> store.authorize(principal, S3Action.PUT_OBJECT,
        "taiga-files", "docs/file.txt"));
  }

  @Test
  public void sameUserDeniedOnOtherBucket() throws Exception {
    LocalS3CredentialStore store = load(validJson());
    S3Principal principal = store.authenticate("taiga");

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> store.authorize(principal, S3Action.PUT_OBJECT,
            "other-bucket", "docs/file.txt"));
    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.ACCESS_DENIED.getCode());
  }

  @Test
  public void sameUserDeniedForActionNotListed() throws Exception {
    LocalS3CredentialStore store = load(validJson());
    S3Principal principal = store.authenticate("taiga");

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> store.authorize(principal, S3Action.DELETE_OBJECT,
            "taiga-files", "docs/file.txt"));
    assertThat(ex.getCode()).isEqualTo(S3ErrorTable.ACCESS_DENIED.getCode());
  }

  @Test
  public void prefixRestrictionWorks() throws Exception {
    LocalS3CredentialStore store = load(validJson());
    S3Principal principal = store.authenticate("taiga");

    assertDoesNotThrow(() -> store.authorize(principal, S3Action.GET_OBJECT,
        "taiga-files", "docs/file.txt"));
    assertDoesNotThrow(() -> store.authorize(principal, S3Action.LIST_BUCKET,
        "taiga-files", "docs/"));

    assertThrows(OS3Exception.class, () -> store.authorize(principal,
        S3Action.GET_OBJECT, "taiga-files", "private/file.txt"));
    assertThrows(OS3Exception.class, () -> store.authorize(principal,
        S3Action.LIST_BUCKET, "taiga-files", ""));
  }

  @Test
  public void wildcardBucketWorksOnlyWhenExplicitlyConfigured()
      throws Exception {
    LocalS3CredentialStore store = load("{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [\n"
        + "    {\"accessKey\":\"wild\",\"secretKey\":\"" + SECRET
        + "\",\"enabled\":true,\"allow\":[\n"
        + "      {\"bucket\":\"*\",\"prefix\":\"*\","
        + "\"actions\":[\"HeadBucket\"]}\n"
        + "    ]},\n"
        + "    {\"accessKey\":\"plain\",\"secretKey\":\"" + SECRET
        + "\",\"enabled\":true,\"allow\":[\n"
        + "      {\"bucket\":\"taiga-files\",\"prefix\":\"*\","
        + "\"actions\":[\"HeadBucket\"]}\n"
        + "    ]}\n"
        + "  ]\n"
        + "}");

    assertDoesNotThrow(() -> store.authorize(store.authenticate("wild"),
        S3Action.HEAD_BUCKET, "other-bucket", null));
    assertThrows(OS3Exception.class, () -> store.authorize(
        store.authenticate("plain"), S3Action.HEAD_BUCKET,
        "other-bucket", null));
  }

  private LocalS3CredentialStore load(String json) throws IOException {
    Path file = tempDir.resolve("s3g-credentials.json");
    Files.write(file, json.getBytes(UTF_8));
    return LocalS3CredentialStore.load(file);
  }

  private String validJson() {
    return "{\n"
        + "  \"version\": 1,\n"
        + "  \"users\": [\n"
        + "    {\n"
        + "      \"accessKey\": \"taiga\",\n"
        + "      \"secretKey\": \"" + SECRET + "\",\n"
        + "      \"displayName\": \"taiga service user\",\n"
        + "      \"enabled\": true,\n"
        + "      \"allow\": [\n"
        + "        {\"bucket\":\"taiga-files\",\"prefix\":\"docs/\","
        + "\"actions\":[\"ListBucket\",\"GetObject\",\"PutObject\"]}\n"
        + "      ]\n"
        + "    }\n"
        + "  ]\n"
        + "}";
  }
}
