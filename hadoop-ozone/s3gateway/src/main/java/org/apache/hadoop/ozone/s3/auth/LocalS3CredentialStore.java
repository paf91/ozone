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
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.INVALID_ACCESS_KEY_ID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;

/**
 * Immutable local S3 credentials and authorization snapshot.
 */
final class LocalS3CredentialStore {
  private static final ObjectMapper MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private static final LocalS3CredentialStore EMPTY =
      new LocalS3CredentialStore(Collections.emptyMap());

  private final Map<String, UserRecord> usersByAccessKey;

  private LocalS3CredentialStore(Map<String, UserRecord> usersByAccessKey) {
    this.usersByAccessKey = usersByAccessKey;
  }

  static LocalS3CredentialStore empty() {
    return EMPTY;
  }

  static LocalS3CredentialStore load(Path file) throws IOException {
    if (file == null) {
      throw new IOException("Local S3 credential file path is not set");
    }
    if (!Files.isRegularFile(file)) {
      throw new IOException("Local S3 credential file does not exist: " + file);
    }

    final CredentialFile credentialFile;
    try {
      credentialFile = MAPPER.readValue(file.toFile(), CredentialFile.class);
    } catch (JsonProcessingException ex) {
      throw new IOException("Invalid local S3 credential file JSON");
    }

    return fromCredentialFile(credentialFile);
  }

  S3Principal authenticate(String accessKey) throws OS3Exception {
    UserRecord user = usersByAccessKey.get(accessKey);
    if (user == null) {
      throw S3ErrorTable.newError(INVALID_ACCESS_KEY_ID, accessKey);
    }
    return user.toPrincipal();
  }

  String getSecretKey(String accessKey) throws OS3Exception {
    UserRecord user = usersByAccessKey.get(accessKey);
    if (user == null) {
      throw S3ErrorTable.newError(INVALID_ACCESS_KEY_ID, accessKey);
    }
    return user.secretKey;
  }

  void authorize(S3Principal principal, S3Action action, String bucket,
      String keyOrPrefix) throws OS3Exception {
    if (principal == null || action == null) {
      throw S3ErrorTable.newError(ACCESS_DENIED, bucket);
    }

    UserRecord user = usersByAccessKey.get(principal.getAccessKey());
    if (user == null) {
      throw S3ErrorTable.newError(INVALID_ACCESS_KEY_ID,
          principal.getAccessKey());
    }

    for (Rule rule : user.allowRules) {
      if (rule.allows(action, bucket, keyOrPrefix)) {
        return;
      }
    }
    throw S3ErrorTable.newError(ACCESS_DENIED, bucket);
  }

  int size() {
    return usersByAccessKey.size();
  }

  private static LocalS3CredentialStore fromCredentialFile(
      CredentialFile file) throws IOException {
    if (file == null) {
      throw new IOException("Local S3 credential file is empty");
    }
    if (file.version != 1) {
      throw new IOException("Unsupported local S3 credential file version");
    }
    if (file.users == null || file.users.isEmpty()) {
      throw new IOException("Local S3 credential file must contain users");
    }

    Map<String, UserRecord> users = new HashMap<>();
    Set<String> allAccessKeys = new HashSet<>();
    for (CredentialUser user : file.users) {
      validateUser(user);

      if (!allAccessKeys.add(user.accessKey)) {
        throw new IOException("Duplicate local S3 accessKey: "
            + user.accessKey);
      }

      if (Boolean.FALSE.equals(user.enabled)) {
        continue;
      }

      String principal = StringUtils.defaultIfBlank(user.principal,
          user.accessKey);
      List<Rule> allowRules = parseRules(user.allow, user.accessKey);
      UserRecord record = new UserRecord(user.accessKey, user.secretKey,
          principal, user.displayName, allowRules);
      users.put(user.accessKey, record);
    }
    return new LocalS3CredentialStore(Collections.unmodifiableMap(users));
  }

  private static void validateUser(CredentialUser user) throws IOException {
    if (user == null) {
      throw new IOException("Local S3 credential user entry is null");
    }
    if (StringUtils.isBlank(user.accessKey)) {
      throw new IOException("Local S3 credential user is missing accessKey");
    }
    if (StringUtils.isBlank(user.secretKey)) {
      throw new IOException("Local S3 credential user " + user.accessKey
          + " is missing secretKey");
    }
  }

  private static List<Rule> parseRules(List<CredentialRule> rawRules,
      String accessKey) throws IOException {
    if (rawRules == null || rawRules.isEmpty()) {
      return Collections.emptyList();
    }

    List<Rule> result = new ArrayList<>();
    for (CredentialRule rawRule : rawRules) {
      if (rawRule == null) {
        throw new IOException("Local S3 allow rule is null for accessKey "
            + accessKey);
      }
      if (StringUtils.isBlank(rawRule.bucket)) {
        throw new IOException("Local S3 allow rule is missing bucket for "
            + "accessKey " + accessKey);
      }
      String prefix = StringUtils.defaultIfBlank(rawRule.prefix, "*");
      if (rawRule.actions == null || rawRule.actions.isEmpty()) {
        throw new IOException("Local S3 allow rule is missing actions for "
            + "accessKey " + accessKey);
      }

      EnumSet<S3Action> actions = EnumSet.noneOf(S3Action.class);
      for (String actionName : rawRule.actions) {
        S3Action action = S3Action.fromActionName(actionName)
            .orElseThrow(() -> new IOException("Unknown local S3 action "
                + actionName + " for accessKey " + accessKey));
        actions.add(action);
      }
      result.add(new Rule(rawRule.bucket, prefix,
          Collections.unmodifiableSet(actions)));
    }
    return Collections.unmodifiableList(result);
  }

  private static final class UserRecord {
    private final String accessKey;
    private final String secretKey;
    private final String principal;
    private final String displayName;
    private final List<Rule> allowRules;

    private UserRecord(String accessKey, String secretKey, String principal,
        String displayName, List<Rule> allowRules) {
      this.accessKey = accessKey;
      this.secretKey = secretKey;
      this.principal = principal;
      this.displayName = displayName;
      this.allowRules = allowRules;
    }

    private S3Principal toPrincipal() {
      return new S3Principal(accessKey, principal, displayName);
    }
  }

  private static final class Rule {
    private static final String WILDCARD = "*";

    private final String bucket;
    private final String prefix;
    private final Set<S3Action> actions;

    private Rule(String bucket, String prefix, Set<S3Action> actions) {
      this.bucket = bucket;
      this.prefix = prefix;
      this.actions = actions;
    }

    private boolean allows(S3Action action, String requestBucket,
        String keyOrPrefix) {
      if (!actions.contains(action)) {
        return false;
      }
      if (!WILDCARD.equals(bucket) && !bucket.equals(requestBucket)) {
        return false;
      }
      if (action == S3Action.LIST_ALL_MY_BUCKETS) {
        return WILDCARD.equals(bucket);
      }
      if (!actionRequiresPrefix(action)) {
        return true;
      }
      return prefixMatches(keyOrPrefix);
    }

    private boolean prefixMatches(String keyOrPrefix) {
      if (WILDCARD.equals(prefix)) {
        return true;
      }
      return StringUtils.isNotEmpty(keyOrPrefix)
          && keyOrPrefix.startsWith(prefix);
    }

    private boolean actionRequiresPrefix(S3Action action) {
      switch (action) {
      case GET_OBJECT:
      case HEAD_OBJECT:
      case PUT_OBJECT:
      case DELETE_OBJECT:
      case CREATE_MULTIPART_UPLOAD:
      case UPLOAD_PART:
      case LIST_MULTIPART_UPLOAD_PARTS:
      case COMPLETE_MULTIPART_UPLOAD:
      case ABORT_MULTIPART_UPLOAD:
      case GET_OBJECT_TAGGING:
      case PUT_OBJECT_TAGGING:
      case DELETE_OBJECT_TAGGING:
      case PUT_OBJECT_ACL:
      case LIST_BUCKET:
      case LIST_MULTIPART_UPLOADS:
        return true;
      default:
        return false;
      }
    }
  }

  private static final class CredentialFile {
    public int version;
    public List<CredentialUser> users;
  }

  private static final class CredentialUser {
    public String accessKey;
    public String secretKey;
    public String principal;
    public String displayName;
    public Boolean enabled = true;
    public List<CredentialRule> allow;
  }

  private static final class CredentialRule {
    public String bucket;
    public String prefix;
    public List<String> actions;
  }
}
