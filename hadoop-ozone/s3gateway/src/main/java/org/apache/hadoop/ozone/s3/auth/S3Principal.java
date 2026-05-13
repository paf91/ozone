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

import java.util.Objects;
import javax.ws.rs.container.ContainerRequestContext;

/**
 * S3 principal authenticated by the S3 Gateway.
 */
public final class S3Principal {
  public static final String CONTEXT_PROPERTY =
      S3Principal.class.getName() + ".principal";

  private final String accessKey;
  private final String principal;
  private final String displayName;

  public S3Principal(String accessKey, String principal, String displayName) {
    this.accessKey = Objects.requireNonNull(accessKey);
    this.principal = Objects.requireNonNull(principal);
    this.displayName = displayName == null ? principal : displayName;
  }

  public String getAccessKey() {
    return accessKey;
  }

  public String getPrincipal() {
    return principal;
  }

  public String getDisplayName() {
    return displayName;
  }

  public static S3Principal fromContext(ContainerRequestContext context) {
    if (context == null) {
      return null;
    }
    Object value = context.getProperty(CONTEXT_PROPERTY);
    return value instanceof S3Principal ? (S3Principal) value : null;
  }
}
