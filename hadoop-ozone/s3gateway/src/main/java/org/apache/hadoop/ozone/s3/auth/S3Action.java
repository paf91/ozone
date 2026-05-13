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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Local S3 Gateway authorization actions.
 */
public enum S3Action {
  LIST_ALL_MY_BUCKETS("ListAllMyBuckets"),
  HEAD_BUCKET("HeadBucket"),
  CREATE_BUCKET("CreateBucket"),
  DELETE_BUCKET("DeleteBucket"),
  LIST_BUCKET("ListBucket"),
  GET_BUCKET_LOCATION("GetBucketLocation"),
  GET_OBJECT("GetObject"),
  HEAD_OBJECT("HeadObject"),
  PUT_OBJECT("PutObject"),
  DELETE_OBJECT("DeleteObject"),
  CREATE_MULTIPART_UPLOAD("CreateMultipartUpload"),
  UPLOAD_PART("UploadPart"),
  LIST_MULTIPART_UPLOAD_PARTS("ListMultipartUploadParts"),
  COMPLETE_MULTIPART_UPLOAD("CompleteMultipartUpload"),
  ABORT_MULTIPART_UPLOAD("AbortMultipartUpload"),
  LIST_MULTIPART_UPLOADS("ListMultipartUploads"),
  GET_BUCKET_ACL("GetBucketAcl"),
  PUT_BUCKET_ACL("PutBucketAcl"),
  GET_OBJECT_TAGGING("GetObjectTagging"),
  PUT_OBJECT_TAGGING("PutObjectTagging"),
  DELETE_OBJECT_TAGGING("DeleteObjectTagging"),
  PUT_OBJECT_ACL("PutObjectAcl");

  private static final Map<String, S3Action> BY_ACTION_NAME = new HashMap<>();

  static {
    for (S3Action action : values()) {
      BY_ACTION_NAME.put(action.actionName, action);
    }
  }

  private final String actionName;

  S3Action(String actionName) {
    this.actionName = actionName;
  }

  public String getActionName() {
    return actionName;
  }

  public static Optional<S3Action> fromActionName(String actionName) {
    return Optional.ofNullable(BY_ACTION_NAME.get(actionName));
  }
}
