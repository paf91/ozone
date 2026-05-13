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

import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MultivaluedMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;

/**
 * S3 action and resource resolved from a gateway HTTP request.
 */
final class S3GatewayAuthRequest {
  private static final String LOCATION_QUERY_PARAM = "location";

  private final S3Action action;
  private final String bucket;
  private final String keyOrPrefix;

  private S3GatewayAuthRequest(S3Action action, String bucket,
      String keyOrPrefix) {
    this.action = action;
    this.bucket = bucket;
    this.keyOrPrefix = keyOrPrefix;
  }

  S3Action getAction() {
    return action;
  }

  String getBucket() {
    return bucket;
  }

  String getKeyOrPrefix() {
    return keyOrPrefix;
  }

  static S3GatewayAuthRequest fromContext(ContainerRequestContext context) {
    Resource resource = parseResource(context);
    MultivaluedMap<String, String> query =
        context.getUriInfo().getQueryParameters();
    String method = context.getMethod();

    if (StringUtils.isEmpty(resource.bucket)) {
      if (HttpMethod.GET.equals(method)) {
        return new S3GatewayAuthRequest(S3Action.LIST_ALL_MY_BUCKETS,
            "*", null);
      }
      return unknown();
    }

    if (StringUtils.isEmpty(resource.key)) {
      return bucketRequest(method, query, resource.bucket);
    }
    return objectRequest(method, query, resource.bucket, resource.key);
  }

  private static S3GatewayAuthRequest bucketRequest(String method,
      MultivaluedMap<String, String> query, String bucket) {
    if (HttpMethod.GET.equals(method)) {
      if (query.containsKey(QueryParams.ACL)) {
        return new S3GatewayAuthRequest(S3Action.GET_BUCKET_ACL, bucket, null);
      }
      if (query.containsKey(QueryParams.UPLOADS)) {
        return new S3GatewayAuthRequest(S3Action.LIST_MULTIPART_UPLOADS,
            bucket, query.getFirst(QueryParams.PREFIX));
      }
      if (query.containsKey(LOCATION_QUERY_PARAM)) {
        return new S3GatewayAuthRequest(S3Action.GET_BUCKET_LOCATION,
            bucket, null);
      }
      return new S3GatewayAuthRequest(S3Action.LIST_BUCKET, bucket,
          StringUtils.defaultString(query.getFirst(QueryParams.PREFIX)));
    } else if (HttpMethod.HEAD.equals(method)) {
      return new S3GatewayAuthRequest(S3Action.HEAD_BUCKET, bucket, null);
    } else if (HttpMethod.PUT.equals(method)) {
      if (query.containsKey(QueryParams.ACL)) {
        return new S3GatewayAuthRequest(S3Action.PUT_BUCKET_ACL, bucket, null);
      }
      return new S3GatewayAuthRequest(S3Action.CREATE_BUCKET, bucket, null);
    } else if (HttpMethod.DELETE.equals(method)) {
      return new S3GatewayAuthRequest(S3Action.DELETE_BUCKET, bucket, null);
    } else if (HttpMethod.POST.equals(method)
        && query.containsKey(QueryParams.DELETE)) {
      return new S3GatewayAuthRequest(S3Action.DELETE_OBJECT, bucket, null);
    }
    return unknown();
  }

  private static S3GatewayAuthRequest objectRequest(String method,
      MultivaluedMap<String, String> query, String bucket, String key) {
    if (HttpMethod.GET.equals(method)) {
      if (query.containsKey(QueryParams.UPLOAD_ID)) {
        return new S3GatewayAuthRequest(
            S3Action.LIST_MULTIPART_UPLOAD_PARTS, bucket, key);
      }
      if (query.containsKey(QueryParams.TAGGING)) {
        return new S3GatewayAuthRequest(S3Action.GET_OBJECT_TAGGING,
            bucket, key);
      }
      return new S3GatewayAuthRequest(S3Action.GET_OBJECT, bucket, key);
    } else if (HttpMethod.HEAD.equals(method)) {
      return new S3GatewayAuthRequest(S3Action.HEAD_OBJECT, bucket, key);
    } else if (HttpMethod.PUT.equals(method)) {
      if (query.containsKey(QueryParams.UPLOAD_ID)) {
        return new S3GatewayAuthRequest(S3Action.UPLOAD_PART, bucket, key);
      }
      if (query.containsKey(QueryParams.ACL)) {
        return new S3GatewayAuthRequest(S3Action.PUT_OBJECT_ACL, bucket, key);
      }
      if (query.containsKey(QueryParams.TAGGING)) {
        return new S3GatewayAuthRequest(S3Action.PUT_OBJECT_TAGGING,
            bucket, key);
      }
      return new S3GatewayAuthRequest(S3Action.PUT_OBJECT, bucket, key);
    } else if (HttpMethod.DELETE.equals(method)) {
      if (query.containsKey(QueryParams.UPLOAD_ID)) {
        return new S3GatewayAuthRequest(S3Action.ABORT_MULTIPART_UPLOAD,
            bucket, key);
      }
      if (query.containsKey(QueryParams.TAGGING)) {
        return new S3GatewayAuthRequest(S3Action.DELETE_OBJECT_TAGGING,
            bucket, key);
      }
      return new S3GatewayAuthRequest(S3Action.DELETE_OBJECT, bucket, key);
    } else if (HttpMethod.POST.equals(method)) {
      if (query.containsKey(QueryParams.UPLOADS)) {
        return new S3GatewayAuthRequest(S3Action.CREATE_MULTIPART_UPLOAD,
            bucket, key);
      }
      if (query.containsKey(QueryParams.UPLOAD_ID)) {
        return new S3GatewayAuthRequest(S3Action.COMPLETE_MULTIPART_UPLOAD,
            bucket, key);
      }
    }
    return unknown();
  }

  private static S3GatewayAuthRequest unknown() {
    return new S3GatewayAuthRequest(null, null, null);
  }

  private static Resource parseResource(ContainerRequestContext context) {
    String path = context.getUriInfo().getPath();
    path = StringUtils.removeStart(path, "/");
    if (StringUtils.isEmpty(path)) {
      return new Resource(null, null);
    }
    int firstSlash = path.indexOf('/');
    if (firstSlash < 0) {
      return new Resource(path, null);
    }
    return new Resource(path.substring(0, firstSlash),
        path.substring(firstSlash + 1));
  }

  private static final class Resource {
    private final String bucket;
    private final String key;

    private Resource(String bucket, String key) {
      this.bucket = bucket;
      this.key = key;
    }
  }
}
