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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.apache.kerby.util.Hex;

/**
 * AWS Signature Version 4 verifier for local S3 Gateway credentials.
 */
final class S3GatewayLocalAuthSignature {
  private static final String HMAC_SHA256 = "HmacSHA256";
  private static final ThreadLocal<Mac> MAC = ThreadLocal.withInitial(() -> {
    try {
      return Mac.getInstance(HMAC_SHA256);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("Missing " + HMAC_SHA256, ex);
    }
  });

  private S3GatewayLocalAuthSignature() {
  }

  static boolean matches(String stringToSign, String providedSignature,
      String secretKey) {
    if (StringUtils.isAnyBlank(stringToSign, providedSignature, secretKey)) {
      return false;
    }
    String expectedSignature;
    try {
      expectedSignature = calculateSignature(stringToSign, secretKey);
    } catch (RuntimeException ex) {
      return false;
    }
    byte[] expected = expectedSignature.getBytes(StandardCharsets.UTF_8);
    byte[] provided = providedSignature.toLowerCase(Locale.ROOT)
        .getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(expected, provided);
  }

  static String calculateSignature(String stringToSign, String secretKey) {
    return Hex.encode(sign(getSigningKey(secretKey, stringToSign),
        stringToSign)).toLowerCase(Locale.ROOT);
  }

  private static byte[] getSigningKey(String secretKey, String stringToSign) {
    String[] stringToSignParts = stringToSign.split("\n", -1);
    if (stringToSignParts.length < 3) {
      throw new IllegalArgumentException("Invalid SigV4 string-to-sign");
    }
    String[] credentialScope = stringToSignParts[2].split("/", -1);
    if (credentialScope.length < 4) {
      throw new IllegalArgumentException("Invalid SigV4 credential scope");
    }

    byte[] kDate = sign(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8),
        credentialScope[0]);
    byte[] kRegion = sign(kDate, credentialScope[1]);
    byte[] kService = sign(kRegion, credentialScope[2]);
    return sign(kService, "aws4_request");
  }

  private static byte[] sign(byte[] key, String message) {
    try {
      Mac mac = MAC.get();
      mac.init(new SecretKeySpec(key, HMAC_SHA256));
      return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("Unable to calculate SigV4 HMAC", ex);
    }
  }
}
