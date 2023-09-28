// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2012-2014 Monty Program Ab
// Copyright (c) 2015-2023 MariaDB Corporation Ab

package org.mariadb.jdbc.client.tls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * Class to accept any server certificate.
 *
 * <p>This permit to have network encrypted, BUT client doesn't validate server identity !!
 */
public class MariaDbX509EphemeralTrustingManager implements X509TrustManager {
  X509TrustManager internal;
  byte[] fingerprint = null;

  /** Constructor */
  public MariaDbX509EphemeralTrustingManager(X509TrustManager javaTrustManager) {
    internal = javaTrustManager;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] x509Certificates, String string)
      throws CertificateException {
    internal.checkClientTrusted(x509Certificates, string);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] x509Certificates, String string)
      throws CertificateException {
    try {
      internal.checkServerTrusted(x509Certificates, string);
    } catch (CertificateException e) {
      try {
        fingerprint = getThumbprint(x509Certificates[0], "SHA-256");
      } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
        throw e;
      }
    }
  }

  public byte[] getFingerprint() {
    return fingerprint;
  }

  private static byte[] getThumbprint(X509Certificate cert, String algorithm)
      throws NoSuchAlgorithmException, CertificateEncodingException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    byte[] der = cert.getEncoded();
    md.update(der);
    return md.digest();
  }

  public X509Certificate[] getAcceptedIssuers() {
    return null;
  }
}
