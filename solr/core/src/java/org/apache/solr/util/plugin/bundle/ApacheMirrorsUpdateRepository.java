/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.solr.util.plugin.bundle;

import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.invoke.MethodHandles;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.solr.common.SolrException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.c02e.jpgpj.Ring;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ro.fortsoft.pf4j.PluginException;
import ro.fortsoft.pf4j.update.FileDownloader;
import ro.fortsoft.pf4j.update.SimpleFileDownloader;

/**
 * Update Repository that resolves Apache Mirros
 */
public class ApacheMirrorsUpdateRepository extends PluginUpdateRepository {
  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final String APACHE_DIST_URL = "https://www.apache.org/dist/";
  private static final String APACHE_ARCHIVE_URL = "https://archive.apache.org/dist/";
  private static final String CLOSER_URL = "https://www.apache.org/dyn/closer.lua?action=download&filename=";
  private String path;
  private FileDownloader downloader;
  private URL mirrorUrl;
  private boolean requireSignatureValidation = false;
  private boolean requireChecksumValidation = true;

  static {
    if(Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public ApacheMirrorsUpdateRepository(String id, String path) {
    super(id);
    this.path = path;
    try {
      this.mirrorUrl = new URL(CLOSER_URL + path);
    } catch (MalformedURLException e) {
      throw new SolrException(SolrException.ErrorCode.SERVER_ERROR, e);
    }
  }

  @Override
  protected URL resolveUrl() {
    try {
      mirrorUrl = getFinalURL(mirrorUrl);
      return mirrorUrl;
    } catch (IOException e) {
      log.debug("Url {} not found in mirrors, response={}",
          mirrorUrl, e.getMessage());
      try {
        mirrorUrl = getFinalURL(new URL(APACHE_DIST_URL + path));
        log.debug("Resolved URL: {}", mirrorUrl);
        return mirrorUrl;
      } catch (IOException e1) {
        log.debug("Url {} not found in main repo, response={}",
            mirrorUrl, e1.getMessage());
        try {
          mirrorUrl = getFinalURL(new URL(APACHE_ARCHIVE_URL + path));
          log.debug("Resolved URL: {}", mirrorUrl);
          return mirrorUrl;
        } catch (IOException e2) {
          log.debug("Url {} not found in archive repo, response={}",
              mirrorUrl, e2.getMessage());
          return null;
        }
      }
    }
  }

  @Override
  public FileDownloader getFileDownloader() {
    if (downloader == null) {
      downloader = new ApacheChecksumVerifyingDownloader();
    }
    return downloader;
  }

  /**
   * Static method that resolves final Apache mirrors URL, resolving redirects
   * @param url original URL
   * @return new URL which could be the same as the original or a new after redirects
   * @throws IOException if problems opening URL
   */
  public static URL getFinalURL(URL url) throws IOException {
      HttpURLConnection con = (HttpURLConnection) url.openConnection();
      con.setInstanceFollowRedirects(false);
      con.setRequestMethod("GET");
      con.connect();
      con.getInputStream();

      if (con.getResponseCode() == HttpURLConnection.HTTP_MOVED_PERM || con.getResponseCode() == HttpURLConnection.HTTP_MOVED_TEMP) {
          URL redirectUrl = new URL(con.getHeaderField("Location"));
          return getFinalURL(redirectUrl);
      }
      return url;
  }

  public boolean isRequireSignatureValidation() {
    return requireSignatureValidation;
  }

  public void setRequireSignatureValidation(boolean requireSignatureValidation) {
    this.requireSignatureValidation = requireSignatureValidation;
  }

  public void setRequireChecksumValidation(boolean requireChecksumValidation) {
    this.requireChecksumValidation = requireChecksumValidation;
  }

  public boolean isRequireChecksumValidation() {
    return requireChecksumValidation;
  }

  /**
   * FileDownloader that fails if the MD5 sum of the downloaded file does not match the one downloaded
   * from Apache archives, and if the PGP signature cannot be verified
   */
  private class ApacheChecksumVerifyingDownloader extends SimpleFileDownloader {
    /**
     * Succeeds if downloaded file exists and has same checksum as md5 file downloaded from Apache archive
     *
     * @param originalUrl    the source from which the file was downloaded
     * @param downloadedFile the path to the downloaded file
     * @throws PluginException if the validation failed
     */
    @Override
    protected void validateDownload(URL originalUrl, Path downloadedFile) throws PluginException {
      super.validateDownload(originalUrl, downloadedFile);
      if (isRequireChecksumValidation()) {
        validateMd5(originalUrl, downloadedFile);
      }
      // NOCOMMIT jrunscript -e 'exit (javax.crypto.Cipher.getMaxAllowedKeyLength("RC5") >= 256);'; echo $?
      if (!restrictedCryptography()) {
        validateSignature(originalUrl, downloadedFile);
      } else if (isRequireSignatureValidation()) {
        throw new PluginException("Failed PGP signature validation, please install Oracle JCE Unlimited Strength in your JRE/JDK");
      } else {
        log.warn("Skipping PGP signature validation since JCE Unlimited Strength is not installed in your system");
      }
    }

    private void validateMd5(URL originalUrl, Path downloadedFile) throws PluginException {
      try {
        String md5FileUrl = getMD5FileUrl(originalUrl.toString());
        String md5 = getAndParseMd5File(md5FileUrl);
        if (md5 == null) {
          throw new PluginException("Failed to fetch md5 of " + originalUrl + ", aborting");
        }
        if (!DigestUtils.md5Hex(Files.newInputStream(downloadedFile)).equalsIgnoreCase(md5)) {
          throw new PluginException("MD5 checksum of file " + originalUrl + " does not match the one from " + md5FileUrl + ", aborting");
        }
      } catch (IOException e) {
        throw new PluginException("Validation failed, could not read downloaded file " + downloadedFile, e);
      }
    }

    private void validateSignature(URL originalUrl, Path downloadedFile) throws PluginException {
      try {
        InputStream committerKeys, fileSignature;
        String keysFileUrl = getKeysFileUrl(originalUrl.toString());
        try {
          committerKeys = new URL(keysFileUrl).openStream();
        } catch (IOException e) {
          throw new PluginException("Validation failed, failed fetching KEYS file " + keysFileUrl, e);
        }
        String pgpFileUrl = getPgpSignatureUrl(originalUrl.toString());
        try {
          fileSignature = new URL(pgpFileUrl).openStream();
        } catch (IOException e) {
          throw new PluginException("Validation failed, failed fetching signature file " + pgpFileUrl, e);
        }
        if (!verifyDetachedSignature(Files.newInputStream(downloadedFile), fileSignature, committerKeys)) {
          throw new PluginException("Validation failed, not signed with any key in KEYS file " + keysFileUrl);
        }
      } catch (IOException e) {
        throw new PluginException("Validation failed, could not read downloaded file " + downloadedFile, e);
      } catch (PGPException e) {
        throw new PluginException("Validation failed, problems with PGP KEYS file ", e);
      }
    }

    private String getMD5FileUrl(String url) {
      return APACHE_ARCHIVE_URL + url.substring(url.indexOf(path)) + ".md5";
    }

    private String getPgpSignatureUrl(String url) {
      return APACHE_ARCHIVE_URL + url.substring(url.indexOf(path)) + ".asc";
    }

    private String getKeysFileUrl(String url) {
      return APACHE_ARCHIVE_URL + "lucene/solr/KEYS";
    }

    private String getAndParseMd5File(String url) {
      try {
        BufferedReader reader = new BufferedReader(new InputStreamReader(
            new URL(url).openStream()));
        return reader.readLine().split(" ")[0];
      } catch (IOException e) {
        log.warn("Failed to find md5 sun file " + url);
        return null;
      }
    }

    /**
     * Determines if cryptography restrictions apply.
     * Restrictions apply if the value of {@link Cipher#getMaxAllowedKeyLength(String)} returns a value smaller than {@link Integer#MAX_VALUE} if there are any restrictions according to the JavaDoc of the method.
     * This method is used with the transform <code>"AES/CBC/PKCS5Padding"</code> as this is an often used algorithm that is <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl">an implementation requirement for Java SE</a>.
     *
     * @return <code>true</code> if restrictions apply, <code>false</code> otherwise
     */
    private boolean restrictedCryptography() {
      try {
        return Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Integer.MAX_VALUE;
      } catch (final NoSuchAlgorithmException e) {
        throw new IllegalStateException("The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)", e);
      }
    }

    // NOCOMMIT - License not clarified, and may need to manually install strong encryption addon to JRE
    boolean verifyDetachedSignature(InputStream fileToVerify, InputStream signature, InputStream pgpKeys) throws IOException, PGPException {
        InputStream sigInputStream = PGPUtil.getDecoderStream(new BufferedInputStream(signature));

        PGPObjectFactory pgpObjFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());
        PGPSignatureList pgpSigList = null;

        Object obj = pgpObjFactory.nextObject();
        if (obj instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData)obj;
            pgpObjFactory = new PGPObjectFactory(c1.getDataStream(), new BcKeyFingerprintCalculator());
            pgpSigList = (PGPSignatureList)pgpObjFactory.nextObject();
        }
        else {
            pgpSigList = (PGPSignatureList)obj;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(pgpKeys),
                new BcKeyFingerprintCalculator());
        InputStream  fileInputStream = new BufferedInputStream(fileToVerify);
        PGPSignature sig = pgpSigList.get(0);
        PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
        sig.init(new BcPGPContentVerifierBuilderProvider(), pubKey);

        int ch;
        while ((ch = fileInputStream.read()) >= 0) {
            sig.update((byte)ch);
        }

        fileInputStream.close();
        sigInputStream.close();

        return sig.verify();
    }

  }

}
