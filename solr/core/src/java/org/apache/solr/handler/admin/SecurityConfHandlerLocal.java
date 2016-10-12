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

package org.apache.solr.handler.admin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.apache.solr.common.SolrException;
import org.apache.solr.common.util.Utils;
import org.apache.solr.core.CoreContainer;
import org.apache.solr.core.SolrResourceLoader;
import org.apache.solr.response.SolrQueryResponse;
import org.apache.solr.util.CommandOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security Configuration Handler which works on standalone local files
 */
public class SecurityConfHandlerLocal extends SecurityConfHandler {
  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  private static final Path SECURITY_JSON_PATH = SolrResourceLoader.locateSolrHome().resolve("security.json");
  
  public SecurityConfHandlerLocal(CoreContainer coreContainer) {
    super(coreContainer);
  }

  /**
   * Fetches security props from SOLR_HOME
   * @param getFresh NOP
   * @return SecurityProps whose data property either contains security.json, or an empty map if not found
   */
  @Override
  public SecurityProps getSecurityProps(boolean getFresh) {
    if (Files.exists(SECURITY_JSON_PATH)) {
      try (InputStream securityJsonIs = Files.newInputStream(SECURITY_JSON_PATH)) {
        log.debug("Using local version of security.json from SOLR_HOME");
        return new SecurityProps().setData(securityJsonIs);
      } catch (IOException e) { /* Fall through */ }
    }
    return new SecurityProps();
  }

  @Override
  protected void getConf(SolrQueryResponse rsp, String key) {
    SecurityProps props = getSecurityProps(false);
    Object o = props.getData().get(key);
    if (o == null) {
      rsp.add(CommandOperation.ERR_MSGS, Collections.singletonList("No " + key + " configured"));
    } else {
      rsp.add(key+".enabled", getPlugin(key)!=null);
      rsp.add(key, o);
    }
  }
  
  @Override
  protected boolean persistConf(SecurityProps securityProps) throws IOException {
    if (securityProps == null || securityProps.getData().isEmpty()) {
      throw new SolrException(SolrException.ErrorCode.SERVER_ERROR, 
          "Failed persisting security.json to SOLR_HOME. Object was empty.");
    }
    try(OutputStream securityJsonOs = Files.newOutputStream(SECURITY_JSON_PATH)) {
      log.debug("Writing security.json to Solr home");
      securityJsonOs.write(Utils.toJSON(securityProps.getData()));
      return true;
    } catch (IOException e) {
      log.warn("Failed persisting security.json to SOLR_HOME", e);
      return false;
    }
  }

  @Override
  public String getDescription() {
    return "Edit or read security configuration locally in SOLR_HOME";
  }
}
