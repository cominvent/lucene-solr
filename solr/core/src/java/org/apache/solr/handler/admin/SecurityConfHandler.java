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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.solr.common.SolrException;
import org.apache.solr.common.params.CommonParams;
import org.apache.solr.common.util.Utils;
import org.apache.solr.core.CoreContainer;
import org.apache.solr.handler.RequestHandlerBase;
import org.apache.solr.handler.SolrConfigHandler;
import org.apache.solr.request.SolrQueryRequest;
import org.apache.solr.response.SolrQueryResponse;
import org.apache.solr.security.AuthorizationContext;
import org.apache.solr.security.ConfigEditablePlugin;
import org.apache.solr.security.PermissionNameProvider;
import org.apache.solr.util.CommandOperation;

import static org.apache.solr.common.SolrException.ErrorCode.SERVER_ERROR;

public abstract class SecurityConfHandler extends RequestHandlerBase implements PermissionNameProvider {
  protected CoreContainer cores;

  public SecurityConfHandler(CoreContainer coreContainer) {
    this.cores = coreContainer;
  }

  @Override
  public PermissionNameProvider.Name getPermissionName(AuthorizationContext ctx) {
    switch (ctx.getHttpMethod()) {
      case "GET":
        return PermissionNameProvider.Name.SECURITY_READ_PERM;
      case "POST":
        return PermissionNameProvider.Name.SECURITY_EDIT_PERM;
      default:
        return null;
    }
  }

  @Override
  public void handleRequestBody(SolrQueryRequest req, SolrQueryResponse rsp) throws Exception {
    SolrConfigHandler.setWt(req, CommonParams.JSON);
    String httpMethod = (String) req.getContext().get("httpMethod");
    String path = (String) req.getContext().get("path");
    String key = path.substring(path.lastIndexOf('/')+1);
    if ("GET".equals(httpMethod)) {
      getConf(rsp, key);
    } else if ("POST".equals(httpMethod)) {
      Object plugin = getPlugin(key);
      doEdit(req, rsp, path, key, plugin);
    }
  }

  private void doEdit(SolrQueryRequest req, SolrQueryResponse rsp, String path, final String key, final Object plugin)
      throws IOException {
    ConfigEditablePlugin configEditablePlugin = null;

    if (plugin == null) {
      throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "No " + key + " plugin configured");
    }
    if (plugin instanceof ConfigEditablePlugin) {
      configEditablePlugin = (ConfigEditablePlugin) plugin;
    } else {
      throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, key + " plugin is not editable");
    }

    if (req.getContentStreams() == null) {
      throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "No contentStream");
    }
    List<CommandOperation> ops = CommandOperation.readCommands(req.getContentStreams(), rsp);
    if (ops == null) {
      throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "No commands");
    }
    for (; ; ) {
      SecurityProps securityProps = getSecurityProps(true);
      Map<String, Object> data = securityProps.getData();
      Map<String, Object> latestConf = (Map<String, Object>) data.get(key);
      if (latestConf == null) {
        throw new SolrException(SERVER_ERROR, "No configuration present for " + key);
      }
      List<CommandOperation> commandsCopy = CommandOperation.clone(ops);
      Map<String, Object> out = configEditablePlugin.edit(Utils.getDeepCopy(latestConf, 4) , commandsCopy);
      if (out == null) {
        List<Map> errs = CommandOperation.captureErrors(commandsCopy);
        if (!errs.isEmpty()) {
          rsp.add(CommandOperation.ERR_MSGS, errs);
          return;
        }
        //no edits
        return;
      } else {
        if(!Objects.equals(latestConf.get("class") , out.get("class"))){
          throw new SolrException(SERVER_ERROR, "class cannot be modified");
        }
        Map meta = getMapValue(out, "");
        meta.put("v", securityProps.getVersion()+1);//encode the expected zkversion
        data.put(key, out);
        
        if(persistConf(securityProps)) return;
      }
    }
  }

  Object getPlugin(String key) {
    Object plugin = null;
    if ("authentication".equals(key)) plugin = cores.getAuthenticationPlugin();
    if ("authorization".equals(key)) plugin = cores.getAuthorizationPlugin();
    return plugin;
  }

  protected abstract void getConf(SolrQueryResponse rsp, String key);

  public static Map<String, Object> getMapValue(Map<String, Object> lookupMap, String key) {
    Map<String, Object> m = (Map<String, Object>) lookupMap.get(key);
    if (m == null) lookupMap.put(key, m = new LinkedHashMap<>());
    return m;
  }

  public static List getListValue(Map<String, Object> lookupMap, String key) {
    List l = (List) lookupMap.get(key);
    if (l == null) lookupMap.put(key, l= new ArrayList());
    return l;
  }

  @Override
  public String getDescription() {
    return "Edit or read security configuration";
  }

  /**
   * Gets security.json from source
   */
  public abstract SecurityProps getSecurityProps(boolean getFresh);

  /**
   * Persist security.json to the source, optionally with a version
   */
  protected abstract boolean persistConf(SecurityProps securityProps) throws IOException;

  /**
   * Object to hold security.json as nested <code>Map&lt;String,Object&gt;</code> and optionally its version
   */
  public static class SecurityProps {
    private Map<String, Object> data = Collections.EMPTY_MAP;
    private int version = -1;

    public SecurityProps() {}

    public SecurityProps setData(Map<String, Object> data) {
      this.data = data;
      return this;
    }

    public SecurityProps setData(Object data) {
      if (data instanceof Map) {
        this.data = (Map<String, Object>) data;
        return this;
      } else {
        throw new SolrException(SERVER_ERROR, "Illegal format when parsing security.json, not object");
      }
    }

    public SecurityProps setVersion(int version) {
      this.version = version;
      return this;
    }

    public Map<String, Object> getData() {
      return data;
    }

    public int getVersion() {
      return version;
    }

    /**
     * Set data from input stream
     * @param securityJsonInputStream an input stream for security.json
     * @return this (builder pattern)
     */
    public SecurityProps setData(InputStream securityJsonInputStream) {
      return setData(Utils.fromJSON(securityJsonInputStream));
    }
  }
}

