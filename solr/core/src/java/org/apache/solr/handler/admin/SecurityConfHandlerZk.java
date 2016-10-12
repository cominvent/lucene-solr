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
import java.util.Collections;

import org.apache.solr.common.SolrException;
import org.apache.solr.common.cloud.ZkStateReader;
import org.apache.solr.common.util.Utils;
import org.apache.solr.core.CoreContainer;
import org.apache.solr.response.SolrQueryResponse;
import org.apache.solr.util.CommandOperation;
import org.apache.zookeeper.KeeperException;

import static org.apache.solr.common.SolrException.ErrorCode.SERVER_ERROR;

/**
 * Security Configuration Handler which works with Zookeeper
 */
public class SecurityConfHandlerZk extends SecurityConfHandler {
  public SecurityConfHandlerZk(CoreContainer coreContainer) {
    super(coreContainer);
  }

  /**
   * Fetches security props from Zookeeper and adds version
   * @param getFresh refresh from ZK
   * @return SecurityProps whose data property either contains security.json, or an empty map if not found
   */
  @Override
  public SecurityProps getSecurityProps(boolean getFresh) {
    ZkStateReader.ConfigData configDataFromZk = cores.getZkController().getZkStateReader().getSecurityProps(getFresh);
    return configDataFromZk == null ? 
        new SecurityProps() :
        new SecurityProps().setData(configDataFromZk.data).setVersion(configDataFromZk.version);
  }

  @Override
  protected void getConf(SolrQueryResponse rsp, String key) {
    ZkStateReader.ConfigData map = cores.getZkController().getZkStateReader().getSecurityProps(false);
    Object o = map == null ? null : map.data.get(key);
    if (o == null) {
      rsp.add(CommandOperation.ERR_MSGS, Collections.singletonList("No " + key + " configured"));
    } else {
      rsp.add(key+".enabled", getPlugin(key)!=null);
      rsp.add(key, o);
    }
  }
  
  @Override
  protected boolean persistConf(SecurityProps securityProps) throws IOException {
    try {
      cores.getZkController().getZkClient().setData(ZkStateReader.SOLR_SECURITY_CONF_PATH, 
          Utils.toJSON(securityProps.getData()), 
          securityProps.getVersion(), true);
      return true;
    } catch (KeeperException.BadVersionException bdve){
      return false;
    } catch (Exception e) {
      throw new SolrException(SERVER_ERROR, " Unable to persist conf",e);
    }
  }
  
  @Override
  public String getDescription() {
    return "Edit or read security configuration from Zookeeper";
  }
  
}
