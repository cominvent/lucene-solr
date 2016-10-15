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

package org.apache.solr.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.apache.solr.util.SolrCLI.findTool;
import static org.apache.solr.util.SolrCLI.parseCmdLine;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for SolrCLI's UtilsTool
 */
public class UtilsToolTest {

  private Path dir;
  private SolrCLI.UtilsTool tool;
  private List<String> files = Arrays.asList(
      "solr.log", 
      "solr.log.1", 
      "solr.log.2", 
      "solr.log.3", 
      "solr.log.9", 
      "solr_log_20160102", 
      "solr_log_20160304", 
      "solr_gc_log_20160102", 
      "solr_gc_log_2");
  
  @Before
  public void setUp() throws IOException {
    dir = Files.createTempDirectory("Utils Tool Test");
    files.stream().forEach(f -> {
      try {
        dir.resolve(f).toFile().createNewFile();
      } catch (IOException e) {
        assertTrue(false);
      }
    });
  }
  
  @After
  public void tearDown() throws IOException {
    org.apache.commons.io.FileUtils.deleteDirectory(dir.toFile());
  }
  
  @Test
  public void empty() throws Exception {
    String[] args = {"utils", "-remove_old_solr_logs", dir.toString(), 
        "-rotate_solr_logs", dir.toString(), 
        "-archive_gc_logs", dir.toString()};
    assertEquals(0, runTool(args));
  }

  @Test
  public void nonexisting() throws Exception {
    String nonexisting = dir.resolve("non-existing").toString();
    String[] args = {"utils", "-remove_old_solr_logs", nonexisting,
        "-rotate_solr_logs", nonexisting,
        "-archive_gc_logs", nonexisting};
    assertEquals(0, runTool(args));
  }
  
  @Test
  public void testRemoveOldSolrLogs() throws Exception {
    String[] args = {"utils", "-remove_old_solr_logs", dir.toString()};
    assertEquals(files.size(), fileCount());
    assertEquals(0, runTool(args));
    assertEquals(files.size()-2, fileCount());
  }

  @Test
  public void testRemoveOldGcLogs() throws Exception {
    String[] args = {"utils", "-archive_gc_logs", dir.toString()};
    assertEquals(files.size(), fileCount());
    assertEquals(0, runTool(args));
    assertEquals(files.size()-2, fileCount());
    assertFalse(listFiles().contains("solr_gc_log_2"));
    assertTrue(Files.exists(dir.resolve("archived").resolve("solr_gc_log_2")));
    assertEquals(0, runTool(args));
    assertFalse(Files.exists(dir.resolve("archived").resolve("solr_gc_log_2")));
  }

  @Test
  public void testRotateSolrLogs() throws Exception {
    String[] args = {"utils", "-rotate_solr_logs", dir.toString()};
    assertEquals(files.size(), fileCount());
    assertTrue(listFiles().contains("solr.log"));
    assertEquals(0, runTool(args));
    assertEquals(files.size()-1, fileCount());
    assertTrue(listFiles().contains("solr.log.4"));
    assertFalse(listFiles().contains("solr.log"));
    assertFalse(listFiles().contains("solr.log.9"));
  }
  
  private List<String> listFiles() throws IOException {
    return Files.find(dir, 1, (p, a) -> a.isRegularFile()).map(p -> p.getFileName().toString()).collect(Collectors.toList());
  }
  
  private long fileCount() throws IOException {
    return listFiles().size();
  }

  private int runTool(String[] args) throws Exception {
    SolrCLI.Tool tool = findTool(args);
    CommandLine cli = parseCmdLine(args, tool.getOptions());
    return tool.runTool(cli);
  }
}