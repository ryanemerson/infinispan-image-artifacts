package org.infinispan.images;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xmlunit.assertj.XmlAssert.assertThat;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xmlunit.assertj.XmlAssert;
import org.yaml.snakeyaml.Yaml;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import picocli.CommandLine;

abstract class AbstractMainTest {

   static Yaml YAML = new Yaml();
   static File outputDir;

   @BeforeAll
   static void setup() {
      var suffix = System.getProperty("native.image.path") != null ? "-Native" : "";
      var path = System.getProperty("java.io.tmpdir") + File.separator + "ConfigGeneratorMainTest" + suffix;
      outputDir = new File(path);
      outputDir.mkdir();
   }

   @AfterAll
   static void teardown() {
      deleteDirectory(outputDir);
   }

   @AfterEach
   void cleanup() {
      for (File file : outputDir.listFiles())
         file.delete();
   }

   abstract int execute(String... args) throws Exception;

   @Test
   void testNonExistentIdentitiesFile() throws Exception {
      assertEquals(CommandLine.ExitCode.USAGE, execute("--config=/made/up/path", outputDir.getAbsolutePath()));
   }

   @Test
   void testNonExistentServerFile() throws Exception {
      assertEquals(CommandLine.ExitCode.USAGE, execute("--identities=/made/up/path", outputDir.getAbsolutePath()));
   }

   @Test
   void testChangeInfinispanClusterName() throws Exception {
      String json = generate("cluster-name").infinispan();
      assertValue(json, "infinispan.cacheContainer.transport.cluster", "${infinispan.cluster.name:customClusterName}");
   }

   @Test()
   void testMemcachedDisabledByDefault() throws Exception {
      String json = generateDefault().infinispan();
      assertThrows(PathNotFoundException.class, () ->
            JsonPath.read(json, "infinispan.server.endpoints.connectors.memcachedConnector"));
   }

   @Test
   void testEnableMemcached() throws Exception {
      String json = generate("memcached-enabled").infinispan();
      assertValue(json, "infinispan.server.endpoints.connectors.memcachedConnector.socketBinding", "memcached");
   }

   @Test
   void testRestDisabled() throws Exception {
      String json = generate("rest-disabled").infinispan();
      assertThrows(PathNotFoundException.class, () ->
            JsonPath.read(json, "infinispan.server.endpoints.connectors.restConnector"));
   }

   @Test
   void testAuthEnabledByDefault() throws Exception {
      String json = generateDefault().infinispan();
      JSONArray propertiesRealm = JsonPath.read(json,"infinispan.server.security.securityRealms[0].securityRealm[?(@.name == 'default')].propertiesRealm");
      assertEquals(1, propertiesRealm.size());

      Map<String, String> sasl = JsonPath.read(json, "infinispan.server.endpoints.connectors.hotrodConnector.authentication.sasl");
      assertNotNull(sasl);
      assertEquals("auth", sasl.get("qop"));
      assertEquals("infinispan", sasl.get("serverName"));
   }

   @Test
   void testAuthDisabled() throws Exception {
      String json = generate("auth-disabled").infinispan();
      assertEmptyJsonList(json, ".infinispan.server.security.securityRealms[0].securityRealm[?(@.name == 'default')].propertiesRealm.userProperties");
      assertThrows(PathNotFoundException.class, () ->
            JsonPath.read(json, "infinispan.server.endpoints.connectors.hotrodConnector.authentication"));
   }

   @Test
   void testHotRodDisabled() throws Exception {
      String json = generate("hotrod-disabled").infinispan();
      assertThrows(PathNotFoundException.class, () ->
            JsonPath.read(json, "infinispan.server.endpoints.connectors.hotrodConnector"));
   }

   @Test
   @SuppressWarnings("unchecked")
   void testRestCorsRules() throws Exception {
      String json = generate("rest-cors-rules").infinispan();
      JSONArray corsRules = JsonPath.read(json, "infinispan.server.endpoints.connectors.restConnector.corsRules[*].corsRule");
      Map<String, ?> rule = (Map<String, ?>) corsRules.get(0);
      assertEquals("restrict-host1", rule.get("name"));
      assertEquals(false, rule.get("allowCredentials"));
      assertEquals(0, rule.get("maxAgeSeconds"));

      assertEquals("http://host1,https://host1", rule.get("allowedOrigins"));
      assertEquals("GET", rule.get("allowedMethods"));
      assertNull(rule.get("allowedHeaders"));
      assertNull(rule.get("exposeHeaders"));

      rule = (Map<String, ?>) corsRules.get(1);
      assertEquals("allow-all", rule.get("name"));
      assertEquals(true, rule.get("allowCredentials"));
      assertEquals(1, rule.get("maxAgeSeconds"));

      assertEquals("*", rule.get("allowedOrigins"));
      assertEquals("GET,OPTIONS,POST,PUT,DELETE", rule.get("allowedMethods"));
      assertEquals("X-Custom-Header,Upgrade-Insecure-Requests", rule.get("allowedHeaders"));
      assertEquals("Key-Content-Type", rule.get("exposeHeaders"));
   }

   @Test
   void testCustomLogging() throws Exception {
      generate("logging");
      XmlAssert xml = assertThat(Files.readString(Paths.get(outputDir.getAbsolutePath(), ConfigGenerator.LOGGING_FILE)));
      xml.hasXPath("//Configuration/Appenders/Console/PatternLayout")
            .haveAttribute("pattern", "%K{level}%d{HH\\:mm\\:ss,SSS} %-5p [%c] (%t) %s%e%n");

      xml.hasXPath("//Configuration/Appenders/RollingFile")
            .haveAttribute("fileName", "server/custom/log")
            .haveAttribute("filePattern", "server/custom/log.%d{yyyy-MM-dd}-%i");

      xml.hasXPath("//Configuration/Appenders/RollingFile/PatternLayout")
            .haveAttribute("pattern", "%d{yyyy-MM-dd HH\\:mm\\:ss,SSS} %-5p [%c] (%t) %s%e%n");

      xml.hasXPath("//Configuration/Loggers/Root/AppenderRef[1]")
            .haveAttribute("ref", "STDOUT")
            .haveAttribute("level", "INFO");

      xml.hasXPath("//Configuration/Loggers/Root/AppenderRef[2]")
            .haveAttribute("ref", "FILE")
            .haveAttribute("level", "INFO");

      assertLogger(xml, 1, "com.arjuna", "WARN");
      assertLogger(xml, 2, "org.infinispan", "DEBUG");
      assertLogger(xml, 3, "org.jgroups", "WARN");
      assertLogger(xml, 4, "org.infinispan.commands", "TRACE");
   }

   void assertLogger(XmlAssert xml, int index, String category, String level) {
      String xpath = String.format("//Configuration/Loggers/Logger[%d]", index);
      xml.hasXPath(xpath)
            .haveAttribute("name", category)
            .haveAttribute("level", level);
   }

   @Test
   void testJGroupsUdp() throws Exception {
      String json = generate("jgroups-udp").infinispan();
      assertStack(json, "image-udp", "UDP", Collections.singletonMap("enable_diagnostics", false));
   }
   @Test
   void testJGroupsDiagnosticsUdp() throws Exception {
      String json = generate("jgroups-diagnostics-udp").infinispan();
      assertStack(json, "image-udp", "UDP", Collections.singletonMap("enable_diagnostics", true));
   }

   @Test
   void testJGroupsTcp() throws Exception {
      testJGroupsTcp(false);
   }

   @Test
   void testJGroupsDiagnosticsTcp() throws Exception {
      testJGroupsTcp(true);
   }

   private void testJGroupsTcp(boolean diagnosticsEnabled) throws Exception {
      String json = (diagnosticsEnabled ? generate("jgroups-diagnostics-tcp") : generateDefault()).infinispan();

      String bindProperty = String.format("${jgroups.bind.address,jgroups.tcp.address:%s}", InetAddress.getLocalHost().getHostAddress());
      Map<String, Object> tcpAtrributes = new HashMap<>();
      tcpAtrributes.put("enable_diagnostics", diagnosticsEnabled);
      tcpAtrributes.put("bind_addr", bindProperty);

      String stack = "image-tcp";
      assertStack(json, stack, "TCP", tcpAtrributes);
      assertStack(json, stack, "MPING");
   }

   @Test
   void testJGroupsEncryptionDefault() throws Exception {
      String json = generateDefault().infinispan();
      String allStacks = "infinispan.jgroups.stacks[*].stack.";
      assertEmptyJsonList(json, allStacks + ".ASYM_ENCRYPT");
      assertEmptyJsonList(json, allStacks + ".SERIALIZE");
   }

   @Test
   void testJGroupsEncryptionEnabled() throws Exception {
      String json = generate("jgroups-encryption").infinispan();
      assertStack(json, "image-tcp", "ASYM_ENCRYPT", Collections.singletonMap("use_external_key_exchange", false));
      assertStack(json, "image-tcp", "SERIALIZE");
   }

   @Test
   void testJGroupsEncryptionWithKeystore() throws Exception {
      // Generate Yaml config so we can set the absolute path of caFile and crtPath
      URI caUri = new File("src/test/resources", "service-ca.crt").toURI();
      String yaml =
            "jgroups:\n" +
                  "  encrypt: true\n" +
                  "keystore:\n" +
                  "  caFile: '" + caUri.getPath() + "'\n" +
                  "  crtPath: " + caUri.resolve(".").getPath();
      writeYamlAndGenerate(yaml, "jgroups-encryption-keystore");

      Map<String, Object> keyExchangeProps = new HashMap<>();
      keyExchangeProps.put("keystore_name", new File(outputDir, "keystores/keystore.p12").getAbsolutePath());
      keyExchangeProps.put("keystore_password", "infinispan");
      keyExchangeProps.put("keystore_type", "pkcs12");

      String json = infinispan();
      assertStack(json, "image-tcp", "SSL_KEY_EXCHANGE", keyExchangeProps);
      assertStack(json, "image-tcp", "ASYM_ENCRYPT", Collections.singletonMap("use_external_key_exchange", true));
      assertStack(json, "image-tcp", "SERIALIZE");
   }

   @Test
   void testJGroupsXSite() throws Exception {
      String json = generate("jgroups-xsite").infinispan();

      assertStackFile(json, "relay-global", "jgroups-relay.xml");
      assertValue(json, "infinispan.cacheContainer.transport.stack", "xsite");

      Map<String, ?> xsite = getStack(json, "xsite");
      assertEquals("image-tcp", xsite.get("extends"));
      Map<String, ?> relay2 = (Map<String, ?>) xsite.get("relay.RELAY2");
      assertEquals(8, relay2.get("max_site_masters"));
      assertEquals(false, relay2.get("can_become_site_master"));
      assertEquals("LON", relay2.get("site"));

      Map<String, ?> sites = (Map<String, ?>) xsite.get("remoteSites");
      assertEquals("relay-global", sites.get("defaultStack"));

      // TODO add test for remoteSite names when yaml parsing is fixed https://github.com/infinispan/infinispan/pull/8987#discussion_r574477119
//      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[1]")
//            .haveAttribute("name", "LON");
//
//      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[2]")
//            .haveAttribute("name", "NYC");
//
      String relay = jgroupsRelay();
      Map<String, Object> tcp = JsonPath.read(relay, "config.TCP");
      assertEquals("lon-addr", tcp.get("externalAddr"));
      assertEquals(7200, tcp.get("externalPort"));

      assertValue(relay, "config.TCPPING.initialHosts", "lon-addr[7200],nyc-addr[7200]");
   }

   @Test
   void testKeyStoreFromCrt() throws Exception {
      // Generate Yaml config so we can set the absolute path of caFile and crtPath
      URI caUri = new File("src/test/resources", "service-ca.crt").toURI();
      String yaml =
            "keystore:\n" +
                  "  alias: customAlias\n" +
                  "  password: customPassword\n" +
                  "  caFile: '" + caUri.getPath() + "'\n" +
                  "  crtPath: " + caUri.resolve(".").getPath();
      testKeyStoreFromCrt(yaml, outputDir.getAbsolutePath() + "/keystores/keystore.p12");
   }

   @Test
   void testKeyStoreFromCrtCustomPath() throws Exception {
      // Generate Yaml config so we can set the absolute path of caFile and crtPath
      URI caUri = new File("src/test/resources", "service-ca.crt").toURI();

      // Test file with extension
      String yaml =
            "keystore:\n" +
                  "  alias: customAlias\n" +
                  "  password: customPassword\n" +
                  "  path: " + outputDir.getAbsolutePath() + "/custom-dir/custom-keystore-name.p12\n" +
                  "  caFile: '" + caUri.getPath() + "'\n" +
                  "  crtPath: " + caUri.resolve(".").getPath();
      testKeyStoreFromCrt(yaml, outputDir.getAbsolutePath() + "/custom-dir/custom-keystore-name.p12");

      // Test file without extension
      yaml =
            "keystore:\n" +
                  "  alias: customAlias\n" +
                  "  password: customPassword\n" +
                  "  path: " + outputDir.getAbsolutePath() + "/keystore\n" +
                  "  caFile: '" + caUri.getPath() + "'\n" +
                  "  crtPath: " + caUri.resolve(".").getPath();
      testKeyStoreFromCrt(yaml, outputDir.getAbsolutePath() + "/keystore");
   }

   private void testKeyStoreFromCrt(String yaml, String keystorePath) throws Exception {
      String json = writeYamlAndGenerate(yaml, "keystore-crt-path").infinispan();
      Map<String, ?> keystore = getKeystore(json);
      assertEquals("customAlias", keystore.get("alias"));
      assertEquals("customPassword", keystore.get("keystorePassword"));
      assertEquals(keystorePath, keystore.get("path"));
      assertNull(keystore.get("generateSelfSignedCertificateHost"));
   }

   private Map<String, ?> getKeystore(String json) {
      return getSingleton(json, "infinispan.server.security.securityRealms[*].securityRealm[?(@.name == 'default')].serverIdentities.ssl.keystore");
   }

   @Test
   void testKeyStoreProvided() throws Exception {
      // Generate Yaml config so we can set the absolute path of the provided keystore
      URI caUri = new File("src/test/resources", "my-keystore.jks").toURI();
      String yaml =
            "keystore:\n" +
                  "  type: jks\n" +
                  "  password: password\n" +
                  "  path: " + caUri.getPath();

      String json = writeYamlAndGenerate(yaml, "keystore-provided").infinispan();
      Map<String, ?> keystore = getKeystore(json);
      assertEquals("server", keystore.get("alias"));
      assertEquals("password", keystore.get("keystorePassword"));
      assertEquals(caUri.getPath(), keystore.get("path"));
      assertNull(keystore.get("generateSelfSignedCertificateHost"));
   }

   @Test
   void testKeystoreSelfSigned() throws Exception {
      String json = generate("keystore-self-signed").infinispan();
      Map<String, ?> keystore = getKeystore(json);
      assertEquals("server", keystore.get("alias"));
      assertEquals("infinispan", keystore.get("keystorePassword"));
      assertEquals("localhost", keystore.get("generateSelfSignedCertificateHost"));
   }

   @Test
   void testJGroupsXSiteWithTunnel() throws Exception {
      String json = generate("jgroups-xsite-tunnel").infinispan();

      assertStackFile(json, "relay-global", "jgroups-relay.xml");
      assertValue(json, "infinispan.cacheContainer.transport.stack", "xsite");

      Map<String, ?> xsite = getStack(json, "xsite");
      assertEquals("image-tcp", xsite.get("extends"));
      Map<String, ?> relay2 = (Map<String, ?>) xsite.get("relay.RELAY2");
      assertEquals(false, relay2.get("can_become_site_master"));
      assertEquals("LON", relay2.get("site"));

      // TODO add test for remoteSite names when yaml parsing is fixed https://github.com/infinispan/infinispan/pull/8987#discussion_r574477119
//      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[1]")
//            .haveAttribute("name", "LON");
//
//      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[2]")
//            .haveAttribute("name", "NYC");

      assertValue(jgroupsRelay(), "config.TUNNEL.gossipRouterHosts", "lon-addr[7200],nyc-addr[7200]");
   }

   @Test
   void testCredentialIdentities() throws Exception {
      String path = new File("src/test/resources/identities", "identities.yaml").getAbsolutePath();
      assertEquals(CommandLine.ExitCode.OK, execute(String.format("--identities=%s", path), outputDir.getAbsolutePath()));

      Properties userProps = loadPropertiesFile("users.properties");
      assertEquals(2, userProps.size());
      assertEquals("pass", userProps.get("user1"));
      assertEquals("pass", userProps.get("user2"));

      Properties groupProps = loadPropertiesFile("groups.properties");
      assertEquals(2, groupProps.size());
      assertEquals("admin,rockstar", groupProps.get("user1"));
      assertEquals("non-admin", groupProps.get("user2"));
   }

   @Test
   void testZeroCapacityNode() throws Exception {
      String json = generate("zero-capacity").infinispan();
      String jsonPath = "infinispan.cacheContainer.zeroCapacityNode";
      assertValue(json, jsonPath, true);

      json = generateDefault().infinispan();
      assertValue(json, jsonPath, false);
   }

   @Test
   void testClusteredLocks() throws Exception {
      String json = generateDefault().infinispan();
      String jsonPath = "infinispan.cacheContainer.clusteredLocks";
      Map<String, ?> locks = JsonPath.read(json, jsonPath);
      assertEquals(-1, locks.get("numOwners"));
      assertEquals("CONSISTENT", locks.get("reliability"));

      json = generate("locks").infinispan();
      locks = JsonPath.read(json, jsonPath);
      assertEquals(2, locks.get("numOwners"));
      assertEquals("AVAILABLE", locks.get("reliability"));
   }

   void assertValue(String json, String path, Object expected) {
      Object val = JsonPath.read(json, path);
      assertEquals(expected, val);
   }

   void assertEmptyJsonList(String json, String path) {
      JSONArray array = JsonPath.read(json, path);
      assertTrue(array.isEmpty());
   }

   void assertStack(String json, String stackName, String protocolName) {
      assertStack(json, stackName, protocolName, null);
   }

   @SuppressWarnings("unchecked")
   void assertStack(String json, String stackName, String protocolName, Map<String, ?> properties) {
      Map<String, ?> stack = getStack(json, stackName);
      assertEquals(stackName, stack.get("name"));
      Map<String, String> protocol = (Map<String, String>) stack.get(protocolName);
      assertNotNull(protocol);
      if (properties == null)
         return;

      for (Map.Entry<String, ?> entry : properties.entrySet()) {
         assertEquals(entry.getValue(), protocol.get(entry.getKey()));
      }
   }

   Map<String, ?> getStack(String json, String stackName) {
      String jsonpath = String.format("infinispan.jgroups.stacks[*].stack[?(@.name == '%s')]", stackName);
      return getSingleton(json, jsonpath);
   }

   @SuppressWarnings("unchecked")
   Map<String, ?> getSingleton(String json, String jsonPath) {
      JSONArray array = JsonPath.read(json, jsonPath);
      assertEquals(1, array.size());
      return (Map<String, ?>) array.get(0);
   }

   void assertStackFile(String json, String name, String path) {
      String jsonpath = String.format("infinispan.jgroups.stackFiles[?(@.name == '%s' && @.path == '%s')]", name, path);
      JSONArray stacks = JsonPath.read(json, jsonpath);
      assertEquals(1, stacks.size());
   }

   private AbstractMainTest generateDefault() throws Exception {
      assertEquals(CommandLine.ExitCode.OK, execute(outputDir.getAbsolutePath()));
      return this;
   }

   private AbstractMainTest generate(String configName) throws Exception {
      String path = new File("src/test/resources/config", configName + ".yaml").getAbsolutePath();
      assertEquals(CommandLine.ExitCode.OK, execute(String.format("--config=%s", path), outputDir.getAbsolutePath()));
      return this;
   }

   private AbstractMainTest writeYamlAndGenerate(String yaml, String fileName) throws Exception {
      Path configPath = Paths.get(outputDir.getAbsolutePath(), fileName);
      Files.writeString(configPath, yaml);
      assertEquals(CommandLine.ExitCode.OK, execute(String.format("--config=%s", configPath), outputDir.getAbsolutePath()));
      return this;
   }

   private String yamlAsJson(String filename) throws IOException {
      try (InputStream is = Files.newInputStream(Paths.get(outputDir.getAbsolutePath(), filename))) {
         Map<String, ?> yaml = YAML.load(is);
         return new JSONObject(yaml).toString();
      }
   }

   private String infinispan() throws Exception {
      return yamlAsJson(ConfigGenerator.INFINISPAN_FILE);
   }

   private String jgroupsRelay() throws Exception {
      return yamlAsJson(ConfigGenerator.JGROUPS_RELAY_FILE);
   }

   private static Properties loadPropertiesFile(String name) throws Exception {
      Properties properties = new Properties();
      File propsFile = new File(outputDir, name);
      try (Reader reader = Files.newBufferedReader(propsFile.toPath())) {
         properties.load(reader);
         return properties;
      }
   }

   static void deleteDirectory(File dir) {
      File[] allContents = dir.listFiles();
      if (allContents != null) {
         for (File file : allContents) {
            deleteDirectory(file);
         }
      }
   }
}
