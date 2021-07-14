package org.infinispan.images;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.xmlunit.assertj.XmlAssert.assertThat;

import java.io.File;
import java.io.Reader;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xmlunit.assertj.MultipleNodeAssert;
import org.xmlunit.assertj.XmlAssert;

import picocli.CommandLine;

abstract class AbstractMainTest {

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
   void testChangeInfinispanServerName() throws Exception {
      generate("server-name")
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container/i:transport[@cluster='${infinispan.cluster.name:customClusterName}']");
   }

   @Test
   void testMemcachedDisabledByDefault() throws Exception {
      generateDefault()
            .infinispan()
            .doesNotHaveXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:memcached-connector");
   }

   @Test
   void testEnableMemcached() throws Exception {
      generate("memcached-enabled")
            .infinispan()
            .hasXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:memcached-connector");
   }

   @Test
   void testClientCertAuthenticate() throws Exception {
      XmlAssert xml = generate("endpoints-client-cert-authenticate").infinispan();
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:properties-realm");
      testClientCert(xml, true);
   }

   @Test
   void testClientCertValidate() throws Exception {
      XmlAssert xml = generate("endpoints-client-cert-validate").infinispan();
      xml.hasXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:properties-realm");
      testClientCert(xml, false);
   }

   void testClientCert(XmlAssert xml, boolean authenticate) {
      xml.hasXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]").haveAttribute("require-ssl-client-auth", "true");
      xml.hasXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:server-identities/s:ssl/s:truststore")
            .haveAttribute("path", "/some/keystore.jks")
            .haveAttribute("password", "secret");

      String tsRealmPath = "//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:truststore-realm";
      if (authenticate) {
         xml.hasXPath(tsRealmPath);
      } else {
         xml.doesNotHaveXPath(tsRealmPath);
      }
   }


   @Test
   void testRestDisabled() throws Exception {
      generate("rest-disabled")
            .infinispan()
            .doesNotHaveXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:rest-connector");
   }

   @Test
   void testAuthorizationEnabledByDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      xml.hasXPath("//i:infinispan/i:cache-container/i:security/i:authorization/i:cluster-role-mapper");
   }

   @Test
   void testAuthorizationCommonNameRoleMapper() throws Exception {
      XmlAssert xml = generate("authorization-common-name").infinispan();
      xml.hasXPath("//i:infinispan/i:cache-container/i:security/i:authorization/i:common-name-role-mapper");
   }

   @Test
   void testAuthorizationDisabled() throws Exception {
      XmlAssert xml = generate("authorization-disabled").infinispan();
      xml.doesNotHaveXPath("//i:infinispan/i:cache-container/i:security");
   }

   @Test
   void testAuthorizationRoles() throws Exception {
      XmlAssert xml = generate("authorization-roles").infinispan();
      xml.hasXPath("//i:infinispan/i:cache-container/i:security/i:authorization/i:role[@name='test-role'][1]").haveAttribute("permissions", "ALL");
      xml.hasXPath("//i:infinispan/i:cache-container/i:security/i:authorization/i:role[@name='test-role2'][1]").haveAttribute("permissions", "READ WRITE");
   }


   @Test
   void testAuthEnabledByDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:truststore-realm");
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:server-identities/s:ssl/s:trustore");
      xml.hasXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:properties-realm");
      xml.hasXPath("//i:infinispan/s:server/s:endpoints")
            .haveAttribute("security-realm");
      xml.hasXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:hotrod-connector/s:authentication/s:sasl")
            .haveAttribute("qop", "auth")
            .haveAttribute("server-name", "infinispan");
   }

   @Test
   void testAuthDisabled() throws Exception {
      XmlAssert xml = generate("auth-disabled").infinispan();
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:properties-realm");
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:hotrod-connector/s:authentication");
      xml.hasXPath("//i:infinispan/s:server/s:endpoints")
         .haveAttribute("security-realm");
   }

   @Test
   void testRestCorsRules() throws Exception {
      XmlAssert xml = generate("rest-cors-rules").infinispan();
      String rulesPath = "//i:infinispan/s:server/s:endpoints[@socket-binding='default'][1]/s:rest-connector/s:cors-rules/";
      String rule = rulesPath + "s:cors-rule[1]";
      xml.hasXPath(rule)
            .haveAttribute("name", "restrict-host1")
            .haveAttribute("allow-credentials", "false")
            .haveAttribute("max-age-seconds", "0");

      xml.valueByXPath(rule + "/s:allowed-origins").isEqualTo("http://host1,https://host1");
      xml.valueByXPath(rule + "/s:allowed-methods").isEqualTo("GET");
      xml.doesNotHaveXPath(rule + "/s:allowed-headers");
      xml.doesNotHaveXPath(rule + "/s:expose-headers");

      rule = rulesPath + "s:cors-rule[2]";
      xml.hasXPath(rule)
            .haveAttribute("name", "allow-all")
            .haveAttribute("allow-credentials", "true")
            .haveAttribute("max-age-seconds", "1");

      xml.valueByXPath(rule + "/s:allowed-origins").isEqualTo("*");
      xml.valueByXPath(rule + "/s:allowed-methods").isEqualTo("GET,OPTIONS,POST,PUT,DELETE");
      xml.valueByXPath(rule + "/s:allowed-headers").isEqualTo("X-Custom-Header,Upgrade-Insecure-Requests");
      xml.valueByXPath(rule + "/s:expose-headers").isEqualTo("Key-Content-Type");
   }

   @Test
   void testCustomLogging() throws Exception {
      XmlAssert xml = generate("logging").logging();
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
      assertLogger(xml, 4, "io.netty.handler.ssl.ApplicationProtocolNegotiationHandler", "ERROR");
      assertLogger(xml, 5, "org.infinispan.commands", "TRACE");
   }

   void assertLogger(XmlAssert xml, int index, String category, String level) {
      String xpath = String.format("//Configuration/Loggers/Logger[%d]", index);
      xml.hasXPath(xpath)
            .haveAttribute("name", category)
            .haveAttribute("level", level);
   }

   @Test
   void testJGroupsUdp() throws Exception {
      XmlAssert xml = generate("jgroups-udp").infinispan();
      assertStack(xml, "image-udp", "i:UDP")
            .haveAttribute("enable_diagnostics", Boolean.toString(false));
   }

   @Test
   void testJGroupsDiagnosticsUdp() throws Exception {
      XmlAssert xml = generate("jgroups-diagnostics-udp").infinispan();
      assertStack(xml, "image-udp", "i:UDP")
            .haveAttribute("enable_diagnostics", Boolean.toString(true));
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
      XmlAssert xml = generate(diagnosticsEnabled ? "jgroups-diagnostics-tcp" : "jgroups-diagnostics-disabled-tcp").infinispan();
      String bindProperty = String.format("${jgroups.bind.address,jgroups.tcp.address:%s}", InetAddress.getLocalHost().getHostAddress());
      assertStack(xml, "i:TCP")
            .haveAttribute("enable_diagnostics", Boolean.toString(diagnosticsEnabled))
            .haveAttribute("bind_addr", bindProperty)
            .haveAttribute("bind_port", "${jgroups.bind.port,jgroups.tcp.port:7800}")
            .haveAttribute("port_range", "0");
      assertStack(xml, "i:MPING");
   }

   @Test
   void testJGroupsEncryptionDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      xml.doesNotHaveXPath("//j:config/j:ASYM_ENCRYPT");
      xml.doesNotHaveXPath("//j:config/j:SERIALIZE");
   }

   @Test
   void testJGroupsEncryptionEnabled() throws Exception {
      XmlAssert xml = generate("jgroups-encryption").infinispan();
      assertStack(xml, "i:ASYM_ENCRYPT")
            .haveAttribute("use_external_key_exchange", "false");

      assertStack(xml, "i:SERIALIZE");
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
      XmlAssert xml = infinispan();

      assertStack(xml, "i:SSL_KEY_EXCHANGE")
            .haveAttribute("keystore_name", new File(outputDir, "keystores/keystore.p12").getAbsolutePath())
            .haveAttribute("keystore_password", "infinispan")
            .haveAttribute("keystore_type", "pkcs12");

      assertStack(xml, "i:ASYM_ENCRYPT")
            .haveAttribute("use_external_key_exchange", "true");

      assertStack(xml, "i:SERIALIZE");
   }

   @Test
   void testJGroupsXSite() throws Exception {
      generate("jgroups-xsite");

      XmlAssert infinispan = infinispan();

      assertStack(infinispan, null);

      assertStackFile(infinispan, "relay-global")
            .haveAttribute("path", "jgroups-relay.xml");

      infinispan.hasXPath("//i:infinispan/i:cache-container/i:transport")
            .haveAttribute("stack", "xsite");

      assertStack(infinispan, "xsite", null)
            .haveAttribute("extends", "image-tcp");

      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[1]")
            .haveAttribute("name", "LON");

      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[2]")
            .haveAttribute("name", "NYC");

      assertStack(infinispan, "xsite", "/j:relay.RELAY2")
            .haveAttribute("max_site_masters", "8")
            .haveAttribute("can_become_site_master", "false")
            .haveAttribute("site", "LON");

      XmlAssert relay = jgroupsRelay();
      String bindProperty = String.format("${jgroups.relay.bind.address:%s}", InetAddress.getLocalHost().getHostAddress());
      relay.hasXPath("//j:config/j:TCP")
            .haveAttribute("bind_addr", bindProperty)
            .haveAttribute("bind_port", "${jgroups.relay.bind.port:7900}")
            .haveAttribute("external_addr", "lon-addr")
            .haveAttribute("external_port", "7200")
            .haveAttribute("port_range", "0")
            .haveAttribute("enable_diagnostics", Boolean.toString(false));

      relay.hasXPath("//j:config/j:TCPPING")
            .haveAttribute("initial_hosts", "lon-addr[7200],nyc-addr[7200]");
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
      writeYamlAndGenerate(yaml, "keystore-crt-path");
      XmlAssert xml = infinispan();

      String path = "//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:server-identities/s:ssl/s:keystore";
      xml.hasXPath(path)
            .haveAttribute("alias", "customAlias")
            .haveAttribute("keystore-password", "customPassword")
            .haveAttribute("path", keystorePath)
            .doNotHaveAttribute("generate-self-signed-certificate-host");
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

      writeYamlAndGenerate(yaml, "keystore-provided");
      XmlAssert xml = infinispan();

      String path = "//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:server-identities/s:ssl/s:keystore";
      xml.hasXPath(path)
            .haveAttribute("alias", "server")
            .haveAttribute("keystore-password", "password")
            .haveAttribute("path", caUri.getPath())
            .doNotHaveAttribute("generate-self-signed-certificate-host");
   }

   @Test
   void testKeystoreSelfSigned() throws Exception {
      generate("keystore-self-signed");
      XmlAssert xml = infinispan();

      String path = "//i:infinispan/s:server/s:security/s:security-realms/s:security-realm[@name='default']/s:server-identities/s:ssl/s:keystore";
      xml.hasXPath(path)
            .haveAttribute("alias", "server")
            .haveAttribute("keystore-password", "infinispan")
            .haveAttribute("generate-self-signed-certificate-host", "localhost");
   }

   @Test
   void testJGroupsXSiteWithTunnel() throws Exception {
      generate("jgroups-xsite-tunnel");

      XmlAssert infinispan = infinispan();

      assertStack(infinispan, null);

      assertStackFile(infinispan, "relay-global")
            .haveAttribute("name", "relay-global")
            .haveAttribute("path", "jgroups-relay.xml");

      infinispan.hasXPath("//i:infinispan/i:cache-container/i:transport")
            .haveAttribute("stack", "xsite");

      assertStack(infinispan, "xsite", null)
            .haveAttribute("extends", "image-tcp");

      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[1]")
            .haveAttribute("name", "LON");

      assertStack(infinispan, "xsite", "/i:remote-sites/i:remote-site[2]")
            .haveAttribute("name", "NYC");

      XmlAssert relay = jgroupsRelay();
      String bindProperty = String.format("${jgroups.relay.bind.address:%s}", InetAddress.getLocalHost().getHostAddress());
      relay.hasXPath("//j:config/j:TUNNEL")
            .haveAttribute("gossip_router_hosts", "lon-addr[7200],nyc-addr[7200]")
            .haveAttribute("bind_addr", bindProperty)
            .haveAttribute("bind_port", "${jgroups.relay.bind.port:7900}")
            .haveAttribute("port_range", "0")
            .haveAttribute("enable_diagnostics", Boolean.toString(false));
   }

   @Test
   void testCredentialIdentities() throws Exception {
      testIdentities("--identities", null);
   }

   @Test
   void testAdminCredentialIdentities() throws Exception {
      testIdentities("--admin-identities", "admin");
   }

   void testIdentities(String cmdOption, String subDir) throws Exception {
      String path = new File("src/test/resources/identities", "identities.yaml").getAbsolutePath();
      assertEquals(CommandLine.ExitCode.OK, execute(String.format("%s=%s", cmdOption, path), outputDir.getAbsolutePath()));

      File propsDir = subDir == null ? outputDir : new File(outputDir, subDir);
      Properties userProps = loadPropertiesFile("users.properties", propsDir);
      assertEquals(2, userProps.size());
      assertEquals("pass", userProps.get("user1"));
      assertEquals("pass", userProps.get("user2"));

      Properties groupProps = loadPropertiesFile("groups.properties", propsDir);
      assertEquals(2, groupProps.size());
      assertEquals("admin,rockstar", groupProps.get("user1"));
      assertEquals("non-admin", groupProps.get("user2"));
   }

   @Test
   void testZeroCapacityNode() throws Exception {
      generate("zero-capacity")
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container[@zero-capacity-node='true']");

      generateDefault()
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container[@zero-capacity-node='false']");
   }

   @Test
   void testClusteredLocks() throws Exception {
      generateDefault()
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container/cl:clustered-locks")
            .haveAttribute("num-owners", "-1")
            .haveAttribute("reliability", "CONSISTENT");

      generate("locks")
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container/cl:clustered-locks")
            .haveAttribute("num-owners", "2")
            .haveAttribute("reliability", "AVAILABLE");
   }

   @Test
   void testAdminEndpointEnabled() throws Exception {
      XmlAssert infinispan = generate("admin-endpoint").infinispan();
      infinispan.hasXPath("//i:infinispan/s:server/s:socket-bindings/s:socket-binding[@name='admin'][1]")
            .haveAttribute("port", "11223");

      infinispan.hasXPath("//i:infinispan/s:server/s:endpoints[@socket-binding='admin' and @security-realm='admin'][1]/s:rest-connector/s:authentication")
      .haveAttribute("mechanisms", "BASIC DIGEST");
   }

   @Test
   void testCloudEventsDisabledByDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      String path = "//i:infinispan/i:cache-container/ce:cloudevents";
      xml.doesNotHaveXPath(path);
   }

   @Test
   void testCloudEventsProvided() throws Exception {
      // Generate Yaml config so we can set the absolute path of the provided keystore
      String yaml =
            "cloudEvents:\n"+
            "  bootstrapServers: 127.0.0.1:9092,192.168.1.14:9092";
      writeYamlAndGenerate(yaml, "cloudevent-provided");
      XmlAssert xml = infinispan();

      String path = "//i:infinispan/i:cache-container/ce:cloudevents";
      xml.hasXPath(path)
            .haveAttribute("bootstrap-servers", "127.0.0.1:9092,192.168.1.14:9092")
            .doNotHaveAttribute("acks")
            .doNotHaveAttribute("cache-entries-topic");
   }

   @Test
   void testCloudEventsOnlyBootstrapProvided() throws Exception {
      // Generate Yaml config so we can set the absolute path of the provided keystore
      String yaml =
            "cloudEvents:\n"+
            "  bootstrapServers: 127.0.0.1:9092,192.168.1.14:9092\n"+
            "  acks: \"1\"\n"+
            "  cacheEntriesTopic: target-topic";
      writeYamlAndGenerate(yaml, "cloudevent-provided");
      XmlAssert xml = infinispan();

      String path = "//i:infinispan/i:cache-container/ce:cloudevents";
      xml.hasXPath(path)
            .haveAttribute("bootstrap-servers", "127.0.0.1:9092,192.168.1.14:9092")
            .haveAttribute("acks", "1")
            .haveAttribute("cache-entries-topic","target-topic");
   }

   MultipleNodeAssert assertStack(XmlAssert xml, String path) {
      return assertStack(xml, "image-tcp", path);
   }

   MultipleNodeAssert assertStack(XmlAssert xml, String name, String path) {
      String stack = String.format("(//i:infinispan/i:jgroups/i:stack[@name='%s'])[1]", name);
      if (path != null)
         stack = String.format("%s/%s", stack, path);
      return xml.hasXPath(stack);
   }

   MultipleNodeAssert assertStackFile(XmlAssert xmlAssert, String file) {
      String path = String.format("(//i:infinispan/i:jgroups/i:stack-file[@name='%s'])[1]", file);
      return xmlAssert.hasXPath(path);
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

   private XmlAssert infinispan() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), ConfigGenerator.INFINISPAN_FILE));
      Map<String, String> prefix2Uri = new HashMap<>();
      prefix2Uri.put("i", "urn:infinispan:config:12.1");
      prefix2Uri.put("cl", "urn:infinispan:config:clustered-locks:12.1");
      prefix2Uri.put("s", "urn:infinispan:server:12.1");
      prefix2Uri.put("j", "urn:org:jgroups");
      prefix2Uri.put("ce", "urn:infinispan:config:cloudevents:12.1");
      return assertThat(config).withNamespaceContext(prefix2Uri);
   }

   private XmlAssert logging() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), ConfigGenerator.LOGGING_FILE));
      return assertThat(config);
   }

   private XmlAssert jgroupsRelay() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), ConfigGenerator.JGROUPS_RELAY_FILE));
      return jgroups(config);
   }

   private XmlAssert jgroups(String config) {
      Map<String, String> prefix2Uri = new HashMap<>();
      prefix2Uri.put("j", "urn:org:jgroups");
      return assertThat(config).withNamespaceContext(prefix2Uri);
   }

   private static Properties loadPropertiesFile(String name, File outputDir) throws Exception {
      Properties properties = new Properties();
      File propsFile = new File(outputDir, name);
      try (Reader reader = Files.newBufferedReader(propsFile.toPath())) {
         properties.load(reader);
         return properties;
      }
   }

   static boolean deleteDirectory(File dir) {
      File[] allContents = dir.listFiles();
      if (allContents != null) {
         for (File file : allContents) {
            deleteDirectory(file);
         }
      }
      return dir.delete();
   }
}
