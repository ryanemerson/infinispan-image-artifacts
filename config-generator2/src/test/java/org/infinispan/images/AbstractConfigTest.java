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

abstract class AbstractConfigTest {

   static File outputDir;

   @BeforeAll
   static void setup() {
      var suffix = System.getProperty("native.image.path") != null ? "-Native" : "";
      var path = System.getProperty("java.io.tmpdir") + File.separator + "ConfigTest" + suffix;
      outputDir = new File(path);
      outputDir.mkdir();
   }

   @AfterAll
   static void teardown() {
      deleteDirectory(outputDir);
   }

   @AfterEach
   void cleanup() {
      for(File file: outputDir.listFiles())
         file.delete();
   }

   abstract void execute(String... args) throws Exception;

   @Test
   void testChangeInfinispanServerName() throws Exception {
      generate("server-name")
            .infinispan()
            .hasXPath("//i:infinispan/i:cache-container/i:transport[@cluster='customClusterName']");
   }

   @Test
   void testMemcachedDisabledByDefault() throws Exception {
      generateDefault()
            .infinispan()
            .doesNotHaveXPath("//i:infinispan/s:server/s:endpoints/s:memcached-connector");
   }

   @Test
   void testEnableMemcached() throws Exception {
      generate("memcached-enabled")
            .infinispan()
            .hasXPath("//i:infinispan/s:server/s:endpoints/s:memcached-connector");
   }

   @Test
   void testRestAuthEnabledByDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:rest-connector/s:authentication");
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:rest-connector/s:authentication[@mechanisms='DIGEST']");
   }

   @Test
   void testRestDisabled() throws Exception {
      generate("rest-disabled")
            .infinispan()
            .doesNotHaveXPath("//i:infinispan/s:server/s:endpoints/s:rest-connector");
   }

   @Test
   void testRestAuthDisabled() throws Exception {
      XmlAssert xml = generate("rest-auth-disabled").infinispan();
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:rest-connector");
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:endpoints/s:rest-connector/s:authentication");
   }

   @Test
   void testRestCorsRules() throws Exception {
      XmlAssert xml = generate("rest-cors-rules").infinispan();
      String rulesPath = "//i:infinispan/s:server/s:endpoints/s:rest-connector/s:cors-rules/";
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
   void testHotRodAuthEnabledByDefault() throws Exception {
      XmlAssert xml = generateDefault().infinispan();
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:hotrod-connector/s:authentication/s:sasl");
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:hotrod-connector/s:authentication/s:sasl[@server-name='infinispan']");
   }

   @Test
   void testHotRodDisabled() throws Exception {
      generate("hotrod-disabled")
            .infinispan()
            .doesNotHaveXPath("//i:infinispan/s:server/s:endpoints/s:hotrod-connector");
   }

   @Test
   void testHotRodAuthDisabled() throws Exception {
      XmlAssert xml = generate("hotrod-auth-disabled").infinispan();
      xml.hasXPath("//i:infinispan/s:server/s:endpoints/s:hotrod-connector");
      xml.doesNotHaveXPath("//i:infinispan/s:server/s:endpoints/s:hotrod-connector/s:authentication");
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
      XmlAssert xml = generate("jgroups-udp").jgroupsUdp();
      testJgroupsDiagnostics(xml, "udp", false);
   }

   @Test
   void testJGroupsDiagnosticsUdp() throws Exception {
      XmlAssert xml = generate("jgroups-diagnostics-udp").jgroupsUdp();
      testJgroupsDiagnostics(xml, "udp", true);
   }

   @Test
   void testJGroupsTcp() throws Exception {
      XmlAssert xml = generateDefault().jgroupsTcp();
      testJgroupsDiagnostics(xml, "tcp", false)
            .haveAttribute("bind_addr", InetAddress.getLocalHost().getHostAddress());
   }

   @Test
   void testJGroupsDiagnosticsTcp() throws Exception {
      XmlAssert xml = generate("jgroups-diagnostics-tcp").jgroupsTcp();
      testJgroupsDiagnostics(xml, "tcp", true)
            .haveAttribute("bind_addr", InetAddress.getLocalHost().getHostAddress());
   }

   MultipleNodeAssert testJgroupsDiagnostics(XmlAssert xml, String protocol, boolean enabled) throws Exception {
      return xml.hasXPath(String.format("//j:config/j:%s", protocol.toUpperCase()))
            .haveAttribute("enable_diagnostics", Boolean.toString(enabled));
   }

   @Test
   void testJGroupsEncryptionDefault() throws Exception {
      XmlAssert xml = generateDefault().jgroupsTcp();
      xml.doesNotHaveXPath("//j:config/j:ASYM_ENCRYPT");
      xml.doesNotHaveXPath("//j:config/j:SERIALIZE");
   }

   @Test
   void testJGroupsEncryptionEnabled() throws Exception {
      XmlAssert xml = generate("jgroups-encryption").jgroupsTcp();
      xml.hasXPath("//j:config/j:ASYM_ENCRYPT")
            .haveAttribute("use_external_key_exchange", "false");

      xml.hasXPath("//j:config/j:SERIALIZE");
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

      Path configPath = Paths.get(outputDir.getAbsolutePath(), "jgroups-encryption-keystore");
      Files.writeString(configPath, yaml);
      execute(String.format("--config=%s", configPath), outputDir.getAbsolutePath());

      XmlAssert xml = jgroupsTcp();
      xml.hasXPath("//j:config/j:SSL_KEY_EXCHANGE")
            .haveAttribute("keystore_name", new File(outputDir, "keystores/keystore.p12").getAbsolutePath())
            .haveAttribute("keystore_password", "infinispan")
            .haveAttribute("keystore_type", "pkcs12");

      xml.hasXPath("//j:config/j:ASYM_ENCRYPT")
            .haveAttribute("use_external_key_exchange", "true");

      xml.hasXPath("//j:config/j:SERIALIZE");
   }

   @Test
   void testCredentialIdentities() throws Exception {
      String path = new File("src/test/resources/identities", "identities.yaml").getAbsolutePath();
      execute(String.format("--identities=%s", path), outputDir.getAbsolutePath());

      Properties userProps = loadPropertiesFile("users.properties");
      assertEquals(2, userProps.size());
      assertEquals("pass", userProps.get("user1"));
      assertEquals("pass", userProps.get("user2"));

      Properties groupProps = loadPropertiesFile("groups.properties");
      assertEquals(2, groupProps.size());
      assertEquals("admin,rockstar", groupProps.get("user1"));
      assertEquals("non-admin", groupProps.get("user2"));
   }

   private AbstractConfigTest generateDefault() throws Exception {
      execute(outputDir.getAbsolutePath());
      return this;
   }

   private AbstractConfigTest generate(String configName) throws Exception {
      String path = new File("src/test/resources/config", configName + ".yaml").getAbsolutePath();
      execute(String.format("--config=%s", path), outputDir.getAbsolutePath());
      return this;
   }

   private XmlAssert infinispan() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), Config.INFINISPAN_FILE));

      Map<String, String> prefix2Uri = new HashMap<>();
      prefix2Uri.put("i", "urn:infinispan:config:11.0");
      prefix2Uri.put("s", "urn:infinispan:server:11.0");
      return assertThat(config).withNamespaceContext(prefix2Uri);
   }

   private XmlAssert logging() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), Config.LOGGING_FILE));
      return assertThat(config);
   }

   private XmlAssert jgroupsUdp() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), Config.JGROUPS_UDP_FILE));
      return jgroups(config);
   }

   private XmlAssert jgroupsTcp() throws Exception {
      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), Config.JGROUPS_TCP_FILE));
      return jgroups(config);
   }

   private XmlAssert jgroups(String config) {
      Map<String, String> prefix2Uri = new HashMap<>();
      prefix2Uri.put("j", "urn:org:jgroups");
      return assertThat(config).withNamespaceContext(prefix2Uri);
   }

   private static Properties loadPropertiesFile(String name) throws Exception {
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
