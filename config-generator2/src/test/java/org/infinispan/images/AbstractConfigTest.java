package org.infinispan.images;

import static org.xmlunit.assertj.XmlAssert.assertThat;

import java.io.File;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.transform.stream.StreamSource;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xmlunit.assertj.XmlAssert;
import org.xmlunit.validation.Languages;
import org.xmlunit.validation.ValidationProblem;
import org.xmlunit.validation.ValidationResult;
import org.xmlunit.validation.Validator;

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

   abstract void execute(String... args) throws Exception;

   @Test
   void testMemcachedDisabledByDefault() throws Exception {
      defaultConfig().doesNotHaveXPath("//server/endpoints/memcached-connector");
   }

   @Test
   void testEnableMemcached() throws Exception {
      config("memcached-enabled").hasXPath("/ispn:infinispan/ispn:jgroups");
   }

   private XmlAssert defaultConfig() throws Exception {
      return config(null);
   }

   private XmlAssert config(String configName) throws Exception {
      if (configName == null) {
         execute(outputDir.getAbsolutePath());
      } else {
         String path = new File("src/test/resources/config", configName + ".yaml").getAbsolutePath();
         execute(String.format("--config=%s", path), outputDir.getAbsolutePath());
      }

      String config = Files.readString(Paths.get(outputDir.getAbsolutePath(), "infinispan.xml"));

      // TODO add xml validation
      try (InputStream coreSchema = AbstractConfigTest.class.getResourceAsStream("/schema/infinispan-config-11.0.xsd");
           InputStream serverSchema = AbstractConfigTest.class.getResourceAsStream("/schema/infinispan-server-11.0.xsd")) {
         Validator v = Validator.forLanguage(Languages.W3C_XML_SCHEMA_NS_URI);
         v.setSchemaSources(new StreamSource(coreSchema), new StreamSource(serverSchema));

         ValidationResult r = v.validateInstance(new StreamSource(new StringReader(config)));
         Iterator<ValidationProblem> probs = r.getProblems().iterator();
         while (probs.hasNext()) {
            System.err.println(probs.next().toString());
         }
      }
      Map<String, String> prefix2Uri = new HashMap<>();
      prefix2Uri.put("ispn", "urn:infinispan:config:11.0");
      prefix2Uri.put("server", "urn:infinispan:server:11.0");
      return assertThat(config).withNamespaceContext(prefix2Uri);
   }

   // TODO move to AbstractIdentitiesTest
   private void withIdentities(String identitiesFile) throws Exception {
      String path = new File("src/test/resources/identities", identitiesFile).getAbsolutePath();
      execute(String.format("--identities=%s", path), outputDir.getAbsolutePath());
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
