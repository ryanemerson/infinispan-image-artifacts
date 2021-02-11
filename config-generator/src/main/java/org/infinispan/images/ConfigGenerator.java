package org.infinispan.images;

import static org.infinispan.images.Util.exec;
import static org.infinispan.images.Util.get;
import static org.infinispan.images.Util.loadYaml;
import static org.infinispan.images.Util.loadYamlFromResources;
import static org.infinispan.images.Util.merge;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import io.quarkus.qute.RawString;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateExtension;
import io.quarkus.qute.api.ResourcePath;

@ApplicationScoped
public class ConfigGenerator {

   static final String INFINISPAN_FILE = "infinispan.yaml";
   static final String LOGGING_FILE = "log4j2.xml";
   static final String JGROUPS_RELAY_FILE = "jgroups-relay.yaml";
   static final String JGROUPS_RELAY_TEMPLATE = "jgroups/relay.yaml";

   @Inject
   Template infinispan;

   @Inject
   @ResourcePath(JGROUPS_RELAY_TEMPLATE)
   Template jgroupsRelay;

   @Inject
   Template log4j2;

   void process(File serverConfig, File outputDir) throws Exception {
      Map<String, Object> userConfig = serverConfig == null ? null : loadYaml(serverConfig);
      Map<String, Object> config = loadYamlFromResources("default-config.yaml");

      ((Map<String, Object>) config.get("jgroups")).put("bindAddress", InetAddress.getLocalHost().getHostAddress());

      // Merge the user config and default config, if no user config provided then the default map is unchanged
      merge(config, userConfig);

      // Configure  keystores if required
      configureKeystore(config, outputDir);

      // Generate JGroups Xsite stack files
      configureJGroupsRelay(config, outputDir);

      // Generate Logging configuration
      createFileAndRenderTemplate(outputDir, LOGGING_FILE, config, log4j2);

      // Generate Infinispan configuration
      createFileAndRenderTemplate(outputDir, INFINISPAN_FILE, config, infinispan);
   }

   void configureJGroupsRelay(Map<String, Object> config, File outputDir) throws Exception {
      List<Map<String, String>> backups = get(config, "xsite.backups");
      if (backups == null)
         return;

      String remoteSites = backups.stream()
            .map(b -> String.format("%s[%s]", b.get("address"), b.get("port")))
            .collect(Collectors.joining(","));

      config.put("remoteSites", remoteSites);
      createFileAndRenderTemplate(outputDir, JGROUPS_RELAY_FILE, config, jgroupsRelay);
   }

   void configureKeystore(Map<String, Object> config, File outputDir) throws Exception {
      Map<String, String> ks = (Map<String, String>) config.computeIfAbsent("keystore", k -> new HashMap<>());
      boolean noPathProvided = List.of("path", "crtPath").stream().noneMatch(ks::containsKey);
      if (noPathProvided) {
         boolean selfSign = get(config, "keystore.selfSignCert");
         if (selfSign) {
            ks.put("password", "infinispan");
            ks.put("path", new File(outputDir, "selfsigned_keystore.p12").getAbsolutePath());
            ks.put("alias", "server");
         }
         return;
      }

      // If path is defined then ignore selfSignCert
      ks.remove("selfSignCert");

      String crtPath = ks.get("crtPath");
      if (crtPath == null || crtPath.trim().isEmpty()) {
         // No crtPath provided, so simply use the provided ks.path value
         return;
      }

      // User has provided a key/cert in ks.crtPath, so build a keystore using them and store it in ks.path (overwriting
      // any existing content in ks.path)
      File keystore;
      File ksRoot;
      String path = ks.get("path");
      if (path == null || path.trim().isEmpty()) {
         ksRoot = new File(outputDir, "keystores");
         keystore = new File(ksRoot, "keystore.p12");
         ks.put("path", keystore.getAbsolutePath());
      } else {
         keystore = new File(path);
         ksRoot = keystore.getParentFile();
      }
      ksRoot.mkdirs();

      String type = ks.get("type").toLowerCase();
      File openSslStore = new File(ksRoot, "keystore." + type);
      String password = ks.computeIfAbsent("password", k -> "infinispan");
      char[] ksPass = password.toCharArray();

      String[] cmd = List.of(
            "openssl",
            "pkcs12",
            "-export",
            "-inkey",
            new File(crtPath, "tls.key").getPath(),
            "-in",
            new File(crtPath, "tls.crt").getPath(),
            "-out",
            openSslStore.getPath(),
            "-name",
            ks.get("alias"),
            "-password",
            "pass:" + password
      ).toArray(new String[0]);

      exec(cmd);

      // Load the pkcs12 keystore
      KeyStore keyStore = KeyStore.getInstance(type);
      try (InputStream is = new FileInputStream(openSslStore)) {
         keyStore.load(is, ksPass);
      }

      // Add all certificates from provided CA file
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<String> certs = parseCAFile(ks.get("caFile"));

      for (int i = 0; i < certs.size(); i++) {
         String alias = "service-crt-" + (i < 10 ? "0" + i : i);
         byte[] bytes = certs.get(i).getBytes(StandardCharsets.UTF_8);
         try (InputStream is = Base64.getDecoder().wrap(new ByteArrayInputStream(bytes))) {
            keyStore.setCertificateEntry(alias, cf.generateCertificate(is));
         }
      }

      // Store the keystore
      try (OutputStream os = new FileOutputStream(keystore)) {
         keyStore.store(os, ksPass);
      }
   }

   static List<String> parseCAFile(String path) throws IOException {
      List<String> certs = new ArrayList<>();
      if (path == null || path.trim().isEmpty())
         return certs;

      StringBuilder sb = new StringBuilder();
      for (String line : Files.readAllLines(Paths.get(path))) {
         if (line.isEmpty() || line.contains("BEGIN CERTIFICATE"))
            continue;

         if (line.contains("END CERTIFICATE")) {
            certs.add(sb.toString());
            sb.setLength(0);
         } else {
            sb.append(line);
         }
      }
      return certs;
   }

   void createFileAndRenderTemplate(File outputDir, String fileName, Object data, Template template) throws IOException {
      Path filePath = new File(outputDir, fileName).toPath();
      Files.writeString(filePath, template.data(data).render());
   }

   @TemplateExtension
   static String upperCase(String value) {
      return value == null ? null : value.toUpperCase();
   }

   @TemplateExtension
   static String stack(String transport) {
      return "image" + transport;
   }

   @TemplateExtension
   static RawString listElement(List<String> list, String elementName) {
      String element = list == null || list.isEmpty() ? "" :
            String.format("%s: \"%s\"", elementName, String.join(",", list));
      return new RawString(element);
   }

   @TemplateExtension
   static RawString yaml(Map<String, Object> map) {
      // TODO cache Yaml instance
      // {endpoints.yaml}
      DumperOptions options = new DumperOptions();
      options.setIndent(2);
      options.setPrettyFlow(true);
      // Fix below - additional configuration
      options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
      return new RawString(new Yaml(options).dump(map));
   }
}
