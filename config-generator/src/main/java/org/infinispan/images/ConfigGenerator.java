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
import java.nio.file.StandardOpenOption;
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

import io.quarkus.qute.RawString;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateExtension;
import io.quarkus.qute.api.ResourcePath;

@ApplicationScoped
public class ConfigGenerator {

   static final String INFINISPAN_FILE = "infinispan.xml";
   static final String LOGGING_FILE = "log4j2.xml";
   static final String JGROUPS_UDP_FILE = "jgroups-udp.xml";
   static final String JGROUPS_TCP_FILE = "jgroups-tcp.xml";
   static final String JGROUPS_RELAY_FILE = "jgroups-relay.xml";

   @Inject
   Template infinispan;

   @Inject
   @ResourcePath(JGROUPS_RELAY_FILE)
   Template jgroupsRelay;

   @Inject
   @ResourcePath(JGROUPS_TCP_FILE)
   Template jgroupsTcp;

   @Inject
   @ResourcePath(JGROUPS_UDP_FILE)
   Template jgroupsUdp;

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

      // Generate JGroups stack files
      configureJGroups(config, outputDir);

      // Generate Logging configuration
      createFileAndRenderTemplate(outputDir, LOGGING_FILE, config, log4j2);

      // Generate Infinispan configuration
      createFileAndRenderTemplate(outputDir, INFINISPAN_FILE, config, infinispan);
   }

   void configureJGroups(Map<String, Object> config, File outputDir) throws Exception {
      String transport = get(config, "jgroups.transport");
      boolean udp = "udp".equalsIgnoreCase(transport);
      Template template = udp ? jgroupsUdp : jgroupsTcp;
      String fileName = udp ? JGROUPS_UDP_FILE : JGROUPS_TCP_FILE;
      createFileAndRenderTemplate(outputDir, fileName, config, template);

      configureJGroupsRelay(config, outputDir);
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
      ks.put("selfSignCert", "false");

      // If ks.path == null then use default for keystore
      String path = ks.get("path");
      File ksRoot = path != null && !path.trim().isEmpty() ?
            new File(path).getParentFile() :
            new File(outputDir, "keystores");
      ksRoot.mkdirs();

      // If user provides a key/cert in ks.crtPath then build a keystore from them and store it in ks.path (overwriting
      // any eventual content in ks.path)
      String crtPath = ks.get("crtPath");
      if (crtPath != null && !crtPath.trim().isEmpty()) {
         ks.putIfAbsent("path", new File(ksRoot, "keystore.p12").getPath());

         String type = ks.get("type").toLowerCase();
         File keystore = new File(ksRoot, "keystore." + type);
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
               keystore.getPath(),
               "-name",
               ks.get("alias"),
               "-password",
               "pass:" + password
         ).toArray(new String[0]);

         exec(cmd);

         // Load the pkcs12 keystore
         KeyStore keyStore = KeyStore.getInstance(type);
         try (InputStream is = new FileInputStream(keystore)) {
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
      Files.writeString(filePath, template.data(data).render(), StandardOpenOption.CREATE);
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
            String.format("<%1$s>%2$s</%1$s>", elementName, String.join(",", list));
      return new RawString(element);
   }
}
