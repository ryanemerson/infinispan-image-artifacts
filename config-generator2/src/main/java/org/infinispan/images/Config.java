package org.infinispan.images;

import static org.infinispan.images.Util.get;
import static org.infinispan.images.Util.loadYaml;
import static org.infinispan.images.Util.loadYamlFromResources;
import static org.infinispan.images.Util.merge;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateExtension;
import io.quarkus.qute.api.ResourcePath;

// Rename to ConfigGenerator & Identities  -> IdentitiesGenerator
@ApplicationScoped
public class Config {

   @Inject
   Template infinispan;

   @Inject
   @ResourcePath("jgroups-relay.xml")
   Template jgroupsRelay;

   @Inject
   @ResourcePath("jgroups-tcp.xml")
   Template jgroupsTcp;

   @Inject
   @ResourcePath("jgroups-udp.xml")
   Template jgroupsUdp;

   @Inject
   Template log4j2;

   void process(File serverConfig, File outputDir) throws IOException {
      Map<String, Object> userConfig = loadYaml(serverConfig);
      Map<String, Object> config = loadYamlFromResources("default-config.yaml");

      ((Map<String, Object>) config.get("jgroups")).put("bindAddress", InetAddress.getLocalHost().getHostAddress());

      // Merge the user config and default config, if no user config provided then the default map is unchanged
      merge(config, userConfig);

      // Configure  keystores if required
      configureKeystore(config, outputDir);

      // Generate JGroups stack files
      configureJGroups(config, outputDir);

      // Generate Logging configuration
      createFileAndRenderTemplate(outputDir, "log4j2.xml", config, log4j2);

      // Generate Infinispan configuration
      createFileAndRenderTemplate(outputDir, "infinispan.xml", config, infinispan);
   }

   void configureJGroups(Map<String, Object> config, File outputDir) throws IOException {
      String transport = get(config, "jgroups.transport");
      Template template = "udp".equalsIgnoreCase(transport) ? jgroupsUdp : jgroupsTcp;
      String fileName = String.format("jgroups-%s.xml", transport);
      createFileAndRenderTemplate(outputDir, fileName, config, template);

      if (get(config, "xsite.backups") != null)
         createFileAndRenderTemplate(outputDir, fileName, config, jgroupsRelay);
   }

   void configureKeystore(Map<String, Object> config, File outputDir) {
      Map<String, Object> ks = get(config, "keystore");
      // TODO
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
}
