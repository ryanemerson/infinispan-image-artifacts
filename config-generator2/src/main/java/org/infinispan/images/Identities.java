package org.infinispan.images;

import static org.infinispan.images.Util.get;
import static org.infinispan.images.Util.loadYaml;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
class Identities {
   void process(File identitiesConfig, File outputDir) throws IOException {
      Map<String, Object> userConfig = loadYaml(identitiesConfig);
      processCredentials(get(userConfig, "credentials"), outputDir);
   }

   static void processCredentials(ArrayList<Map<String, Object>> credentials, File outputDir) throws IOException {
      if (credentials == null)
         return;

      Properties users = new Properties();
      Properties groups = new Properties();
      for (Map<String, Object> c : credentials) {
         var username = c.get("username");
         var password = c.get("password");
         if (username == null || password == null) {
            System.err.println("Credential identities require both a 'username' and 'password'");
            System.exit(1);
         }
         users.put(username, password);

         List<String> roles = (List<String>) c.get("roles");
         if (roles != null)
            groups.put(username, String.join(",", roles));

         try (Writer usersWriter = new FileWriter(new File(outputDir, "users.properties"));
         Writer groupsWriter = new FileWriter(new File(outputDir, "groups.properties"))) {
            users.store(usersWriter, "$REALM_NAME=default$");
            groups.store(groupsWriter, null);
         }
      }
   }
}
