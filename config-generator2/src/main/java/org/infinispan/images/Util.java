package org.infinispan.images;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

public class Util {

   static Map<String, Object> loadYamlFromResources(String name) throws IOException {
      try (InputStream is = Util.class.getClassLoader().getResourceAsStream(name)) {
         return new Yaml().load(is);
      }
   }

   static Map<String, Object> loadYaml(File file) throws IOException {
      try (InputStream is = new FileInputStream(file)) {
         return new Yaml().load(is);
      }
   }

   static void merge(Map<String, Object> lhs, Map<String, Object> rhs) {
      if (rhs == null)
         return;

      for (String key : rhs.keySet()) {
         Object leftValue = lhs.get(key);
         if (leftValue instanceof Map) {
            //noinspection unchecked
            merge((Map<String, Object>) lhs.get(key), (Map<String, Object>) rhs.get(key));
         } else {
            lhs.put(key, rhs.get(key));
         }
      }
   }

   @SuppressWarnings("unchecked")
   static <T> T get(Map<String, Object> config, String path) {
      if (config.isEmpty() || path == null)
         return null;

      var keys = path.split("\\.");
      Map<String, Object> map = config;
      for (int i = 0; i < keys.length; i++) {
         if (i + 1 == keys.length) {
            return (T) map.get(keys[i]);
         } else {
            Object obj = config.get(keys[i]);
            if (obj == null)
               return null;

            map = (Map<String, Object>) config.get(keys[i]);
         }
      }
      return (T) config.get(path);
   }
}
