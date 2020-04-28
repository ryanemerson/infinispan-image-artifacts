package org.infinispan.images;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Map;

import javax.inject.Inject;

import org.yaml.snakeyaml.Yaml;

import io.quarkus.runtime.QuarkusApplication;


public class Main implements QuarkusApplication {

    @Inject
    Config config;

    @Override
    public int run(String... args) throws Exception {
        // TODO can we get picocli cli builder to work with Quarkus?
        // 3. Use yaml to pass to Template
        // 4. Make sure works with native
        // 5. Convert log4j2 template
        // 6. Convert infinispan.xml
        // 7. Convert jgroups

        System.out.println(args[0]);
        System.out.println(args[1]);
        System.out.println(args[2]);
        String configFile = args[0].split("=")[1];

        try (InputStream is = new FileInputStream(new File(configFile))) {
            Map<String, Object> m = new Yaml().load(is);
            m.forEach((k, v) -> System.out.println(String.format("k=%s, v=%s", k, v)));
            config.process(m, new File("/tmp"));
        }
        return 10;
    }
}
