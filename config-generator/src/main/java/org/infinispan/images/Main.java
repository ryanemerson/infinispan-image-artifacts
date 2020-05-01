package org.infinispan.images;

import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;
import static picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;

import javax.inject.Inject;

import io.quarkus.runtime.QuarkusApplication;
import picocli.CommandLine;

public class Main implements QuarkusApplication {

   @Inject
   ConfigGenerator configGenerator;

   @Inject
   IdentitiesGenerator identitiesGenerator;

   @Override
   public int run(String... args) {
      return new CommandLine(new MainCommand())
            .execute(args);
   }

   @Command(name = "config-generator")
   class MainCommand implements Callable<Integer> {

      @Option(
            names = {"-c", "--config"},
            description = {"Yaml file used to generate Infinispan configuration"}
      )
      File server;

      @Option(
            names = {"-i", "--identities"},
            description = {"Yaml file used to initialize identities"}
      )
      File identities;

      @Parameters(
            index = "0",
            description = {"The directory where the generated files will be saved"},
            paramLabel = "output-dir"
      )
      File outputDir;

      @Override
      public Integer call() throws Exception {
         configGenerator.process(server, outputDir);
         identitiesGenerator.process(identities, outputDir);
         return 0;
      }
   }
}
