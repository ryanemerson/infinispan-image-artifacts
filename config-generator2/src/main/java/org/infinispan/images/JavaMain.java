package org.infinispan.images;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;

/**
 * Entry point to allow IDE execution.
 */
@QuarkusMain
public class JavaMain {
   public static void main(String[] args) {
      Quarkus.run(Main.class, args);
   }
}
