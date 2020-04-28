package org.infinispan.images;

import javax.inject.Inject;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class MainTest extends AbstractMainTest {

   @Inject
   Main main;

   @Override
   int execute(String... args) {
      return main.run(args);
   }
}
