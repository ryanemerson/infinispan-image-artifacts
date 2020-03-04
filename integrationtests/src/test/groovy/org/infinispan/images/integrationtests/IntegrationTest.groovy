package org.infinispan.images.integrationtests

import org.infinispan.client.hotrod.RemoteCache
import org.infinispan.commons.test.CommonsTestingUtil
import org.infinispan.images.Main
import org.infinispan.server.test.core.ServerRunMode
import org.infinispan.server.test.junit4.InfinispanServerRule
import org.infinispan.server.test.junit4.InfinispanServerRuleBuilder
import org.infinispan.server.test.junit4.InfinispanServerTestMethodRule
import org.junit.ClassRule
import org.junit.Rule
import org.junit.Test

class IntegrationTest {

   @ClassRule
   static InfinispanServerRule classRule() {
      String outputDir = CommonsTestingUtil.tmpDirectory(IntegrationTest.class)
      new File(outputDir).mkdir()
      URL configUrl = IntegrationTest.classLoader.getResource('HotRodNoAuth.yaml')
      Main.main outputDir, "--config=${configUrl.path}"
      println(outputDir)

      String serverConfig = new File(outputDir, 'conf/infinispan.xml').toString()
      InfinispanServerRuleBuilder.config(serverConfig )
            .numServers(2)
            .runMode(ServerRunMode.CONTAINER)
            .build()
   }

   @Rule
   public InfinispanServerTestMethodRule SERVER_TEST = new InfinispanServerTestMethodRule(classRule())

   @Test
   void testHotRodAuthDisabled() {
      RemoteCache<String, String> cache = SERVER_TEST.hotrod().create()
      cache.put 'k1', 'v1'
      assert 1, cache.size()
   }
}
