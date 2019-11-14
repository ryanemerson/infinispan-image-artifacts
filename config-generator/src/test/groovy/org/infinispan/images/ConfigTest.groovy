package org.infinispan.images

import groovy.util.slurpersupport.GPathResult
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import org.yaml.snakeyaml.Yaml

class ConfigTest {

    private static final String HOTROD_ENDPOINT = 'hotrod-connector'
    private static final String MEMCACHED_ENDPOINT = 'memcached-connector'
    private static final String REST_ENDPOINT = 'rest-connector'
    static File outputDir;

    @BeforeClass
    static void setup() {
        def path = "${System.properties['java.io.tmpdir']}/${ConfigTest.getSimpleName()}"
        outputDir = new File(path)
        outputDir.mkdir()
    }

    @AfterClass
    static void teardown() {
        outputDir.deleteDir()
    }

    @Test
    void testMemcachedDisabledByDefault() {
        createConfig()
        assert ispnXml().server.endpoints[MEMCACHED_ENDPOINT].isEmpty()
    }

    @Test
    void testEnableMemcached() {
        createConfig '''
            |endpoints:
            |  memcached:
            |    enabled: true
            '''
        assert !ispnXml().server.endpoints[MEMCACHED_ENDPOINT].isEmpty()
    }

    @Test
    void testRestAuthEnabledByDefault() {
        createConfig()
        def ispn = ispnXml()
        assert !ispn.server.endpoints[REST_ENDPOINT].authentication.isEmpty()
        assert 'DIGEST' == ispn.server.endpoints[REST_ENDPOINT].authentication.@mechanisms.toString()
        assert 'default' == ispn.server.endpoints[REST_ENDPOINT].authentication.@'security-realm'.toString()
    }

    @Test
    void testRestDisabled() {
        createConfig '''
            |endpoints:
            |  rest:
            |    enabled: false
            '''
        assert ispnXml().server.endpoints[REST_ENDPOINT].isEmpty()
    }

    @Test
    void testRestAuthDisabled() {
        createConfig '''
            |endpoints:
            |  rest:
            |    auth: false
            '''
        def ispn = ispnXml()
        assert !ispn.server.endpoints[REST_ENDPOINT].isEmpty()
        assert ispn.server.endpoints[REST_ENDPOINT].authentication.isEmpty()
    }

    @Test
    void testHotRodAuthEnabledByDefault() {
        createConfig()
        def ispn = ispnXml()
        assert !ispn.server.endpoints[HOTROD_ENDPOINT].authentication.sasl.isEmpty()
        assert 'default' == ispn.server.endpoints[HOTROD_ENDPOINT].authentication.@'security-realm'.toString()
        assert 'infinispan' == ispn.server.endpoints[HOTROD_ENDPOINT].authentication.sasl.@'server-name'.toString()
    }

    @Test
    void testHotRodDisabled() {
        createConfig '''
            |endpoints:
            |  hotrod:
            |    enabled: false
            '''
        assert ispnXml().server.endpoints[HOTROD_ENDPOINT].isEmpty()
    }

    @Test
    void testHotRodAuthDisabled() {
        createConfig '''
            |endpoints:
            |  hotrod:
            |    auth: false
            '''
        def ispn = ispnXml()
        assert !ispn.server.endpoints[HOTROD_ENDPOINT].isEmpty()
        assert ispn.server.endpoints[HOTROD_ENDPOINT].authentication.isEmpty()
    }

    @Test
    void testChangeInfinispanServerName() {
        String customName = 'customClusterName'
        createConfig """
            |infinispan:
            |  clusterName: ${customName}
            """
        assert 'customClusterName' == ispnXml()['cache-container'].transport.@cluster.toString()
    }

    private static createConfig(String yaml = "") {
        Map userConfig = new Yaml().load(yaml.stripMargin())
        Config.process(userConfig, outputDir)
    }

    private static GPathResult ispnXml() {
        new XmlSlurper().parse(new File(outputDir, 'infinispan.xml'))
    }
}
