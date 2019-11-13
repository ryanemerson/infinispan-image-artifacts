package org.infinispan.images

import groovy.util.slurpersupport.GPathResult
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import org.yaml.snakeyaml.Yaml

class ConfigTest {

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
        assert ispnXml().server.endpoints['memcached-connector'].isEmpty()
    }

    @Test
    void testEnableMemcached() {
        createConfig '''
            |endpoints:
            |  memcached:
            |    enabled: true
            '''
        assert !ispnXml().server.endpoints['memcached-connector'].isEmpty()
    }

    @Test
    void testRestAuthEnabledByDefault() {
        createConfig()
        def ispn = ispnXml()
        assert !ispn.server.endpoints['rest-connector'].authentication.isEmpty()
        assert 'DIGEST' == ispn.server.endpoints['rest-connector'].authentication.@mechanisms.toString()
        assert 'default' == ispn.server.endpoints['rest-connector'].authentication.@'security-realm'.toString()
    }

    @Test
    void testHotRodAuthEnabledByDefault() {
        createConfig()
        def ispn = ispnXml()
        assert !ispn.server.endpoints['hotrod-connector'].authentication.sasl.isEmpty()
        assert 'default' == ispn.server.endpoints['hotrod-connector'].authentication.@'security-realm'.toString()
        assert 'infinispan' == ispn.server.endpoints['hotrod-connector'].authentication.sasl.@'server-name'.toString()
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
