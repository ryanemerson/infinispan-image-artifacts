package org.infinispan.images

import groovy.util.slurpersupport.GPathResult
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import org.yaml.snakeyaml.Yaml

class ConfigTest {

    private static final String ALLOWED_HEADERS = 'allowed-headers'
    private static final String ALLOWED_METHODS = 'allowed-methods'
    private static final String ALLOWED_ORIGINS = 'allowed-origins'
    private static final String CORS_RULE = 'cors-rule'
    private static final String CORS_RULES = 'cors-rules'
    private static final String EXPOSE_HEADERS = 'expose-headers'
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

    @Test
    void testCorsRules() {
        createConfig """
            |endpoints:
            |  rest:
            |    cors:
            |      - name: restrict-host1
            |        allowedOrigins:
            |          - http://host1
            |          - https://host1
            |        allowedMethods:
            |          - GET
            |
            |      - name: allow-all
            |        allowCredentials: true
            |        allowedOrigins:
            |          - '*'
            |        allowedMethods:
            |          - GET
            |          - OPTIONS
            |          - POST
            |          - PUT
            |          - DELETE
            |        allowedHeaders:
            |          - X-Custom-Header
            |          - Upgrade-Insecure-Requests
            |        exposeHeaders:
            |          - Key-Content-Type
            |        maxAgeSeconds: 1
            """
        def ispn = ispnXml()
        assert !ispn.server.endpoints[REST_ENDPOINT].isEmpty()
        assert 'restrict-host1' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0].@name.toString()
        assert !ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0].@'allow-credentials'.toBoolean()
        assert 0 == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0].@'max-age-seconds'.toInteger()
        assert 'http://host1,https://host1' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0][ALLOWED_ORIGINS].toString()
        assert 'GET' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0][ALLOWED_METHODS].toString()
        assert ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0][ALLOWED_HEADERS].isEmpty()
        assert ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][0][EXPOSE_HEADERS].isEmpty()

        assert 'allow-all' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1].@name.toString()
        assert ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1].@'allow-credentials'.toBoolean()
        assert 1 == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1].@'max-age-seconds'.toInteger()
        assert '*' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1][ALLOWED_ORIGINS].toString()
        assert 'X-Custom-Header,Upgrade-Insecure-Requests' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1][ALLOWED_HEADERS].toString()
        assert 'Key-Content-Type' == ispn.server.endpoints[REST_ENDPOINT][CORS_RULES][CORS_RULE][1][EXPOSE_HEADERS].toString()
    }

    @Test
    void testJGroupsEncryptionUdp() {
        testJGroupsEncryption 'udp'
        testJGroupsEncryption 'udp', true
    }

    @Test
    void testJGroupsEncryptionTcp() {
        testJGroupsEncryption 'tcp'
        testJGroupsEncryption 'tcp', true
    }

    private static void testJGroupsEncryption(String protocol, boolean enabled=false) {
        createConfig """
            |jgroups:
            |  encrypt: ${enabled}
            |  transport: ${protocol}
            """
        def xml = new XmlSlurper().parse(new File(outputDir, "jgroups-${protocol}.xml"))
        if (enabled) {
            assert !xml.ASYM_ENCRYPT.@'use_external_key_exchange'.toBoolean()
            assert 'AES/ECB/PKCS5Padding' == xml.ASYM_ENCRYPT.@'sym_algorithm'.toString()
            assert '512' == xml.ASYM_ENCRYPT.@'asym_keylength'.toString()
            assert 'RSA' == xml.ASYM_ENCRYPT.@'asym_algorithm'.toString()
        } else {
            assert xml.ASYM_ENCRYPT.isEmpty()
        }
    }

    @Test
    void testJGroupsDiagnosticsDefaultUdp() {
        createConfig """
            |jgroups:
            |  transport: udp
            """
        testDiagnostics 'jgroups-udp.xml', 'UDP', false
    }

    @Test
    void testEnableJGroupsDiagnosticsUDP() {
        createConfig """
            |jgroups:
            |  transport: udp
            |  diagnostics: true
            """
        testDiagnostics 'jgroups-udp.xml', 'UDP', true
    }

    @Test
    void testJGroupsDiagnosticsDefaultTCP() {
        testJGroupsDiagnosticsTcp false
    }

    @Test
    void testEnableJGroupsDiagnosticsTCP() {
        testJGroupsDiagnosticsTcp true
    }

    private static void testJGroupsDiagnosticsTcp(boolean enabled) {
        String diagnosticsYaml = """\n
            |jgroups:
            |  diagnostics: true
            """
        String xsiteYaml = """
            |xsite:
            |  address:
            |    name: LON
            |    port: 7200
            |  backups:
            |    - address:
            |      name: NYC
            |      port: 7200
            """
        String config = enabled ? diagnosticsYaml + xsiteYaml : xsiteYaml
        createConfig config
        testDiagnostics 'jgroups-tcp.xml', 'TCP', enabled
        testDiagnostics 'jgroups-relay.xml', 'TCP', enabled
    }

    private static void testDiagnostics(String fileName, String protocol, boolean enabled) {
        def xml = new XmlSlurper().parse(new File(outputDir, fileName))
        assert enabled == xml[protocol].@'enable_diagnostics'.toBoolean()
    }

    private static createConfig(String yaml = "") {
        Map userConfig = new Yaml().load(yaml.stripMargin())
        Config.process(userConfig, outputDir)
    }

    private static GPathResult ispnXml() {
        new XmlSlurper().parse(new File(outputDir, 'infinispan.xml'))
    }
}
