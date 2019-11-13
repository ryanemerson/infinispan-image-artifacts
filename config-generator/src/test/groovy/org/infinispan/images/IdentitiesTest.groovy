package org.infinispan.images

import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test
import org.yaml.snakeyaml.Yaml

class IdentitiesTest {

    static File outputDir;

    @BeforeClass
    static void setup() {
        def path = "${System.properties['java.io.tmpdir']}/${IdentitiesTest.getSimpleName()}"
        outputDir = new File(path)
        outputDir.mkdir()
    }

    @AfterClass
    static void teardown() {
        outputDir.deleteDir()
    }

    @Test
    void testCredentialsWritten() {
        createIdentities '''
            |credentials:
            |  - username: user1
            |    password: pass
            |    preDigestedPassword: true
            |    roles:
            |    - admin
            |    - rockstar
            |
            |  - username: user2
            |    password: pass
            |    roles:
            |    - non-admin
            '''

        Properties userProps = loadPropertiesFile('users.properties')
        assert 2 == userProps.size()
        // If as 'preDigestedPassword' is true for user1, the stored password should still be 'pass'
        assert 'pass' == userProps.get('user1')
        assert 'pass' != userProps.get('user2')

        Properties groupProps = loadPropertiesFile('groups.properties')
        assert 2 == groupProps.size()
        assert 'admin,rockstar' == groupProps.get('user1')
        assert 'non-admin' == groupProps.get('user2')
    }

    private static createIdentities(String yaml = '') {
        Map userConfig = new Yaml().load(yaml.stripMargin())
        Identities.process(userConfig, outputDir)
    }

    private static Properties loadPropertiesFile(String name) {
        Properties properties = new Properties()
        File propsFile = new File(outputDir, name)
        propsFile.withInputStream {
            properties.load(it)
        }
        properties
    }
}
