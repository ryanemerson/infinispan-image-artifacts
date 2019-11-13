package org.infinispan.images

import org.yaml.snakeyaml.Yaml

import static org.infinispan.images.Util.*

static void create(userFile, File outputDir) {
    Map userConfig = !userFile ? null : new Yaml().load(new File(userFile).newInputStream())
    process userConfig, outputDir
}

static void process(Map userConfig, File outputDir) {
    Map defaultConfig = new Yaml().load(Config.classLoader.getResourceAsStream('default-config.yaml'))
    // Add bindAddress to defaults
    defaultConfig.jgroups.bindAddress = InetAddress.localHost.hostAddress

    // If no user config then use defaults, otherwise merge user config and default config
    Map configYaml = !userConfig ? defaultConfig : mergeMaps(defaultConfig, userConfig)

    // Configure  keystores if required
    configureKeystore configYaml.keystore, outputDir

    // Generate JGroups stack files
    def transport = configYaml.jgroups.transport
    proccessXmlTemplate "jgroups-${transport}.xml", new File(outputDir, "jgroups-${transport}.xml"), configYaml

    if (configYaml.xsite?.backups)
        proccessXmlTemplate "jgroups-relay.xml", new File(outputDir, "jgroups-relay.xml"), configYaml

    // Generate Infinispan configuration
    proccessXmlTemplate 'infinispan.xml', new File(outputDir, 'infinispan.xml'), configYaml

    // Generate Logging configuration
    processPropertiesTemplate 'logging.properties', new File(outputDir, 'logging.properties'), configYaml
}

static void configureKeystore(ks, File outputDir) {
    if (!ks.path?.trim() && !ks.crtPath?.trim()) {
        if (ks.selfSignCert) {
            ks.password = "infinispan"
            ks.path = "${outputDir}selfsigned_keystore.p12"
            ks.alias = "server"
        }
        return
    }

    // If path is defined then ignore selfSignCert
    ks.selfSignCert = false

    // If ks.path == null then use default for keystore
    def ksRoot = ks.path == null ? new File(outputDir, 'keystores') : new File(ks.path).parentFile
    ksRoot.mkdirs()
    ksRoot = addSeparator ksRoot.getAbsolutePath()

    // If user provides a key/cert in ks.crtPath then build
    // a keystore from them and store it in ks.path (overwriting
    // any eventual content in ks.path)
    if (ks.crtPath != null) {
        String crtSrc = addSeparator((String) ks.crtPath)
        String ksPkcs = "${ksRoot}keystore.pkcs12"

        // Add values to the map so they can be used in the templates
        ks.path = ks.path ?: "${ksRoot}keystore.p12"
        ks.password = ks.password ?: "infinispan"

        exec "openssl pkcs12 -export -inkey ${crtSrc}tls.key -in ${crtSrc}tls.crt -out ${ksPkcs} -name ${ks.alias} -password pass:${ks.password}"

        exec "keytool -importkeystore -noprompt -srckeystore ${ksPkcs} -srcstoretype pkcs12 -srcstorepass ${ks.password} -srcalias ${ks.alias} " +
                "-destalias ${ks.alias} -destkeystore ${ks.path} -deststoretype pkcs12 -storepass ${ks.password}"
    }
}
