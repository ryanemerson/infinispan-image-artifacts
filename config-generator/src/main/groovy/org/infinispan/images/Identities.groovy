package org.infinispan.images

import org.yaml.snakeyaml.Yaml

import java.security.MessageDigest

import static org.infinispan.images.Util.printErrorAndExit

static void create(String userFile, File outputDir) {
    Map identities = new Yaml().load(new File(userFile).newInputStream())
    process identities, outputDir
}

static void process(Map identities, File outputDir) {
    processCredentials identities.credentials, outputDir
}

static void processCredentials(credentials, File outputDir, realm = "default") {
    if (!credentials) return

    def (users, groups) = [new Properties(), new Properties()]
    credentials.each { c ->
        if (!c.username || !c.password) printErrorAndExit "Credential identities require both a 'username' and 'password'"

        if (c.preDigestedPassword) {
            users.put c.username, c.password
        } else {
            MessageDigest md5 = MessageDigest.getInstance "MD5"
            String hash = md5.digest("${c.username}:${realm}:${c.password}".getBytes("UTF-8")).encodeHex().toString()
            users.put c.username, hash
        }

        if (c.roles) groups.put c.username, c.roles.join(",")
    }
    users.store new File(outputDir, 'users.properties').newWriter(), "\$REALM_NAME=${realm}\$"
    groups.store new File(outputDir, 'groups.properties').newWriter(), null
}
