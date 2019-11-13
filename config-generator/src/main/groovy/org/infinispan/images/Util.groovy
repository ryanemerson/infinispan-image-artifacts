package org.infinispan.images

import groovy.text.SimpleTemplateEngine
import groovy.text.TemplateEngine
import groovy.text.XmlTemplateEngine

static Map mergeMaps(Map lhs, Map rhs) {
    rhs.each { k, v -> lhs[k] = lhs[k] in Map ? mergeMaps(lhs[k], v) : v }
    lhs
}

static void printErrorAndExit(String error) {
    System.err.println error
    System.exit 1
}

static String addSeparator(String path) {
    return path.endsWith(File.separator) ? path : "${path}${File.separator}"
}

static void exec(String cmd) {
    Process process = cmd.execute()
    process.waitForProcessOutput System.out, System.err
    def exitValue = process.exitValue()
    if (exitValue) System.exit exitValue
}

static void proccessXmlTemplate(String templateName, File dest, Map binding) {
    processTemplate new XmlTemplateEngine(), templateName, dest, binding
}

static void processPropertiesTemplate(String templateName, File dest, Map binding) {
    processTemplate new SimpleTemplateEngine(), templateName, dest, binding
}

static void processTemplate(TemplateEngine engine, String templateName, File dest, Map binding) {
    String template = Util.classLoader.getResourceAsStream(templateName).text
    engine.createTemplate(template)
            .make(binding)
            .writeTo(dest.newWriter())
}
