package org.infinispan.images

import groovy.cli.picocli.CliBuilder

import static org.infinispan.images.Util.printErrorAndExit

def cli = new CliBuilder(usage: 'config-generator [options] output-dir', stopAtNonOption: false)
cli.setErrorWriter(new PrintWriter(System.err))
cli._(longOpt: 'identities', args: 1, argName: 'file', 'Yaml file used to initialize identities')
cli._(longOpt: 'config', args: 1, argName: 'file', 'Yaml file used to generate Infinispan configuration')

def options = cli.parse(args)
if (!options || options.arguments().isEmpty() || options.arguments().size() != 1) {
    cli.usage()
    System.exit 1
}

File outputDir = new File(options.arguments().get(0))
if (!outputDir.exists())
    printErrorAndExit "Directory '${outputDir.path}' does not exist"

if (!outputDir.isDirectory())
    printErrorAndExit "The specified output-dir must be a directory"

// Process Identities if provided
if (options.identities)
    Identities.create options.identities, outputDir

// Create infinispan/jgroups configuration using --config yaml if provided
Config.create options.config, outputDir
