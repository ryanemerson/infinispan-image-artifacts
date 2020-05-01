#!/bin/bash
reset
set -e

ARGS="--config=/home/remerson/workspace/RedHat/infinispan/infinispan-images/test/config.yaml"
ARGS="$ARGS --identities=/home/remerson/workspace/RedHat/infinispan/infinispan-images/test/identities.yaml"
ARGS="$ARGS /tmp/"

ARGS="--config=/home/remerson/workspace/RedHat/infinispan/infinispan-images/test/config.yaml --identities=/home/remerson/workspace/RedHat/infinispan/infinispan-images/test/identities.yaml /tmp/"


rm /tmp/log4j2.xml || true

mvn compile quarkus:dev -Dquarkus.args="$ARGS" -Ddebug=false

cat /tmp/log4j2.xml

