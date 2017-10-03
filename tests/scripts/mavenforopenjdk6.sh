#!/bin/bash

# Download and install a Maven version that works with OpenJDK6 under ubuntu Trusy
echo "Downloading Maven 3.0";
wget https://archive.apache.org/dist/maven/binaries/apache-maven-3.0-bin.zip || travis_terminate 1
unzip -qq apache-maven-3.0-bin.zip || travis_terminate 1
export M2_HOME=$PWD/apache-maven-3.0
export PATH=$M2_HOME/bin:$PATH
mvn -version
mvn clean package install -DskipTests -Dgpg.skip