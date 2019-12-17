# Jenkins Slave JNLP

Scripts to create and run a [Jenkins](http://jenkins-ci.org) slave via [Java Web Start](https://wiki.jenkins-ci.org/display/JENKINS/Distributed+builds#Distributedbuilds-LaunchslaveagentviaJavaWebStart) (JNLP) on different OS.

Currently the following OS are supported:
- Debian Linux
- Ubuntu Linux
- CentOS
- Fedora
- FreeBSD 10
- Solaris 10.x, 11.x

## Requirements
You need to have the Oracle Java or Open JDK already installed before running this script.



## Quick Start
`sh <( curl -L https://raw.github.com/dia38/jenkins-slave-jnlp/master/install.sh )`



## Features
Slaves created with this script:
* Start on system boot
* Run as an independent user
* Use an independent Java Truststore for self-signed certificates (so your Jenkins master can use a self-signed certificate, and you do not have to instruct the slave to trust all certificates regardless of source)
* If you're using https the ssl certificate is imported automatically inside the keystore



## Install
`sh <( curl -L https://raw.github.com/dia38/jenkins-slave-jnlp/master/install.sh ) [options]`

The install script has the following options:
* `--java-args="ARGS"` to specify any optional java arguments. *Optional;* the installer does not test these arguments.
* `--master=URL` to specify the Jenkins Master on the command line. *Optional;* the installer prompts for this if not specified on the command line.
* `--node=NAME` to specify the Slave's node name. *Optional;* this defaults to the OS X hostname and is verified by the installer.
* `--secret=SECRET` to specify the Jenkins token who authenticates the slave. *Optional;* this is verified by the installer.
* `--confirm` to auto answer yes to all question asked by the installer. You always have to provide the other informations (see Configuration).



## Update
Simply rerun the installer. It will reinstall the scripts, but use existing configuration settings.



## Configuration
The file ``org.jenkins-ci.slave.jnlp.conf`` in ``/var/lib/jenkins`` (assuming an installation in the default location) can be used to configure this service with these options:
* `JAVA_ARGS` specifies any optional java arguments to be passed to the slave. This may be left blank.
* `JENKINS_SLAVE` specifies the node name for the slave. This is required.
* `JENKINS_MASTER` specifies the URL for the Jenkins master. This is required.
* `JENKINS_SECRET` specifies the Jenkins secret used to bind the master to the slave. This is required.
* `HTTP_PORT` specifies the nonstandard port used to communicate with the Jenkins master. This may be left blank for port 80 (http) or 443 (https).

## Adding Server Certificates
If you decide to secure the Jenkins master, or need to add additional certificates for the slave to trust the Jenkins master, you only need (assuming your service account is "jenkins", and your CA is StartSSL.com) from a command line:

On the other OS in general:

1. Stop the jenkins-slave service using the specific OS command
2. `sudo -i -u jenkins`
3. `./security.sh add-java-certificate --host=your.jenkins.host:port`
   or
   `./security.sh add-java-certificate --alias=your.alias --certificate=server.crt`
4. `exit`
5. Start the jenkins-slave service using the specific OS command



## Known Issues
None yet.
