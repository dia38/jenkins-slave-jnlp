#!/bin/sh

JENKINS_HOME=${HOME}
OS="`uname -s`"
if [ "${OS}" = "Darwin" ]; then
	JENKINS_CONF=${JENKINS_HOME}/Library/Preferences/org.jenkins-ci.slave.jnlp.conf
	JENKINS_WRKSPC=${JENKINS_HOME}/Library/Developer/org.jenkins-ci.slave.jnlp
else
	JENKINS_CONF=${JENKINS_HOME}/org.jenkins-ci.slave.jnlp.conf
	JENKINS_WRKSPC=${JENKINS_HOME}/org.jenkins-ci.slave.jnlp
fi
JENKINS_SLAVE=''
JENKINS_MASTER=''
HTTP_PORT=''
JENKINS_SECRET=''
JAVA_ARGS='-Djava.awt.headless=true'
JAVA_ARGS_LOG=''
JAVA_TRUSTSTORE=${JENKINS_HOME}/.keystore
JAVA_TRUSTSTORE_PASS=''
AGENT=''

# called when unloaded by launchctl
unload() {
	PID=`cat ${JENKINS_WRKSPC}/.slave.pid`
	if [ "$PID" != "" ]
	then
		kill $PID
		wait $PID
	fi
	echo
	echo "Stopping at `date`"
	echo
	exit 0
}

# launchctl sends SIGTERM to unload a daemon
# trap SIGTERM to be able to gracefully cleanup
trap "unload" HUP INT TERM

if [ -f ${JENKINS_CONF} ]
then
	chmod 400 ${JENKINS_CONF}
	. ${JENKINS_CONF}
fi

[ ! -z $HTTP_PORT ] && HTTP_PORT=":${HTTP_PORT}"
JENKINS_SLAVE_ESC=`printf "${JENKINS_SLAVE}" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c 3-`
JENKINS_JNLP_URL=${JENKINS_MASTER}${HTTP_PORT}/computer/${JENKINS_SLAVE_ESC}/slave-agent.jnlp

echo
echo "Starting at `date`"
echo

# Create and switch to working directory
if ! cd ${JENKINS_WRKSPC}
then
	echo "Unable to use expected workspace: ${JENKINS_WRKSPC}"
	exit 1
fi

# Download slave.jar. This ensures that everytime this daemon is loaded, we get the correct slave.jar
# from the Master. We loop endlessly to get the jar, so that if we start before networking, we ensure
# the jar gets loaded anyway.
echo "Getting slave.jar from ${JENKINS_MASTER}"
RESULT=-1
while [ true ]
do
	curl --url ${JENKINS_MASTER}${HTTP_PORT}/jnlpJars/slave.jar --insecure --output ${JENKINS_WRKSPC}/slave.jar
	RESULT=$?
	if [ $RESULT -eq 0 ]
	then
		break
	else
		sleep 60
	fi
done

echo "Launching slave process at ${JENKINS_JNLP_URL}"
RESULT=-1
# If we use a trustStore for the Jenkins Master certificates, we need to pass it
# and its password to the java process that runs the slave. The password is stored
# in the OS X Keychain that we use for other purposes.
if [ -f $JAVA_TRUSTSTORE ]
then
	JAVA_ARGS_LOG="${JAVA_ARGS} -Djavax.net.ssl.trustStore=${JAVA_TRUSTSTORE} -Djavax.net.ssl.trustStorePassword=********"
	JAVA_ARGS="${JAVA_ARGS} -Djavax.net.ssl.trustStore=${JAVA_TRUSTSTORE} -Djavax.net.ssl.trustStorePassword=${JAVA_TRUSTSTORE_PASS}" 
fi
echo "Calling java ${JAVA_ARGS_LOG} -jar ${JENKINS_WRKSPC}/slave.jar -jnlpUrl ${JENKINS_JNLP_URL} -secret ********"
java ${JAVA_ARGS} -jar ${JENKINS_WRKSPC}/slave.jar -jnlpUrl ${JENKINS_JNLP_URL} -secret ${JENKINS_SECRET} &
echo $! > ${JENKINS_WRKSPC}/.slave.pid
wait `cat ${JENKINS_WRKSPC}/.slave.pid`
unload
