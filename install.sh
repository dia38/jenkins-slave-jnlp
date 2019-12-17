#!/bin/sh
#
# Install and configure the Jenkins JNLP Slave
#
# See https://github.com/antonyx/jenkins-slave-jnlp for usage

set -u

SERVICE_USER=${SERVICE_USER:-"jenkins"}
SERVICE_GROUP=${SERVICE_GROUP:-"${SERVICE_USER}"}
SERVICE_HOME=${SERVICE_HOME:-"/var/lib/${SERVICE_USER}"}
SERVICE_CONF=""   # set in create_user function
SERVICE_WRKSPC="" # set in create_user function
MASTER_NAME=""    # set default to jenkins later
MASTER=""
MASTER_HTTP_PORT=""
SLAVE_NODE=""
JENKINS_SECRET=${JENKINS_SECRET:-""}
KEYSTORE_PASS=""
JAVA_TRUSTSTORE_PASS=""
JAVA_ARGS=${JAVA_ARGS:-""}
INSTALL_TMP=`mktemp -d -q -t org.jenkins-ci.slave.jnlp.XXXXXX`
DOWNLOADS_PATH=https://raw.github.com/dia38/jenkins-slave-jnlp/master
G_CONFIRM=${CONFIRM:-""}
OS="`uname -s`"

create_user() {
	if [ ! -d "${SERVICE_HOME}" ]
	then
		USER_SHELL="/usr/sbin/nologin"
		if [ "${OS}" = "FreeBSD" ]
		then
			pw groupshow ${SERVICE_GROUP} > /dev/null
			if [ ${?} -ne 0 ]; then
				pw groupadd ${SERVICE_GROUP}
			fi
			pw user add -n ${SERVICE_USER} -g ${SERVICE_GROUP} -d ${SERVICE_HOME} -m -w no -s ${USER_SHELL} -c 'Jenkins Node Service'
		else
			if [ "${OS}" = "SunOS" ]; then
				USER_SHELL="/usr/sbin/sh"
			fi
			groupadd -r ${SERVICE_GROUP}
			useradd -r -g ${SERVICE_GROUP} -d ${SERVICE_HOME} -m -s ${USER_SHELL} -c 'Jenkins Node Service' ${SERVICE_USER}
			passwd -l ${SERVICE_USER}
		fi
	fi
	SERVICE_CONF=${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.conf
	SERVICE_WRKSPC=${SERVICE_HOME}/org.jenkins-ci.slave.jnlp
}

install_files() {
	# create the jenkins home dir
	if [ ! -d ${SERVICE_WRKSPC} ]
	then
		mkdir -p ${SERVICE_WRKSPC}
	fi

	SEC_HELPER="security.sh"
	if [ "${OS}" = "SunOS" ]
	then
		JNLP_HELPER="jenkins-slave.xml"
		JNLP_HELPER_DEST="/var/svc/manifest/application/jenkins-slave.xml"
		INSTALL_OPTS="-u root -g ${SERVICE_GROUP} -m 644 -c /var/svc/manifest/application ${SERVICE_WRKSPC}/${JNLP_HELPER}"
	elif [ "${OS}" = "FreeBSD" ]
	then
		JNLP_HELPER="jenkins-slave.rc.d.sh"
		JNLP_HELPER_DEST="/etc/rc.d/jenkins_slave"
		INSTALL_OPTS="-o root -g ${SERVICE_GROUP} -m 744 ${SERVICE_WRKSPC}/${JNLP_HELPER} ${JNLP_HELPER_DEST}"
	elif [ "${OS}" = "Linux" ]
	then
		if [ -d "/lib/systemd/system" ] && [ -x /bin/systemctl ]
		then
			JNLP_HELPER="jenkins-slave.service"
			JNLP_HELPER_DEST="/lib/systemd/system/jenkins-slave.service"
			JNLP_HELPER_PERM="644"
		else
			JNLP_HELPER="jenkins-slave.init.d.sh"
			JNLP_HELPER_DEST="/etc/init.d/jenkins-slave"
			JNLP_HELPER_PERM="744"
		fi
		INSTALL_OPTS="-o root -g root -m ${JNLP_HELPER_PERM} ${SERVICE_WRKSPC}/${JNLP_HELPER} ${JNLP_HELPER_DEST}"
	fi

	# download the jenkins JNLP security helper script
	curl --silent -L --url ${DOWNLOADS_PATH}/${SEC_HELPER} -o ${SERVICE_WRKSPC}/security.sh
	chmod 755 ${SERVICE_WRKSPC}/security.sh

	# download the correct jnlp daemon helper
	curl --silent -L --url ${DOWNLOADS_PATH}/${JNLP_HELPER} -o ${SERVICE_WRKSPC}/${JNLP_HELPER}
	if [ "${OS}" = "SunOS" ]; then
		sed "s#\${JENKINS_HOME}#${SERVICE_HOME}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER} > /tmp/jnlp.tmp
		mv /tmp/jnlp.tmp ${SERVICE_WRKSPC}/${JNLP_HELPER}
		sed "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER} > /tmp/jnlp.tmp
		mv /tmp/jnlp.tmp ${SERVICE_WRKSPC}/${JNLP_HELPER}
	elif [ "${OS}" = "Linux" ]; then
		sed -i "s#\${JENKINS_HOME}#${SERVICE_WRKSPC}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
		sed -i "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
	else
		sed -i '' "s#\${JENKINS_HOME}#${SERVICE_WRKSPC}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
		sed -i '' "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_WRKSPC}/${JNLP_HELPER}
	fi
	rm -f ${JNLP_HELPER_DEST}
	install ${INSTALL_OPTS}

	if [ "${OS}" = "SunOS" ]
	then
		svccfg import ${JNLP_HELPER_DEST}
		svcadm restart svc:/system/manifest-import
	fi

	# download the jenkins JNLP slave script
	curl --silent -L --url ${DOWNLOADS_PATH}/slave.jnlp.sh -o ${SERVICE_WRKSPC}/slave.jnlp.sh
	chmod 755 ${SERVICE_WRKSPC}/slave.jnlp.sh

	# jenkins should own jenkin's home directory and all its contents
	chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${SERVICE_HOME}
	# create a logging space
	if [ ! -d /var/log/${SERVICE_USER} ]
	then
		mkdir /var/log/${SERVICE_USER}
		chown ${SERVICE_USER}:${SERVICE_GROUP} /var/log/${SERVICE_USER}
	fi
}

process_conf() {
	if [ -f ${SERVICE_CONF} ]
	then
		chmod 666 ${SERVICE_CONF}
		. ${SERVICE_CONF}
		chmod 400 ${SERVICE_CONF}
		SLAVE_NODE="${SLAVE_NODE:-$JENKINS_SLAVE}"
		JENKINS_SECRET="${JENKINS_SECRET:-$JENKINS_SECRET}"
		MASTER=${MASTER:-$JENKINS_MASTER}
		MASTER_HTTP_PORT=${HTTP_PORT}
		KEYSTORE_PASS="${KEYSTORE_PASS:-$JAVA_TRUSTSTORE_PASS}"
	fi
}

process_args() {
	while [ $# -gt 0 ]; do
		case $1 in
			--node=*) SLAVE_NODE="${1#*=}"     ;;
			--secret=*) JENKINS_SECRET="${1#*=}"   ;;
			--master=*) MASTER=${1#*=}         ;;
			--java-args=*) JAVA_ARGS="${1#*=}" ;;
			--confirm) G_CONFIRM="yes"         ;;
		esac
		shift
	done
}

configure_daemon() {
	if [ -z $MASTER ]
	then
		MASTER=${MASTER:-"http://jenkins"}
		echo
		read -p "URL for Jenkins master [$MASTER]: " RESPONSE
		MASTER=${RESPONSE:-$MASTER}
	fi
	while ! curl -L --url ${MASTER}/jnlpJars/slave.jar --insecure --location --silent --fail --output ${INSTALL_TMP}/slave.jar
	do
		echo "Unable to connect to Jenkins at ${MASTER}"
		read -p "URL for Jenkins master: " MASTER
	done
	MASTER_NAME=`echo $MASTER | cut -d':' -f2 | cut -d'.' -f1 | cut -d'/' -f3`
	PROTOCOL=`echo $MASTER | cut -d':' -f1`
	MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f3`
	if [ "$PROTOCOL" = "$MASTER" ]
	then
		PROTOCOL="http"
		MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f2`
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}://`echo $MASTER | cut -d':' -f2`"
	else
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}:`echo $MASTER | cut -d':' -f2`"
	fi
	[ -z $MASTER_HTTP_PORT ] && MASTER_HTTP_PORT="443"
	[ ! -z $MASTER_HTTP_PORT ] && MASTER_HTTP_PORT=":${MASTER_HTTP_PORT}"
	if [ -z "$SLAVE_NODE" ]
	then
		SLAVE_NODE=${SLAVE_NODE:-`hostname -s | tr '[:upper:]' '[:lower:]'`}
		echo
		read -p "Name of this slave on ${MASTER_NAME} [$SLAVE_NODE]: " RESPONSE
		SLAVE_NODE="${RESPONSE:-$SLAVE_NODE}"
	fi
	echo
	if [ -z "${JENKINS_SECRET}" ]
	then
		echo "The secret token is listed at ${MASTER}${MASTER_HTTP_PORT}/computer/${SLAVE_NODE}"
		read -p "Secret for ${SLAVE_NODE}: " JENKINS_SECRET
	fi

	if [ "${OS}" = "FreeBSD" ]
	then
		KEYSTORE_PASS=${KEYSTORE_PASS:-`head -c 32768 /dev/urandom | sha1`}
	else
		KEYSTORE_PASS=${KEYSTORE_PASS:-`head -n 16 /dev/urandom | sha1sum | awk '{print $1}'`}
	fi

	if [ "${PROTOCOL}" = "https" ]
	then
		echo "Trying to auto import ${MASTER} SSL certificate ..."

		MASTER_HOST=`echo $MASTER | cut -d':' -f2 | cut -d'/' -f3`
		openssl s_client -connect ${MASTER_HOST}${MASTER_HTTP_PORT} < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ${SERVICE_WRKSPC}/${MASTER_NAME}.cer
		keytool -import -noprompt -trustcacerts -alias ${MASTER_NAME} -file ${SERVICE_WRKSPC}/${MASTER_NAME}.cer -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}
		keytool -list -v -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}

		echo
		echo "
If the certificate for ${MASTER_NAME} is not trusted by Java, you will need
to install public certificates required for Java to trust ${MASTER_NAME}.
NOTE: The installer is not capable of testing that Java trusts ${MASTER_NAME}.

If ${MASTER_NAME} has a self-signed certifate, the public certificate
must be imported. If the certificate for ${MASTER_NAME} is signed by
a certificate authority, you may need to import both the root and server CA
certificates.

To install certificates, you will need to:
1) copy or download the certificates into ${SERVICE_HOME}
2) use the following command:
sudo -i -u ${SERVICE_USER} ${SERVICE_WRKSPC}/security.sh add-java-certificate \
--alias=AN_ALIAS --certificate=/path/to/certificate
If the certificate is a Root CA cert, add the --ca-cert flag to the above
command.
"
	fi
	create_ssh_keys
	configure_github
	echo
	echo "
If you need to do additional tasks to setup ${SERVICE_USER}, you can
sudo -i -u ${SERVICE_USER}
in Terminal to open a shell running as ${SERVICE_USER}
"
}

contains() { case $2 in *$1*) true;; *) false;; esac; }
beginswith() { case $2 in $1*) true;; *) false;; esac; }

create_ssh_keys() {
	if [ ! -f ${SERVICE_HOME}/.ssh/id_rsa ]; then
		echo "
Do you wish to create SSH keys for this ${SERVICE_USER}? These keys will be
suitable for GitHub, amoung other services. Keys generated at this point will
not be protected by a password.
"
		if [ "${G_CONFIRM}" = "yes" ]; then
			CONFIRM="yes"
		else
			read -p "Create SSH keys? (yes/no) [yes]" CONFIRM
			CONFIRM=${CONFIRM:-yes}
		fi
		if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
			if [ "${OS}" = "Darwin" ]; then
				echo n | sudo -i -u ${SERVICE_USER} ssh-keygen -t rsa -N \'\' -f ${SERVICE_HOME}/.ssh/id_rsa -C \"${SERVICE_USER}@${SLAVE_NODE}\"
			else
				echo n | sudo su - ${SERVICE_USER} -c "ssh-keygen -t rsa -N '' -f ${SERVICE_HOME}/.ssh/id_rsa -C ${SERVICE_USER}@${SLAVE_NODE}"
			fi
		fi
		echo "
You will need to connect to each SSH host as ${SERVICE_USER} to add the host
to the known_hosts file to allow the service to use SSH. This can be done
using the following command:
sudo -i -u ${SERVICE_USER} ssh account@service

To get ${SERVICE_USER}'s public key to add to a service to allow SSH:
sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
"
	fi
}

configure_github() {
	if [ "${G_CONFIRM}" = "yes" ]; then
		CONFIRM="no"
	else
		read -p "Will this slave need to connect to GitHub? (yes/no) [no]" CONFIRM
		CONFIRM=${CONFIRM:-no}
	fi
	if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
		echo "Attempting to SSH to GitHub... You may be prompted to trust github.com."
		sudo -i -u ${SERVICE_USER} ssh -T git@github.com
		RESULT=$?
		if [ $RESULT -eq 255 ] ; then
			echo "
You need to add the ssh keys to the GitHub account that Jenkins uses

Copy the following key to https://github.com/settings/ssh after you have
logged into GitHub as the user that Jenkins connects to GitHub as
"
			sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
		fi
	fi
}

write_config() {
	# ensure JAVA_ARGS specifies a setting for java.awt.headless (default to true)
	tmp="-Djava.awt.headless=true"
	if ! contains "${tmp}" "${JAVA_ARGS}"; then
		JAVA_ARGS="${JAVA_ARGS} ${tmp}"
	fi
	# create config directory
	sudo mkdir -p `dirname ${SERVICE_CONF}`
	sudo chmod 777 `dirname ${SERVICE_CONF}`
	# make the config file writable
	if [ -f ${SERVICE_CONF} ]; then
		sudo chmod 666 ${SERVICE_CONF}
	fi
	# write the config file
	if beginswith ":" "${MASTER_HTTP_PORT}"; then
		MASTER_HTTP_PORT=${MASTER_HTTP_PORT#":"}
	fi
	CONF_TMP=${INSTALL_TMP}/org.jenkins-ci.slave.jnlp.conf
	:> ${CONF_TMP}
	echo "JENKINS_SLAVE=\"${SLAVE_NODE}\"" >> ${CONF_TMP}
	echo "JENKINS_MASTER=${MASTER}" >> ${CONF_TMP}
	echo "HTTP_PORT=${MASTER_HTTP_PORT}" >> ${CONF_TMP}
	echo "JENKINS_SECRET=${JENKINS_SECRET}" >>${CONF_TMP}
	echo "JAVA_ARGS=\"${JAVA_ARGS}\"" >> ${CONF_TMP}
	if [ "${OS}" != "Darwin" ]; then
		echo "JAVA_TRUSTSTORE_PASS=${KEYSTORE_PASS}" >> ${CONF_TMP}
	fi
	sudo mv ${CONF_TMP} ${SERVICE_CONF}
	# secure the config file
	sudo chmod 755 `dirname ${SERVICE_CONF}`
	sudo chmod 644 ${SERVICE_CONF}
	sudo chown -R ${SERVICE_USER}:${SERVICE_GROUP} ${SERVICE_HOME}
}

start_daemon() {
	LOG_FILE="/var/log/org.jenkins-ci.slave.jnlp.log"
	case ${OS} in
		'FreeBSD')
			grep -q '^jenkins_slave_enable' /etc/rc.conf
			if [ ${?} -ne 0 ]; then
				echo "jenkins_slave_enable=\"YES\"" >> /etc/rc.conf
			fi
			BOOT_CMD=""
			START_CMD="sudo service jenkins_slave start"
			STOP_CMD="sudo service jenkins_slave stop"
			;;
		'SunOS')
			LOG_FILE="/var/svc/log/application-jenkins-slave\\:default.log"
			BOOT_CMD=""
			START_CMD="sudo svcadm enable jenkins-slave"
			STOP_CMD="sudo svcadm disable jenkins-slave"
			;;
		'Linux')
			OS_DISTRO="Unknown"
			if [ -f /etc/redhat-release ]; then
				OS_DISTRO="Redhat"
			elif [ -f /etc/debian_version ]; then
				OS_DISTRO="Debian"
			else
				OS_DISTRO="Other"
			fi

			if [ -d "/lib/systemd/system" ] && [ -x /bin/systemctl ]; then
				systemctl daemon-reload
				BOOT_CMD="systemctl enable jenkins-slave"
				START_CMD="sudo service jenkins-slave start"
				STOP_CMD="sudo service jenkins-slave stop"
			else
				case ${OS_DISTRO} in
					'Debian')
						BOOT_CMD="update-rc.d jenkins-slave defaults"
						START_CMD="sudo service jenkins-slave start"
						STOP_CMD="sudo service jenkins-slave stop"
						;;
					'Redhat')
						BOOT_CMD="chkservice jenkins-slave on"
						START_CMD=""
						STOP_CMD=""
						;;
					*)
						echo
						echo "Sorry but ${OS_DISTRO} is not supported"
						;;
				esac
			fi
			;;
		*)
			echo
			echo "Sorry but ${OS} is not supported"
			exit 1
		;;
	esac
	if [ "${BOOT_CMD}" ]; then
		${BOOT_CMD}
	fi

	echo "
The Jenkins JNLP Slave service is installed

This service can be started using the command
    ${START_CMD}
and stopped using the command
    ${STOP_CMD}

This service logs to ${LOG_FILE}
"
	if [ "${G_CONFIRM}" = "yes" ]; then
		CONFIRM="yes"
	else
		read -p "Start the slave service now (yes/no) [yes]? " CONFIRM
		CONFIRM=${CONFIRM:-yes}
	fi
	if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
		if [ "${START_CMD}" ]; then
			${START_CMD}
		fi
		if [ "${OS}" = "Darwin" ]; then
			echo
			if [ "${G_CONFIRM}" = "yes" ]; then
				CONFIRM="no"
			else
				read -p "Open Console.app to view logs now (yes/no) [no]? " CONFIRM
				CONFIRM=${CONFIRM:-no}
			fi
			if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
				open ${LOG_FILE}
			fi
		fi
	fi
}

cleanup() {
	rm -rf ${INSTALL_TMP}
	exit $1
}

echo "
        _          _   _              _ _  _ _    ___   ___ _              
     _ | |___ _ _ | |_(_)_ _  ___  _ | | \| | |  | _ \ / __| |__ ___ _____ 
    | || / -_) ' \| / / | ' \(_-< | || | .\` | |__|  _/ \__ \ / _\` \ V / -_)
     \__/\___|_||_|_\_\_|_||_/__/  \__/|_|\_|____|_|   |___/_\__,_|\_/\___|

This script will download, install, and configure a Jenkins JNLP Slave on ${OS}.

You must be an administrator on the system you are installing the Slave on,
since this installer will add a user to the system and then configure the slave
as that user.

A Java Development Kit (JDK) must be installed prior to installing the Jenkins
JNLP Slave.

During the configuration, you will be prompted for necessary information. The
suggested or default response will be in brackets [].
"
case ${OS} in
	'FreeBSD') ;;
	'SunOS')   ;;
	'Linux')   ;;
	*)
		echo
		echo "Sorry but ${OS} is not supported"
		exit 1
	;;
esac
# $@ must be quoted in order to handle arguments that contain spaces
# see http://stackoverflow.com/a/8198970/14731
process_args "$@"
if [ "${G_CONFIRM}" = "yes" ]; then
	CONFIRM="yes"
else
	read -p "Continue (yes/no) [yes]? " CONFIRM
	CONFIRM=${CONFIRM:-yes}
fi
if contains "y" "${CONFIRM}" || contains "Y" "${CONFIRM}"; then
	echo
	echo "Verifying that you may use sudo. You may be prompted for your password"
	if ! sudo -v ; then
		echo "Unable to use sudo. Aborting installation"
		cleanup 1
	fi
	create_user
	process_conf
	echo "Installing files..."
	install_files
	echo "Configuring daemon..."
	configure_daemon
	write_config
	start_daemon
else
	echo "Aborting installation"
	cleanup 1
fi

cleanup 0
