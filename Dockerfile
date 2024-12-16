############################################################
# Dockerfile to build base GMI container with flask
# Based on centos
############################################################

# Set the base image to CentOS
FROM python:3.10-alpine3.19

# Versions
# ARG HTTPD_VERSION="2.4.7"
# ARG MOD_AUTH_GSSAPI_VERSION="1.5.1"
# ARG MOD_WSGI_VERSION="4.6.5"

# ARG SSH_PRV_KEY
# ARG LOCAL_USER_DIR


# File Author / Maintainer
# MAINTAINER Kapil Trivedi 

# Update the repository sources list

# for alpine
RUN apk update

# Install python pip 
# RUN yum -y install python36 python36-setuptools python36-devel
# RUN easy_install-3.6 pip

# Install apache

#for alpine
RUN apk add --no-cache apache2 apache2-ssl openssl apache2-utils py3-python-gssapi ca-certificates coreutils busybox-extras

#for apline
RUN apk add --no-cache gcc libffi-dev libc-dev openldap-dev openssl-dev krb5-dev apache2-dev curl musl-dev make
RUN apk add --no-cache openssh-client git


# install mod_wsgi for python
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install mod_wsgi gunicorn
RUN mod_wsgi-express install-module
RUN apk add openrc
RUN echo "LoadModule wsgi_module /usr/lib/apache2/mod_wsgi-py310.cpython-310-x86_64-linux-gnu.so" >> /etc/apache2/httpd.conf
RUN curl -sL http://certificates.generalmills.com/certdata/bundles/GmiSha2Root.pem -o /etc/ssl/certs/genmills-ca-network-bundle.pem &&\
    chmod 744 /etc/ssl/certs/genmills-ca-network-bundle.pem
# RUN openssl s_client -connect guc1dc.genmills.com:636 2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /etc/ssl/certs/iac-ldap-server.pem &&\
#    chmod 744 /etc/ssl/certs/iac-ldap-server.pem && \
#    update-ca-certificates
# RUN ls -la /etc/ssl/certs/iac-ldap-server.pem
# RUN openssl s_client -connect guc1dc.genmills.com:636 -showcerts -CAfile /etc/ssl/certs/ca-certificates.crt
# ADD http://certificates.generalmills.com/certdata/bundles/gmisha2fullchain.pem /opt/gmisha2fullchain.pem
# RUN csplit -s -z -f individual- /opt/gmisha2fullchain.pem '/-----BEGIN CERTIFICATE-----/' '{*}' --prefix=/opt/ --suffix-format='%03d.crt' && \
#    mv /opt/*.crt /usr/local/share/ca-certificates/ && \
#    update-ca-certificates && \
#    chmod 644 /opt/gmisha2fullchain.pem && \
#    chmod 644 /usr/local/share/ca-certificates/*.crt
# RUN timeout 15 sh -c 'echo "QUIT" | openssl s_client -connect t.guc1dc.genmills.com:636 -showcerts > ldap_connection.log' || true && cat ldap_connection.log || true
#   ls -l /etc/ssl/certs/iac-ldap-server.pem
RUN touch /.dockerenv
ARG KAOS_USER=apache_kaos_usr
ARG GROUP_ID=1000
ARG GROUP_NAME=lnx_kaos_dev
ARG USER_ID=1000
ARG GMIServer=DEVELOPMENT
RUN addgroup --gid $GROUP_ID $GROUP_NAME && \
    adduser -D -s /sbin/nologin -u $USER_ID --ingroup $GROUP_NAME $KAOS_USER
RUN addgroup --system kaos && adduser -D -s /sbin/nologin --ingroup kaos kaos
RUN mkdir -p /var/log/gunicorn && chown -R ${KAOS_USER}: /var/log/gunicorn

WORKDIR /app

# RUN mkdir -p /root/.ssh && \
#    chmod 0700 /root/.ssh && \
#    ssh-keyscan -t rsa github.com >> /root/.ssh/known_hosts && \
#    echo "$SSH_PRV_KEY" > /root/.ssh/id_rsa && \
#    chmod 600 /root/.ssh/id_rsa

# COPY ${LOCAL_USER_DIR}/.ssh/* /root/.ssh/.

# RUN python3 -m pip install network-iac-common-utils==0.2.1 --extra-index-url https://artifactory.genmills.com/artifactory/api/pypi/python-release-local/simple

RUN rm -rf /var/tmp/network-network_iac_common_utils* && \ 
    python3 -m pip download --extra-index-url https://artifactory.genmills.com/artifactory/api/pypi/python-release-local/simple --dest /var/tmp --no-deps network-iac-common-utils && \
    tar -xzf /var/tmp/network-iac-common-utils-*.tar.gz -C /var/tmp && \
    mkdir /var/tmp/utilHelpers && \
    cp -rf /var/tmp/network-iac-common-utils-*/network_iac_common_utils /var/tmp/utilHelpers/. && \
    chown ${KAOS_USER}: -R /var/tmp/utilHelpers  


COPY requirements_docker.txt /app/requirements.txt

# RUN python3 -m pip freeze

RUN python3 -m pip install -r /app/requirements.txt --extra-index-url https://artifactory.genmills.com/artifactory/api/pypi/python-release-local/simple

# RUN python3 -m pip freeze

# RUN rm -rf /root/.ssh/

# We copy just the requirements.txt first to leverage Docker cache
COPY --chown=${KAOS_USER}: . /app

RUN chmod +x /app/wsgi.py

USER ${KAOS_USER}

EXPOSE 8080
ENV DD_LOGS_INJECTION=true
# ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
# CMD ["gunicorn", "-b", "0.0.0.0:8080","--log-level=debug","--workers=2","--timeout=90","wsgi:app"]
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--error-logfile","/var/log/gunicorn/error.log","--access-logfile", "/var/log/gunicorn/access.log", "--log-level=debug","--workers=2","--timeout=90","wsgi:app"]
# CMD ["tail", "-f", "/dev/null"]