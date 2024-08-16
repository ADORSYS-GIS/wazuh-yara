FROM alpine

ENV WAZUH_MANAGER="10.0.0.2"

# Install Wazuh agent
RUN wget -O /etc/apk/keys/alpine-devel@wazuh.com-633d7457.rsa.pub https://packages.wazuh.com/key/alpine-devel%40wazuh.com-633d7457.rsa.pub \
    && echo "https://packages.wazuh.com/4.x/alpine/v3.12/main" >> /etc/apk/repositories \
    && apk update \
    && apk add wazuh-agent \
    && sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf \
    && /var/ossec/bin/wazuh-control start

# Install dependencies
COPY ./scripts/install.sh .

RUN chmod +x install.sh && ./install.sh

RUN yara -v