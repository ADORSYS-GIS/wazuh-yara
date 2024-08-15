FROM debian

ENV WAZUH_MANAGER="10.0.0.2"

RUN apt-get update && apt-get install -y curl gnupg2 apt-utils

# Install Wazuh agent
RUN (curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import)  \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install wazuh-agent -y \
    && sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf

COPY ./scripts/install.sh .

RUN chmod +x install.sh && ./install.sh

RUN yara -v