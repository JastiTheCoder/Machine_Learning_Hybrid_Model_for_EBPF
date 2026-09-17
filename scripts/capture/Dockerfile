# Per-sample capture container.
#
# One fresh container per package. That matters for data quality as much as for
# safety: without it, sample 5's persistence mechanism (a modified .bashrc, a
# dropped binary, a poisoned npm cache) is still present when sample 6 runs,
# and sample 6's feature vector silently records sample 5's behaviour.
#
# The eBPF monitor runs on the VM host, not in here. It observes this
# container's syscalls through the host kernel, since containers share it.

FROM node:20-slim

# Decoy credentials.
#
# Credential-stealing malware typically stats a path before reading it and
# gives up if it is absent. With an empty home directory, a sample whose entire
# payload is "steal the SSH key" would produce a feature vector showing no
# credential access -- indistinguishable from a benign package, and precisely
# the false negative this corpus exists to measure.
#
# The contents are obviously fake and worthless. Their only job is to exist at
# the paths a real sample looks for, so that the read happens and
# features.ClassifyPath sees it. Anything exfiltrated goes to the sinkhole
# anyway.
RUN set -eux; \
    mkdir -p /root/.ssh /root/.aws /root/.docker /root/.kube; \
    printf '%s\n' \
      '-----BEGIN OPENSSH PRIVATE KEY-----' \
      'ZGVjb3kgLSBub3QgYSByZWFsIGtleSAtIGNhcHN0b25lIGNhcHR1cmUgaGFybmVzcwo=' \
      '-----END OPENSSH PRIVATE KEY-----' > /root/.ssh/id_rsa; \
    chmod 600 /root/.ssh/id_rsa; \
    printf '%s\n' \
      '[default]' \
      'aws_access_key_id = AKIADECOYDECOYDECOY0' \
      'aws_secret_access_key = decoy0000000000000000000000000000000000' \
      > /root/.aws/credentials; \
    printf '%s\n' '{"auths":{"decoy.invalid":{"auth":"ZGVjb3k6ZGVjb3k="}}}' \
      > /root/.docker/config.json; \
    printf '%s\n' \
      'apiVersion: v1' \
      'kind: Config' \
      'clusters: [{name: decoy, cluster: {server: "https://decoy.invalid"}}]' \
      > /root/.kube/config; \
    printf '%s\n' 'DECOY_API_KEY=not-a-real-secret' > /root/.env

# npm settings for a network-restricted, single-shot install.
#
# audit and fund are off because they add registry round-trips that are
# unrelated to the package under test and would pollute the TCP features.
# update-notifier is off for the same reason.
RUN set -eux; \
    npm config set audit false --global; \
    npm config set fund false --global; \
    npm config set update-notifier false --global; \
    npm config set progress false --global

WORKDIR /work

# A package.json has to exist before `npm install <pkg>` behaves like a normal
# project install rather than a global one.
RUN npm init -y >/dev/null 2>&1

# No ENTRYPOINT: capture.sh supplies the exact install command per sample.
CMD ["bash"]
