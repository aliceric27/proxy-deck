FROM ghcr.io/sagernet/sing-box:v1.14.2

# curl: per-app proxy target; python3: direct-route test driver
# stunprobe / stunfallback: renamed python3 copies so route rules can match them by process_name
RUN apk add --no-cache curl python3 bind-tools gettext iproute2 \
 && cp "$(readlink -f /usr/bin/python3)" /usr/local/bin/stunprobe \
 && cp "$(readlink -f /usr/bin/python3)" /usr/local/bin/stunfallback

COPY rulesets/ /m0/rulesets/
COPY config.template.json entrypoint.sh tests.py stun_probe.py /m0/
RUN chmod +x /m0/entrypoint.sh

ENTRYPOINT ["/m0/entrypoint.sh"]
