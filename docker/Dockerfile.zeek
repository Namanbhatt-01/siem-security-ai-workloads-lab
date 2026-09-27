FROM zeek/zeek:latest

WORKDIR /var/log/zeek

CMD ["zeek", "-i", "eth0", "local", "/usr/local/zeek/share/zeek/site/custom/llm_traffic.zeek"]
