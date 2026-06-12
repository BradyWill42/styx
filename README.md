# styx
Styx is a k3s platform that cleans homelab nodes, installs a dual-stack k3s cluster, creates a 10.0.0.0/14 + fd00:cafe::/48 WireGuard mesh, steers VPN clients through the best available access point, runs watchdog and Ansible automation from inside Kubernetes, and deploys Wazuh for SIEM/XDR monitoring of the cluster and nodes.
