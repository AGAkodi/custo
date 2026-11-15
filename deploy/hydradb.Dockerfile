FROM ghcr.io/hydra-db/hydradb@sha256:ab71d651fefee13ebb23eb56d72316065bdca563ff7587442e07be663f2bf880
USER root
COPY deploy/hydradb-start.sh /usr/local/bin/custos-hydradb-start
ENTRYPOINT ["/bin/sh", "/usr/local/bin/custos-hydradb-start"]
