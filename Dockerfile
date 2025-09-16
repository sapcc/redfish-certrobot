ARG PYVER=3.12
ARG REPO=python
FROM goacme/lego:v4.26.0 AS lego

# build stage
FROM ${REPO}:${PYVER} AS builder

ARG PIP_CACHE_DIR=/var/cache/pip
# install PDM
ADD https://pdm-project.org/install-pdm.py /tmp
RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
  python /tmp/install-pdm.py -p /opt/pdm

# copy files
COPY pdm.lock pyproject.toml README.md src/ /redfish_certrobot/

# install dependencies and project into the local packages directory
WORKDIR /redfish_certrobot
RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
  mkdir __pypackages__ && /opt/pdm/bin/pdm install --prod --frozen-lockfile --no-editable

# run stage
FROM ${REPO}:${PYVER}-slim
ARG PYVER=3.12
LABEL source_repository=https://github.com/sapcc/redfish-certrobot/
# retrieve packages from build stage
ARG CA_CRT=https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt
ADD ${CA_CRT} /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV PYTHONPATH=/redfish_certrobot/pkgs
COPY --from=builder /redfish_certrobot/__pypackages__/${PYVER}/lib $PYTHONPATH
ENV OS_CLOUD=default
COPY --from=lego /lego /usr/bin/lego

CMD ["python", "-m", "redfish_certrobot"]
