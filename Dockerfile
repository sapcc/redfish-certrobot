ARG PYVER=3.11
ARG REPO=python
FROM goacme/lego:latest AS lego

# build stage
FROM ${REPO}:${PYVER} AS builder

# install PDM
RUN pip install -U pip setuptools wheel
RUN pip install pdm

# copy files
COPY pdm.lock pyproject.toml README.md src/ /redfish_certrobot/

# install dependencies and project into the local packages directory
WORKDIR /redfish_certrobot
RUN mkdir __pypackages__ && pdm install --prod --no-lock --no-editable

# run stage
FROM ${REPO}:${PYVER}-slim
LABEL source_repository=https://github.com/sapcc/redfish-certrobot/
# retrieve packages from build stage
ARG CA_CRT=https://aia.pki.co.sap.com/aia/SAPNetCA_G2.crt
ADD ${CA_CRT} /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV PYTHONPATH=/redfish_certrobot/pkgs
COPY --from=builder /redfish_certrobot/__pypackages__/3.11/lib $PYTHONPATH
COPY --from=lego /usr/bin/lego /usr/bin/lego

# set command/entrypoint, adapt to fit your needs
CMD ["python", "-m", "redfish_certrobot"]
