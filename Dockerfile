ARG PYVER=3.11
# build stage
FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/python:${PYVER} AS builder

# install PDM
RUN pip install -U pip setuptools wheel
RUN pip install pdm

# copy files
COPY pdm.lock pyproject.toml README.md src/ /redfish_certrobot/

# install dependencies and project into the local packages directory
WORKDIR /redfish_certrobot
RUN mkdir __pypackages__ && pdm install --prod --no-lock --no-editable && ls -la __pypackages__

# run stage
FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/python:${PYVER}-slim

# retrieve packages from build stage
ENV PYTHONPATH=/redfish_certrobot/pkgs
COPY --from=builder /redfish_certrobot/__pypackages__/3.11/lib $PYTHONPATH

# set command/entrypoint, adapt to fit your needs
CMD ["python", "-m", "redfish_certrobot"]
