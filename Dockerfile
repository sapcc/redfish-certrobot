ARG PYVER=3.11
ARG REPO=python
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
ENV PYTHONPATH=/redfish_certrobot/pkgs
COPY --from=builder /redfish_certrobot/__pypackages__/3.11/lib $PYTHONPATH

# set command/entrypoint, adapt to fit your needs
CMD ["python", "-m", "redfish_certrobot"]
