# syntax=docker/dockerfile:1.7
#
# clean-skill sandbox image.
#
# Runs an untrusted AI skill under gVisor (runtime: runsc) with:
#   - no network (host-side constraint, enforced by docker run)
#   - read-only root, /tmp tmpfs only
#   - dropped capabilities, no-new-privileges
#   - audit log written to /var/log/cleanskill/audit.jsonl
#
# Inside the container, `/opt/clean-skill/runner.sh` is the entrypoint that:
#   1) starts the mock LLM server bound to 127.0.0.1:8088
#   2) invokes the skill's declared entrypoint under strace (process + fs events)
#   3) flushes the audit log before exiting

FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strace=6.1* \
        ca-certificates \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Non-root execution user.
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin sandbox

RUN mkdir -p /opt/clean-skill /var/log/cleanskill /skill \
    && chown -R sandbox:sandbox /opt/clean-skill /var/log/cleanskill

COPY --chown=sandbox:sandbox src/clean_skill/dynamic_analysis/mock_llm.py /opt/clean-skill/mock_llm.py
COPY --chown=sandbox:sandbox docker/runner.sh /opt/clean-skill/runner.sh
RUN chmod 0755 /opt/clean-skill/runner.sh

USER sandbox
WORKDIR /skill

ENTRYPOINT ["/opt/clean-skill/runner.sh"]
CMD ["/skill"]
