#!/usr/bin/env python3
"""Gera o predicado SLSA provenance v1 (conteúdo do atestado keyless) com o contexto do job. É conteúdo escolhido pelo PUBLICADOR; a identidade
autenticada está no certificado (Fulcio), não aqui. Uso: gerar_predicado.py <saida.json>"""
import json, os, sys
E = os.environ
repo = E["GITHUB_REPOSITORY"]
wf = E["GITHUB_WORKFLOW_REF"].split("@")[0].split(repo + "/", 1)[1]  # .github/workflows/<arquivo>
pred = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
        "externalParameters": {"workflow": {"ref": E["GITHUB_REF"], "repository": f"https://github.com/{repo}", "path": wf}},
        "internalParameters": {"github": {"event_name": E["GITHUB_EVENT_NAME"], "repository_id": E["GITHUB_REPOSITORY_ID"],
                                          "repository_owner_id": E["GITHUB_REPOSITORY_OWNER_ID"], "runner_environment": "github-hosted" if E.get("RUNNER_ENVIRONMENT") == "github-hosted" else E.get("RUNNER_ENVIRONMENT", "")}},
        "resolvedDependencies": [{"uri": f"git+https://github.com/{repo}@{E['GITHUB_REF']}", "digest": {"gitCommit": E["GITHUB_SHA"]}}]},
        "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"},
                       "metadata": {"invocationId": f"https://github.com/{repo}/actions/runs/{E['GITHUB_RUN_ID']}/attempts/{E['GITHUB_RUN_ATTEMPT']}"}}}
with open(sys.argv[1], "w") as f:
    json.dump(pred, f)
