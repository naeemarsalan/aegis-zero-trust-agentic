#!/usr/bin/env bash
# integrations/eda-aap/setup.sh
#
# Idempotent setup script: configures AAP 2.6 for the Agent Remediation EDA loop.
#
# Reads:  environment/.env  (gitignored — never committed)
# Uses:   AAP 2.6 Gateway API  /api/gateway/v1/
#         AAP 2.6 EDA API      /api/eda/v1/
#
# Creates (idempotent — looks up existing objects before creating):
#   1. AAP Project          — points to this Gitea repo
#   2. Machine Credential   — AAP Controller (username/password, NOT token)
#   3. Custom Credential    — Gitea token (for the playbook)
#   4. Custom Credential    — Loki URL (for the playbook)
#   5. Job Template         — "Agent Remediation PR"
#   6. EDA Token Credential — for the Event Stream inbound auth
#   7. EDA Controller Credential — back-channel EDA -> controller
#   8. EDA Project          — points to this Gitea repo
#   9. EDA Rulebook Activation — "agent-remediation"  with Event Stream source
#  10. Event Stream          — "agent-denials"
#
# Prints the Event Stream ingress URL at the end — paste into AlertmanagerConfig.
#
# Usage:
#   source environment/.env   # optional; script sources it automatically
#   bash integrations/eda-aap/setup.sh
#
# Required env vars (in environment/.env):
#   AAP_HOSTNAME              https://aap-aap.apps.hammer.na-launch.com
#   AAP_CONTROLLER_USERNAME   admin (or dedicated service account)
#   AAP_CONTROLLER_PASSWORD   <password>
#   GITEA_URL                 https://git.arsalan.io
#   GITEA_TOKEN               <personal-access-token with repo write>
#   GITEA_REPO_OWNER          anaeem
#   GITEA_REPO_NAME           nvidia-ida
#   LOKI_PUSH_URL             http://172.16.2.252:3100
#   AAP_EDA_STREAM_TOKEN      <random token for Event Stream inbound auth>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/environment/.env"

# ---------------------------------------------------------------------------
# Load environment
# ---------------------------------------------------------------------------
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "${ENV_FILE}"
  set +a
else
  echo "ERROR: ${ENV_FILE} not found. Copy environment/.env.example and fill in values." >&2
  exit 1
fi

# Validate required vars
required_vars=(
  AAP_HOSTNAME
  AAP_CONTROLLER_USERNAME
  AAP_CONTROLLER_PASSWORD
  GITEA_URL
  GITEA_TOKEN
  GITEA_REPO_OWNER
  GITEA_REPO_NAME
  LOKI_PUSH_URL
  AAP_EDA_STREAM_TOKEN
)
for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: Required env var '${var}' is not set in ${ENV_FILE}" >&2
    exit 1
  fi
done

AAP_HOST="${AAP_HOSTNAME%/}"   # strip trailing slash
CTRL_API="${AAP_HOST}/api/controller/v2"
EDA_API="${AAP_HOST}/api/eda/v1"
GW_API="${AAP_HOST}/api/gateway/v1"

AUTH=(-u "${AAP_CONTROLLER_USERNAME}:${AAP_CONTROLLER_PASSWORD}")
CURL_OPTS=(-s -k)   # -k: self-signed certs OK in lab; remove for prod with valid certs

GITEA_REPO_URL="${GITEA_URL}/${GITEA_REPO_OWNER}/${GITEA_REPO_NAME}.git"
RULEBOOK_NAME="agent-remediation"
JT_NAME="Agent Remediation PR"
PROJECT_NAME="nvidia-ida-eda"
EDA_PROJECT_NAME="nvidia-ida-eda-rulebooks"
ORG_NAME="Default"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
aap_get() {
  curl "${CURL_OPTS[@]}" "${AUTH[@]}" -H "Content-Type: application/json" "$@"
}

aap_post() {
  local url="$1"; shift
  curl "${CURL_OPTS[@]}" "${AUTH[@]}" -X POST \
    -H "Content-Type: application/json" \
    "$@" "${url}"
}

# Look up object by name, return id or empty string
lookup_id() {
  local url="$1"
  local name="$2"
  local field="${3:-id}"
  aap_get "${url}?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${name}'))")" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('results', data.get('data', []))
for r in results:
    if r.get('name') == '${name}':
        print(r.get('${field}', ''))
        sys.exit(0)
print('')
"
}

wait_project_sync() {
  local project_id="$1"
  local max_wait=120
  local waited=0
  echo "  Waiting for project sync (id=${project_id})..."
  while [[ ${waited} -lt ${max_wait} ]]; do
    status=$(aap_get "${CTRL_API}/projects/${project_id}/" \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
    if [[ "${status}" == "successful" ]]; then
      echo "  Project sync complete."
      return 0
    elif [[ "${status}" == "failed" ]]; then
      echo "ERROR: Project sync failed." >&2
      return 1
    fi
    sleep 5
    (( waited += 5 ))
  done
  echo "WARNING: Project sync timed out after ${max_wait}s." >&2
}

# ---------------------------------------------------------------------------
# 1. Get Organization ID
# ---------------------------------------------------------------------------
echo "==> [1/10] Resolving organization '${ORG_NAME}'"
ORG_ID=$(lookup_id "${CTRL_API}/organizations/" "${ORG_NAME}")
if [[ -z "${ORG_ID}" ]]; then
  echo "ERROR: Organization '${ORG_NAME}' not found in AAP controller." >&2
  exit 1
fi
echo "    org_id=${ORG_ID}"

# ---------------------------------------------------------------------------
# 2. Create or get AAP Controller Project (for job templates / playbooks)
# ---------------------------------------------------------------------------
echo "==> [2/10] Project '${PROJECT_NAME}'"
PROJECT_ID=$(lookup_id "${CTRL_API}/projects/" "${PROJECT_NAME}")
if [[ -z "${PROJECT_ID}" ]]; then
  echo "    Creating project..."
  PROJECT_ID=$(aap_post "${CTRL_API}/projects/" -d "{
    \"name\": \"${PROJECT_NAME}\",
    \"description\": \"nvidia-ida EDA remediation playbooks (Gitea)\",
    \"organization\": ${ORG_ID},
    \"scm_type\": \"git\",
    \"scm_url\": \"${GITEA_REPO_URL}\",
    \"scm_branch\": \"main\",
    \"scm_clean\": true,
    \"scm_delete_on_update\": false,
    \"scm_update_on_launch\": true
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created project id=${PROJECT_ID}. Triggering sync..."
  aap_post "${CTRL_API}/projects/${PROJECT_ID}/update/" > /dev/null
  wait_project_sync "${PROJECT_ID}"
else
  echo "    Exists: id=${PROJECT_ID}"
fi

# ---------------------------------------------------------------------------
# 3. Create or get Machine Credential for AAP controller auth (not used by
#    playbook directly, but required for project SCM if repo is private)
# ---------------------------------------------------------------------------
echo "==> [3/10] Gitea SCM credential"
SCM_CRED_NAME="gitea-scm-${GITEA_REPO_OWNER}"
SCM_CRED_TYPE_ID=$(aap_get "${CTRL_API}/credential_types/?name=Source+Control" \
  | python3 -c "import sys,json; data=json.load(sys.stdin); print(data['results'][0]['id'] if data['results'] else '')")
SCM_CRED_ID=$(lookup_id "${CTRL_API}/credentials/" "${SCM_CRED_NAME}")
if [[ -z "${SCM_CRED_ID}" ]]; then
  echo "    Creating Gitea SCM credential..."
  SCM_CRED_ID=$(aap_post "${CTRL_API}/credentials/" -d "{
    \"name\": \"${SCM_CRED_NAME}\",
    \"credential_type\": ${SCM_CRED_TYPE_ID},
    \"organization\": ${ORG_ID},
    \"inputs\": {
      \"password\": \"${GITEA_TOKEN}\"
    }
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created SCM credential id=${SCM_CRED_ID}"
else
  echo "    Exists: id=${SCM_CRED_ID}"
fi

# Attach credential to project if not already attached
aap_post "${CTRL_API}/projects/${PROJECT_ID}/credentials/" \
  -d "{\"id\": ${SCM_CRED_ID}, \"disassociate\": false}" > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 4. Create custom credential type + credential: Gitea API token (for playbook)
# ---------------------------------------------------------------------------
echo "==> [4/10] Custom credential type: Gitea API Token"
GITEA_CT_NAME="Gitea API Token"
GITEA_CT_ID=$(lookup_id "${CTRL_API}/credential_types/" "${GITEA_CT_NAME}")
if [[ -z "${GITEA_CT_ID}" ]]; then
  echo "    Creating credential type..."
  GITEA_CT_ID=$(aap_post "${CTRL_API}/credential_types/" -d '{
    "name": "Gitea API Token",
    "description": "Token and URL for the Gitea instance",
    "kind": "cloud",
    "inputs": {
      "fields": [
        {"id": "gitea_url",        "type": "string", "label": "Gitea URL"},
        {"id": "gitea_token",      "type": "string", "label": "Token", "secret": true},
        {"id": "gitea_repo_owner", "type": "string", "label": "Repo Owner"},
        {"id": "gitea_repo_name",  "type": "string", "label": "Repo Name"}
      ],
      "required": ["gitea_url","gitea_token","gitea_repo_owner","gitea_repo_name"]
    },
    "injectors": {
      "env": {
        "GITEA_URL":        "{{ gitea_url }}",
        "GITEA_TOKEN":      "{{ gitea_token }}",
        "GITEA_REPO_OWNER": "{{ gitea_repo_owner }}",
        "GITEA_REPO_NAME":  "{{ gitea_repo_name }}"
      }
    }
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created credential type id=${GITEA_CT_ID}"
else
  echo "    Exists: id=${GITEA_CT_ID}"
fi

GITEA_CRED_NAME="gitea-api-nvidia-ida"
GITEA_CRED_ID=$(lookup_id "${CTRL_API}/credentials/" "${GITEA_CRED_NAME}")
if [[ -z "${GITEA_CRED_ID}" ]]; then
  echo "    Creating Gitea API credential..."
  GITEA_CRED_ID=$(aap_post "${CTRL_API}/credentials/" -d "{
    \"name\": \"${GITEA_CRED_NAME}\",
    \"credential_type\": ${GITEA_CT_ID},
    \"organization\": ${ORG_ID},
    \"inputs\": {
      \"gitea_url\":        \"${GITEA_URL}\",
      \"gitea_token\":      \"${GITEA_TOKEN}\",
      \"gitea_repo_owner\": \"${GITEA_REPO_OWNER}\",
      \"gitea_repo_name\":  \"${GITEA_REPO_NAME}\"
    }
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created Gitea credential id=${GITEA_CRED_ID}"
else
  echo "    Exists: id=${GITEA_CRED_ID}"
fi

# ---------------------------------------------------------------------------
# 5. Create custom credential type + credential: Loki URL (for playbook)
# ---------------------------------------------------------------------------
echo "==> [5/10] Custom credential type: Loki"
LOKI_CT_NAME="Loki Push URL"
LOKI_CT_ID=$(lookup_id "${CTRL_API}/credential_types/" "${LOKI_CT_NAME}")
if [[ -z "${LOKI_CT_ID}" ]]; then
  echo "    Creating Loki credential type..."
  LOKI_CT_ID=$(aap_post "${CTRL_API}/credential_types/" -d '{
    "name": "Loki Push URL",
    "description": "Loki push/query base URL",
    "kind": "cloud",
    "inputs": {
      "fields": [
        {"id": "loki_push_url", "type": "string", "label": "Loki Base URL"}
      ],
      "required": ["loki_push_url"]
    },
    "injectors": {
      "env": {
        "LOKI_PUSH_URL": "{{ loki_push_url }}"
      }
    }
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created Loki credential type id=${LOKI_CT_ID}"
else
  echo "    Exists: id=${LOKI_CT_ID}"
fi

LOKI_CRED_NAME="loki-agentic-observability"
LOKI_CRED_ID=$(lookup_id "${CTRL_API}/credentials/" "${LOKI_CRED_NAME}")
if [[ -z "${LOKI_CRED_ID}" ]]; then
  echo "    Creating Loki credential..."
  LOKI_CRED_ID=$(aap_post "${CTRL_API}/credentials/" -d "{
    \"name\": \"${LOKI_CRED_NAME}\",
    \"credential_type\": ${LOKI_CT_ID},
    \"organization\": ${ORG_ID},
    \"inputs\": {
      \"loki_push_url\": \"${LOKI_PUSH_URL}\"
    }
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created Loki credential id=${LOKI_CRED_ID}"
else
  echo "    Exists: id=${LOKI_CRED_ID}"
fi

# ---------------------------------------------------------------------------
# 6. Create Job Template: "Agent Remediation PR"
# ---------------------------------------------------------------------------
echo "==> [6/10] Job Template '${JT_NAME}'"
JT_ID=$(lookup_id "${CTRL_API}/job_templates/" "${JT_NAME}")
if [[ -z "${JT_ID}" ]]; then
  echo "    Creating job template..."
  JT_ID=$(aap_post "${CTRL_API}/job_templates/" -d "{
    \"name\": \"${JT_NAME}\",
    \"description\": \"EDA-triggered remediation: fetch Loki logs, generate RBAC/Kyverno patch, open Gitea PR\",
    \"job_type\": \"run\",
    \"organization\": ${ORG_ID},
    \"project\": ${PROJECT_ID},
    \"playbook\": \"integrations/eda-aap/job-templates/remediation-pr.yml\",
    \"ask_variables_on_launch\": true,
    \"extra_vars\": \"{}\",
    \"verbosity\": 1
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "    Created JT id=${JT_ID}"
  # Attach credentials
  for cred_id in "${GITEA_CRED_ID}" "${LOKI_CRED_ID}"; do
    aap_post "${CTRL_API}/job_templates/${JT_ID}/credentials/" \
      -d "{\"id\": ${cred_id}}" > /dev/null
    echo "    Attached credential id=${cred_id} to JT"
  done
else
  echo "    Exists: id=${JT_ID}"
fi

# ---------------------------------------------------------------------------
# 7. EDA: create "Red Hat Ansible Automation Platform" credential (controller back-channel)
# ---------------------------------------------------------------------------
echo "==> [7/10] EDA Controller credential"
# First get the EDA credential type ID
EDA_CTRL_CT_ID=$(aap_get "${EDA_API}/credential-types/?name=Red+Hat+Ansible+Automation+Platform" \
  | python3 -c "
import sys,json
data=json.load(sys.stdin)
results=data.get('results',data.get('data',[]))
print(results[0]['id'] if results else '')
")
if [[ -z "${EDA_CTRL_CT_ID}" ]]; then
  echo "    WARNING: EDA credential type 'Red Hat Ansible Automation Platform' not found."
  echo "    Trying alternate name 'Ansible Tower'..."
  EDA_CTRL_CT_ID=$(aap_get "${EDA_API}/credential-types/?name=Ansible+Tower" \
    | python3 -c "
import sys,json
data=json.load(sys.stdin)
results=data.get('results',data.get('data',[]))
print(results[0]['id'] if results else '')
")
fi

EDA_CTRL_CRED_NAME="aap-controller-for-eda"
EDA_CTRL_CRED_ID=$(lookup_id "${EDA_API}/credentials/" "${EDA_CTRL_CRED_NAME}")
if [[ -z "${EDA_CTRL_CRED_ID}" ]] && [[ -n "${EDA_CTRL_CT_ID}" ]]; then
  echo "    Creating EDA controller credential..."
  EDA_CTRL_CRED_ID=$(aap_post "${EDA_API}/credentials/" -d "{
    \"name\": \"${EDA_CTRL_CRED_NAME}\",
    \"description\": \"EDA -> AAP Controller back-channel (username/password, not token)\",
    \"credential_type_id\": ${EDA_CTRL_CT_ID},
    \"inputs\": {
      \"host\":     \"${AAP_HOST}\",
      \"username\": \"${AAP_CONTROLLER_USERNAME}\",
      \"password\": \"${AAP_CONTROLLER_PASSWORD}\"
    }
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")
  echo "    Created EDA controller credential id=${EDA_CTRL_CRED_ID}"
elif [[ -n "${EDA_CTRL_CRED_ID}" ]]; then
  echo "    Exists: id=${EDA_CTRL_CRED_ID}"
else
  echo "    WARNING: Could not find EDA controller credential type. Skipping."
fi

# ---------------------------------------------------------------------------
# 8. EDA: Event Stream Token credential
# ---------------------------------------------------------------------------
echo "==> [8/10] EDA Event Stream Token credential"
EDA_TOKEN_CT_ID=$(aap_get "${EDA_API}/credential-types/?name=Token" \
  | python3 -c "
import sys,json
data=json.load(sys.stdin)
results=data.get('results',data.get('data',[]))
print(results[0]['id'] if results else '')
")
EDA_STREAM_CRED_NAME="agent-denials-stream-token"
EDA_STREAM_CRED_ID=$(lookup_id "${EDA_API}/credentials/" "${EDA_STREAM_CRED_NAME}")
if [[ -z "${EDA_STREAM_CRED_ID}" ]] && [[ -n "${EDA_TOKEN_CT_ID}" ]]; then
  echo "    Creating Event Stream token credential..."
  EDA_STREAM_CRED_ID=$(aap_post "${EDA_API}/credentials/" -d "{
    \"name\": \"${EDA_STREAM_CRED_NAME}\",
    \"description\": \"Inbound auth token for agent-denials Event Stream\",
    \"credential_type_id\": ${EDA_TOKEN_CT_ID},
    \"inputs\": {
      \"token\": \"${AAP_EDA_STREAM_TOKEN}\"
    }
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")
  echo "    Created token credential id=${EDA_STREAM_CRED_ID}"
elif [[ -n "${EDA_STREAM_CRED_ID}" ]]; then
  echo "    Exists: id=${EDA_STREAM_CRED_ID}"
else
  echo "    WARNING: EDA Token credential type not found. Event Stream may be created without auth."
  EDA_STREAM_CRED_ID=""
fi

# ---------------------------------------------------------------------------
# 9. EDA: Create Project
# ---------------------------------------------------------------------------
echo "==> [9/10] EDA Project '${EDA_PROJECT_NAME}'"
EDA_PROJECT_ID=$(lookup_id "${EDA_API}/projects/" "${EDA_PROJECT_NAME}")
if [[ -z "${EDA_PROJECT_ID}" ]]; then
  echo "    Creating EDA project..."
  EDA_PROJECT_ID=$(aap_post "${EDA_API}/projects/" -d "{
    \"name\": \"${EDA_PROJECT_NAME}\",
    \"description\": \"nvidia-ida EDA rulebooks (Gitea source)\",
    \"url\": \"${GITEA_REPO_URL}\"
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")
  echo "    Created EDA project id=${EDA_PROJECT_ID}"
  echo "    Waiting for EDA project import..."
  sleep 10  # EDA project import is async; brief wait before proceeding
else
  echo "    Exists: id=${EDA_PROJECT_ID}"
fi

# ---------------------------------------------------------------------------
# 10. EDA: Create Rulebook Activation with Event Stream
# ---------------------------------------------------------------------------
echo "==> [10/10] EDA Rulebook Activation + Event Stream"

# 10a. Create the activation first (we need its ID for the event stream)
ACTIVATION_NAME="agent-remediation-activation"
ACTIVATION_ID=$(lookup_id "${EDA_API}/activations/" "${ACTIVATION_NAME}")

# Get the default DE ID (prefer de-supported-rhel9)
DE_ID=$(aap_get "${EDA_API}/decision-environments/" \
  | python3 -c "
import sys,json
data=json.load(sys.stdin)
results=data.get('results',data.get('data',[]))
for r in results:
    if 'de-supported' in r.get('name','').lower() or 'default' in r.get('name','').lower():
        print(r['id'])
        break
if not results:
    print('')
")

if [[ -z "${ACTIVATION_ID}" ]]; then
  echo "    Creating rulebook activation..."
  CRED_ARG=""
  if [[ -n "${EDA_CTRL_CRED_ID}" ]]; then
    CRED_ARG="\"credentials\": [{\"id\": ${EDA_CTRL_CRED_ID}}],"
  fi
  DE_ARG=""
  if [[ -n "${DE_ID}" ]]; then
    DE_ARG="\"decision_environment_id\": ${DE_ID},"
  fi

  ACTIVATION_ID=$(aap_post "${EDA_API}/activations/" -d "{
    \"name\": \"${ACTIVATION_NAME}\",
    \"description\": \"AgentPermissionDenied self-healing — driven by agent-denials Event Stream\",
    \"project_id\": ${EDA_PROJECT_ID},
    \"rulebook_id\": null,
    \"rulebook\": \"integrations/eda-aap/rulebooks/agent-remediation.yml\",
    ${DE_ARG}
    ${CRED_ARG}
    \"restart_policy\": \"on-failure\",
    \"is_enabled\": true,
    \"source_mappings\": []
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")
  echo "    Created activation id=${ACTIVATION_ID}"
else
  echo "    Exists: id=${ACTIVATION_ID}"
fi

# 10b. Create Event Stream "agent-denials"
STREAM_NAME="agent-denials"
STREAM_ID=$(lookup_id "${EDA_API}/event-streams/" "${STREAM_NAME}")
if [[ -z "${STREAM_ID}" ]]; then
  echo "    Creating Event Stream '${STREAM_NAME}'..."
  STREAM_CRED_ARG=""
  if [[ -n "${EDA_STREAM_CRED_ID}" ]]; then
    STREAM_CRED_ARG=", \"credential_id\": ${EDA_STREAM_CRED_ID}"
  fi
  STREAM_PAYLOAD=$(python3 -c "
import json, sys
payload = {
  'name': '${STREAM_NAME}',
  'description': 'Receives AgentPermissionDenied Alertmanager events, forwards to agent-remediation activation',
  'forward_events': True
}
if '${EDA_STREAM_CRED_ID}':
    payload['credential_id'] = int('${EDA_STREAM_CRED_ID}')
print(json.dumps(payload))
")
  STREAM_RESULT=$(aap_post "${EDA_API}/event-streams/" -d "${STREAM_PAYLOAD}")
  STREAM_ID=$(echo "${STREAM_RESULT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))")
  STREAM_URL=$(echo "${STREAM_RESULT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url', d.get('webhook_url','')))")
  echo "    Created Event Stream id=${STREAM_ID}"
else
  echo "    Exists: id=${STREAM_ID}"
  STREAM_URL=$(aap_get "${EDA_API}/event-streams/${STREAM_ID}/" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('url', d.get('webhook_url','')))")
fi

# 10c. Link the event stream to the activation via source_mappings (if supported)
if [[ -n "${ACTIVATION_ID}" ]] && [[ -n "${STREAM_ID}" ]]; then
  echo "    Linking Event Stream to activation (source_mappings)..."
  aap_post "${EDA_API}/activations/${ACTIVATION_ID}/" \
    --request PATCH \
    -d "{\"source_mappings\": [{\"event_stream_id\": ${STREAM_ID}}]}" > /dev/null 2>&1 || \
    echo "    INFO: source_mappings PATCH not supported via API; configure in AAP UI."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  AAP EDA setup complete"
echo "======================================================================"
echo ""
echo "  AAP Host:             ${AAP_HOST}"
echo "  EDA Project:          ${EDA_PROJECT_NAME} (id=${EDA_PROJECT_ID})"
echo "  Job Template:         ${JT_NAME} (id=${JT_ID})"
echo "  Rulebook Activation:  ${ACTIVATION_NAME} (id=${ACTIVATION_ID})"
echo "  Event Stream:         ${STREAM_NAME} (id=${STREAM_ID})"
echo ""
if [[ -n "${STREAM_URL}" ]]; then
  echo "  *** EVENT STREAM INGRESS URL (paste into AlertmanagerConfig) ***"
  echo "  ${STREAM_URL}"
  echo ""
  echo "  AlertmanagerConfig receiver example:"
  echo "    receivers:"
  echo "      - name: eda-agent-denials"
  echo "        webhookConfigs:"
  echo "          - url: '${STREAM_URL}'"
  echo "            httpConfig:"
  echo "              bearerToken: '\${AAP_EDA_STREAM_TOKEN}'"
  echo "            sendResolved: false"
else
  echo "  WARNING: Could not determine Event Stream URL. Check AAP UI:"
  echo "  ${AAP_HOST}/api/eda/v1/event-streams/${STREAM_ID}/"
fi
echo ""
echo "  Verify steps:"
echo "    curl -s -k -u '${AAP_CONTROLLER_USERNAME}:***' ${EDA_API}/activations/${ACTIVATION_ID}/ | python3 -m json.tool"
echo "    curl -s -k -u '${AAP_CONTROLLER_USERNAME}:***' ${EDA_API}/event-streams/${STREAM_ID}/ | python3 -m json.tool"
echo ""
echo "  Send a test event:"
echo "    curl -X POST '${STREAM_URL}' \\"
echo "      -H 'Authorization: Bearer \${AAP_EDA_STREAM_TOKEN}' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"alerts\":[{\"labels\":{\"alertname\":\"AgentPermissionDenied\",\"namespace\":\"agent-sandbox\",\"tool\":\"pfsense-mcp\",\"user\":\"test@example.com\",\"denial_reason\":\"kyverno policy block\"},\"annotations\":{\"summary\":\"Test alert\"}}]}'"
echo "======================================================================"
