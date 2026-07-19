"""Cognito helpers: find-before-create for pool / resource server / client /
domain (pool names are NOT unique -- a blind create mints duplicates on every
re-run), plus the client-credentials token minting used by verify and demos.

The client secret and bearer tokens are returned to callers but never logged.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .awsutil import BotoCoreError, ClientError, err_code, log, paginate, tls_context


def discovery_url(region, pool_id):
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"


def token_endpoint(domain, region):
    return f"https://{domain}.auth.{region}.amazoncognito.com/oauth2/token"


def find_pool(cognito, name):
    for p in paginate(cognito.list_user_pools, MaxResults=60):
        if p.get("Name") == name:
            return p.get("Id")
    return None


def find_client(cognito, pool_id, name):
    for c in paginate(cognito.list_user_pool_clients, UserPoolId=pool_id, MaxResults=60):
        if c.get("ClientName") == name:
            return c.get("ClientId")
    return None


def client_secret(cognito, pool_id, client_id):
    desc = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    return desc["UserPoolClient"].get("ClientSecret")


def ensure_pool(cognito, name, tags=None):
    """Return the pool id, reusing an existing pool with this name."""
    pool_id = find_pool(cognito, name)
    if pool_id:
        log(f"  pool {name} already exists; reusing {pool_id}")
        return pool_id
    kwargs = {"PoolName": name}
    if tags:
        kwargs["UserPoolTags"] = tags
    return cognito.create_user_pool(**kwargs)["UserPool"]["Id"]


def ensure_resource_server(cognito, pool_id, identifier, name, scopes):
    try:
        cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier)
        return
    except ClientError as e:
        if err_code(e) != "ResourceNotFoundException":
            raise
    cognito.create_resource_server(
        UserPoolId=pool_id, Identifier=identifier, Name=name, Scopes=scopes
    )


def ensure_client(cognito, pool_id, name, scope):
    """Return (client_id, client_secret), reusing an existing app client."""
    client_id = find_client(cognito, pool_id, name)
    if client_id:
        log(f"  app client {name} already exists; reusing {client_id}")
        return client_id, client_secret(cognito, pool_id, client_id)
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=name,
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[scope],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]
    return client["ClientId"], client["ClientSecret"]


def domain_description(cognito, domain):
    """Describe a hosted domain. Returns {} when it doesn't exist."""
    try:
        return cognito.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
    except (ClientError, BotoCoreError):
        return {}


def ensure_domain(cognito, domain, pool_id, attempts=36, delay=5):
    """Attach the hosted domain to this pool. Returns True on success.

    Handles the teardown->redeploy race: domain deletion is ASYNC, so a
    same-named domain from a just-torn-down pool can still be draining when
    the next deploy runs. Creating it then fails -- and silently swallowing
    that (the original behavior) leaves the pool with NO domain, which makes
    every later token request fail with no clue why. So: wait for a draining
    domain to clear, retry the create, and if it still can't be attached say
    so LOUDLY and return False so the deploy records a real failure."""
    waited = False
    for attempt in range(attempts):
        desc = domain_description(cognito, domain)
        owner, status = desc.get("UserPoolId"), desc.get("Status")
        if owner == pool_id and status != "DELETING":
            if attempt:
                log(f"  domain {domain} attached (status {status})")
            return True
        if owner:
            # Exists but deleting, or still attached to a just-deleted pool.
            if not waited:
                log(f"  domain {domain} is {status or 'attached'} on pool {owner} -- "
                    "waiting for the old one to finish deleting...")
                waited = True
            time.sleep(delay)
            continue
        try:
            cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
            log(f"  domain {domain} created")
            return True
        except ClientError as e:
            log(f"  domain create not accepted yet ({err_code(e) or e}) -- retrying...")
            time.sleep(delay)
    log(f"  ERROR: hosted domain {domain} could not be attached to pool {pool_id}.")
    log("  Without it, NO OAuth token can be minted (this is exactly what a token")
    log("  stall looks like). Re-run the deploy to retry, or inspect:")
    log(f"    aws cognito-idp describe-user-pool-domain --domain {domain}")
    return False


def get_token(endpoint, client_id, secret, scope, attempts=24, delay=10):
    """Mint a client-credentials access token (pure stdlib; TLS verification
    stays ON -- awsutil.tls_context falls back to the certifi/botocore CA
    bundle when the interpreter's default trust store is empty). Retries with
    a heartbeat because the Cognito hosted domain can take minutes to become
    resolvable after create."""
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": scope,
        }
    ).encode("utf-8")
    last_err = "no response yet"
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=tls_context()) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                token = body.get("access_token")
                if token:
                    return token
                last_err = "response had no access_token"
        except urllib.error.HTTPError as e:
            # The OAuth error body ({"error":"invalid_client"} etc.) contains
            # no secrets and is exactly what an operator needs to see.
            try:
                snippet = e.read().decode("utf-8", errors="replace")[:120]
            except Exception:
                snippet = ""
            last_err = f"HTTP {e.code}" + (f" {snippet}" if snippet else "")
        except urllib.error.URLError as e:
            # NXDOMAIN here usually means the hosted domain does not exist.
            last_err = f"URLError: {e.reason}"
        except ValueError as e:
            last_err = f"unparseable response: {e}"
        if attempt % 6 == 0:
            log(f"    still waiting for a Cognito token "
                f"(attempt {attempt}/{attempts}; last error: {last_err})...")
        if attempt < attempts:
            time.sleep(delay)
    log(f"    token minting gave up; last error: {last_err}")
    return ""
