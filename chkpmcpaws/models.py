"""Automate Bedrock model access for the Claude models the agent prefers.

`agent` auto-selects the first callable model, preferring Claude; but Claude
needs per-account access granted in Bedrock (the console's "Model access"
page). This module does that grant programmatically so nobody has to click:

  enable   for each preferred Claude model not already usable, create the
           Bedrock foundation-model agreement (accepts the model's EULA offer)
           and RECORD it in an SSM marker so destroy knows we enabled it.
  status   report each preferred Claude model's availability.
  disable  revoke ONLY the agreements this tool created (from the marker) and
           delete the marker -- never touches access that already existed.

Decisions baked in (per the maintainer):
  * destroy revokes only what deploy enabled (marker-scoped), so pre-existing
    account access is never removed;
  * we only CREATE the agreement -- if AWS says the account isn't authorized
    yet (Anthropic's one-time use-case form is required), we surface that and
    STOP; we never submit company details on anyone's behalf.

VALIDATE-LIVE: built against the boto3 `bedrock` model (Create/Delete
FoundationModelAgreement, GetFoundationModelAvailability,
ListFoundationModelAgreementOffers) but not yet run on a live account -- the
exact authorizationStatus/entitlement flow for a brand-new grant should be
confirmed on first authenticated `deploy`.
"""

import json

from .awsutil import ClientError, err_code, log


def managed_model_ids():
    """Base foundation-model ids we manage access for: the Claude entries in the
    agent's MODEL_PREFERENCE, as BASE ids (agreements are on the base model, not
    the `us.` inference profile). Amazon Nova needs no agreement, so it's out."""
    from .agent import MODEL_PREFERENCE
    ids = []
    for m in MODEL_PREFERENCE:
        if "anthropic" in m:
            ids.append(m[3:] if m.startswith("us.") else m)  # us.anthropic.X -> anthropic.X
    return ids


def decide(avail):
    """Pure: given a GetFoundationModelAvailability response, what to do?
      'already'  -> entitlement present, usable now (we did NOT enable it)
      'region'   -> model isn't offered in this region
      'needs-auth' -> account not authorized yet (use-case form required)
      'create'   -> authorized, no entitlement -> create the agreement
    """
    if avail.get("entitlementAvailability") == "AVAILABLE":
        return "already"
    if avail.get("regionAvailability") == "NOT_AVAILABLE":
        return "region"
    if avail.get("authorizationStatus") == "NOT_AUTHORIZED":
        return "needs-auth"
    return "create"


def _bedrock(session, region, quiet=False):
    """The `bedrock` control-plane client, or None if this boto3 predates the
    foundation-model-agreement APIs (with an upgrade hint)."""
    br = session.client("bedrock", region_name=region)
    if not hasattr(br, "create_foundation_model_agreement"):
        if not quiet:
            log("  model access: this boto3 predates the Bedrock model-access APIs "
                "-- upgrade:  python3 -m pip install --upgrade boto3")
        return None
    return br


def _read_marker(ssm, name):
    try:
        raw = ssm.get_parameter(Name=name)["Parameter"]["Value"]
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except (ClientError, ValueError, KeyError):
        return []


def _write_marker(ssm, name, ids, tags):
    kw = dict(Name=name, Value=json.dumps(sorted(set(ids))), Type="String", Overwrite=True)
    ssm.put_parameter(**kw)
    # Tag on a best-effort basis (put_parameter can't tag an existing param).
    try:
        ssm.add_tags_to_resource(
            ResourceType="Parameter", ResourceId=name,
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
    except ClientError:
        pass


def _use_case_form_blocking(session, region):
    """True when a preferred Claude is entitled to the account but blocked by the
    unsubmitted Anthropic use-case form -- a runtime Converse ping returns that
    specific ResourceNotFoundException ('use case details have not been
    submitted'). Best-effort: any other failure returns False so `enable` never
    breaks on the probe. This is why entitlementAvailability=AVAILABLE alone is
    not enough to report 'already enabled' -- invoke can still be blocked."""
    from .agent import MODEL_PREFERENCE
    claude = next((m for m in MODEL_PREFERENCE if "anthropic" in m), None)
    if not claude:
        return False
    try:
        rt = session.client("bedrock-runtime", region_name=region)
        rt.converse(modelId=claude,
                    messages=[{"role": "user", "content": [{"text": "hi"}]}],
                    inferenceConfig={"maxTokens": 8})
        return False
    except ClientError as e:
        msg = str(e).lower()
        return "use case" in msg or "not been submitted" in msg
    except Exception:  # noqa: BLE001 -- a probe failure must not break enable()
        return False


def enable(cfg, session, quiet=False):
    """Grant access to the preferred Claude models. Idempotent. Returns the list
    of model ids THIS run newly enabled (also appended to the SSM marker). Never
    raises into the caller -- model access is an enhancement, and a plain
    deploy still works on Nova."""
    region = cfg.region
    br = _bedrock(session, region, quiet)
    if br is None:
        return []
    ssm = session.client("ssm", region_name=region)
    newly, already = [], []
    for mid in managed_model_ids():
        try:
            avail = br.get_foundation_model_availability(modelId=mid)
        except ClientError as e:
            if not quiet:
                log(f"  model access: cannot read availability for {mid} "
                    f"({err_code(e) or e}) -- skipping.")
            continue
        action = decide(avail)
        if action == "already":
            already.append(mid)
            continue
        if action == "region":
            if not quiet:
                log(f"  model access: {mid} is not offered in {region} -- skipping.")
            continue
        if action == "needs-auth":
            if not quiet:
                log(f"  model access: {mid} needs the one-time Anthropic use-case "
                    "form (Bedrock console -> Model access -> Anthropic). This tool "
                    "does not submit it. Enable it once there, then re-run.")
            continue
        # action == "create"
        try:
            offers = br.list_foundation_model_agreement_offers(modelId=mid).get("offers", [])
            token = offers[0]["offerToken"] if offers else None
            if not token:
                if not quiet:
                    log(f"  model access: no agreement offer for {mid} -- skipping.")
                continue
            br.create_foundation_model_agreement(offerToken=token, modelId=mid)
            newly.append(mid)
            if not quiet:
                log(f"  model access: enabled {mid}")
        except ClientError as e:
            msg = str(e).lower()
            if "authoriz" in msg or "use case" in msg or "not been submitted" in msg:
                if not quiet:
                    log(f"  model access: {mid} requires the Anthropic use-case form "
                        "(console -> Model access -> Anthropic); not submitting.")
            elif not quiet:
                log(f"  model access: could not enable {mid} ({err_code(e) or e}).")
    if newly:
        existing = _read_marker(ssm, cfg.model_access_param)
        _write_marker(ssm, cfg.model_access_param, existing + newly, cfg.tags())
    # Entitlement can read AVAILABLE while Anthropic's one-time use-case form is
    # still unsubmitted -- which blocks INVOKE (the agent then silently drops to
    # Nova). A quick runtime ping catches that so we report the real gap instead
    # of a misleading "already enabled".
    if already and not newly and _use_case_form_blocking(session, region):
        if not quiet:
            log("  model access: the Claude agreement is in place, but Anthropic's")
            log("  ONE-TIME use-case form has not been submitted for this account, so")
            log("  Claude cannot be invoked yet (the agent falls back to Nova). Submit")
            log("  it once in the Bedrock console (Model access -> Anthropic -> use case")
            log("  details), wait ~15 min, then re-run. This tool does not submit your")
            log("  company details on your behalf.")
        return newly
    if not quiet:
        if newly:
            log(f"  model access: {len(newly)} model(s) enabled; access can take a "
                "few minutes to propagate.")
        elif already:
            log("  model access: preferred Claude model(s) already enabled -- nothing to do.")
    return newly


def disable_enabled(cfg, session):
    """Revoke ONLY the agreements this tool created (from the marker), then
    delete the marker. No-op when the marker is absent. Returns a status string
    for the destroy report."""
    region = cfg.region
    ssm = session.client("ssm", region_name=region)
    ids = _read_marker(ssm, cfg.model_access_param)
    if not ids:
        return None
    br = _bedrock(session, region)
    if br is None:
        return None
    revoked = []
    for mid in ids:
        try:
            br.delete_foundation_model_agreement(modelId=mid)
            revoked.append(mid)
        except ClientError as e:
            log(f"  model access: could not revoke {mid} ({err_code(e) or e}).")
    try:
        ssm.delete_parameter(Name=cfg.model_access_param)
    except ClientError:
        pass
    return (f"revoked {len(revoked)} model agreement(s) this stack enabled: "
            + ", ".join(revoked)) if revoked else None


def status(cfg, session):
    """Print each preferred Claude model's availability (read-only)."""
    br = _bedrock(session, cfg.region)
    if br is None:
        return 1
    ssm = session.client("ssm", region_name=cfg.region)
    marker = set(_read_marker(ssm, cfg.model_access_param))
    for mid in managed_model_ids():
        try:
            a = br.get_foundation_model_availability(modelId=mid)
            usable = a.get("entitlementAvailability") == "AVAILABLE"
            tag = " (enabled by this tool)" if mid in marker else ""
            log(f"  {mid}: {'AVAILABLE' if usable else decide(a)}{tag}")
        except ClientError as e:
            log(f"  {mid}: unknown ({err_code(e) or e})")
    return 0
