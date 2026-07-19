"""The auto-detecting paginator: AgentCore list responses are not uniform
('items', 'policyEngines', 'agentRuntimes', ...) and Cognito uses NextToken
where AgentCore uses nextToken. One paginator must handle all of them."""

from chkpmcpaws.awsutil import paginate


def _fake_pages(pages, token_name):
    """Build a fake list_* callable serving `pages`, chained by `token_name`."""
    calls = []

    def fn(**kwargs):
        calls.append(kwargs)
        idx = 0
        if token_name in kwargs:
            idx = int(kwargs[token_name])
        page = dict(pages[idx])
        if idx + 1 < len(pages):
            page[token_name] = str(idx + 1)
        page["ResponseMetadata"] = {"HTTPStatusCode": 200}
        return page

    fn.calls = calls
    return fn


def test_autodetects_nonstandard_list_key():
    fn = _fake_pages(
        [{"policyEngines": [{"name": "e1"}]}, {"policyEngines": [{"name": "e2"}]}],
        "nextToken",
    )
    assert [e["name"] for e in paginate(fn)] == ["e1", "e2"]


def test_cognito_style_uppercase_next_token():
    fn = _fake_pages(
        [{"UserPools": [{"Id": "p1"}]}, {"UserPools": [{"Id": "p2"}]}],
        "NextToken",
    )
    assert [p["Id"] for p in paginate(fn, MaxResults=60)] == ["p1", "p2"]
    # Original kwargs must be preserved on every page request.
    assert all(c.get("MaxResults") == 60 for c in fn.calls)


def test_ignores_response_metadata_and_empty_pages():
    def fn(**kwargs):
        return {"items": [], "ResponseMetadata": {"HTTPStatusCode": 200}}

    assert list(paginate(fn)) == []


def test_client_errors_terminate_iteration():
    from chkpmcpaws.awsutil import ClientError

    def fn(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListGateways")

    assert list(paginate(fn)) == []
