"""ensure_domain must survive the teardown->redeploy race: a same-named
hosted domain from a just-deleted pool is still draining (DELETING) when the
next deploy runs. It must wait, then create -- and report failure instead of
silently leaving the pool domainless (the original bug)."""

from chkpmcpaws.cognito import ensure_domain


class StubCognito:
    """Serves a scripted sequence of describe results; records creates."""

    def __init__(self, timeline, create_errors=0):
        self.timeline = list(timeline)
        self.created = 0
        self._create_errors = create_errors

    def describe_user_pool_domain(self, Domain):
        desc = self.timeline.pop(0) if self.timeline else {}
        return {"DomainDescription": desc}

    def create_user_pool_domain(self, Domain, UserPoolId):
        if self._create_errors:
            self._create_errors -= 1
            from chkpmcpaws.awsutil import ClientError

            raise ClientError(
                {"Error": {"Code": "InvalidParameterException"}}, "CreateUserPoolDomain"
            )
        self.created += 1
        return {}


def test_reuses_domain_already_attached_to_this_pool():
    stub = StubCognito([{"UserPoolId": "pool-me", "Status": "ACTIVE"}])
    assert ensure_domain(stub, "dom", "pool-me", attempts=3, delay=0) is True
    assert stub.created == 0


def test_waits_out_deleting_domain_then_creates():
    stub = StubCognito(
        [
            {"UserPoolId": "pool-old", "Status": "DELETING"},
            {"UserPoolId": "pool-old", "Status": "DELETING"},
            {},
        ]
    )
    assert ensure_domain(stub, "dom", "pool-new", attempts=5, delay=0) is True
    assert stub.created == 1


def test_retries_create_rejected_during_drain():
    stub = StubCognito([{}, {}, {}], create_errors=2)
    assert ensure_domain(stub, "dom", "pool-new", attempts=5, delay=0) is True
    assert stub.created == 1


def test_reports_failure_instead_of_silence():
    stub = StubCognito(
        [{"UserPoolId": "pool-old", "Status": "DELETING"}] * 4,
    )
    assert ensure_domain(stub, "dom", "pool-new", attempts=3, delay=0) is False
    assert stub.created == 0
